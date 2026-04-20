# 0003 — Process Filtering via lsof Socket Resolution

## Context

Users often want to see only packets from a specific application (e.g., a web
browser, a database client). libpcap operates at the network interface level
and has no concept of process ownership — BPF filters work on packet headers
(IPs, ports, protocols), not PIDs.

## Decision

**Software post-filter based on process socket resolution via `lsof`.**

1. `lsof -i -n -P -F pcn` lists all processes with open network sockets,
   returning PID, command name, and local/remote addresses.
2. The user picks a process (via `--process` CLI flag or `p` key picker).
3. hexcap extracts the process's known local ports.
4. Captured packets are filtered in the app layer by matching source or
   destination ports against the process's port set.
5. The port set is refreshed every ~5 seconds to track sockets that open
   and close over time.

## Why not a BPF filter?

BPF filters cannot express "packets belonging to PID X." The only way to
filter by process at the BPF level would be to generate a port-based filter
string (e.g., `port 443 or port 8080`), but:

- Sockets are dynamic — the filter goes stale immediately.
- Restarting capture to apply a new BPF filter would lose buffered packets.
- The pcap `Capture` API doesn't support filter changes on a live handle
  without reopening.

A software post-filter avoids all of these issues. The performance cost is
negligible — port matching is an O(1) `HashSet::contains` per packet.

## Why lsof instead of /proc/net?

- `/proc/net/tcp` and `/proc/net/udp` exist only on Linux.
- `lsof` works on both macOS and Linux.
- hexcap's primary development target is macOS (libpcap is native).
- `lsof` output is stable and well-documented.

## Why fuzzy matching for process names?

Exact matching is fragile — process names vary by platform (`Google Chrome`
vs `chrome` vs `Chrome Helper`). Case-insensitive substring matching
(`contains`) covers these variations. When multiple PIDs match the same name
(e.g., Chrome spawns many processes), their ports are merged.

## Trade-offs

- Short-lived connections may be missed between 5-second refresh intervals.
- Processes using raw sockets or non-TCP/UDP protocols won't map to ports.
- The `lsof` call takes ~50-100ms, which is why it runs on the main thread
  during the periodic refresh (not every frame).
