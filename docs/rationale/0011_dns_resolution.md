# 0011 — DNS Resolution Cache

## Context

Raw IP addresses in the packet list are hard to interpret at a glance.
Users frequently need to know which domain a connection targets without
switching to another tool.

## Decision

**Background reverse DNS resolution with an in-memory cache, toggled
with the `D` key.**

- DNS is **off by default** to avoid unwanted network traffic and latency.
- When enabled, a background thread periodically resolves IPs from the
  packet list using libc `getnameinfo` (PTR records via the system resolver).
- Results are cached in `App::dns_cache: HashMap<IpAddr, String>`.
- The packet list shows `hostname (ip:port)` when a resolution exists.
- Resolution runs every ~5 seconds, only for IPs not already cached.

### Why libc `getnameinfo` instead of a DNS library?

Using the system resolver via libc:
- Respects `/etc/hosts`, mDNS, and platform-specific resolution.
- Zero additional dependencies (libc is already transitively included).
- Works on both macOS and Linux.

### Why off by default?

Reverse DNS lookups generate network traffic that would appear in the
capture itself, creating a feedback loop. It also adds latency to the
first display of new IPs. Opt-in via `D` gives the user control.

## Trade-offs

- PTR records don't exist for all IPs; many will remain unresolved.
- The resolver thread is fire-and-forget; results appear asynchronously
  after a short delay.
- No TTL-based expiry — the cache grows unbounded during a session.
  This is acceptable because the capture ring buffer bounds the number
  of unique IPs.
