# 0006 — Pcap Export and Import

## Context

Captured packets are only useful within a single hexcap session unless they
can be saved and reloaded. Users also need to share captures with colleagues
using Wireshark or other tools.

## Decision

**Classic libpcap format (`.pcap`) for both export and import.**

### Export (`w` key / `--write` flag)

- `export::write_pcap` writes the classic pcap global header (magic
  `0xA1B2C3D4`, version 2.4, link type Ethernet) followed by per-packet
  records (timestamp, captured length, original length, data).
- The `w` key exports all currently buffered packets to
  `hexcap_YYYYMMDD_HHMMSS.pcap` in the current directory.
- A status message confirms the export with packet count and filename.

### Import (`--read <file>`)

- `export::read_pcap` parses the global header and iterates packet records.
- `--read` loads packets into the ring buffer and starts in paused mode,
  allowing inspection without live capture.
- Imported packets are re-parsed through the same `packet::parse_packet`
  pipeline, so all decode and flow tracking works identically.

## Why classic pcap instead of pcapng?

Classic pcap is universally supported by every tool (Wireshark, tcpdump,
tshark, scapy). pcapng adds features (multiple interfaces, comments,
name resolution blocks) that hexcap doesn't need. Choosing the simpler
format maximizes interoperability.

## Why not shell out to tcpdump for export?

Writing 24 bytes of header + 16 bytes per packet record is trivial. A
dependency on tcpdump would be an unnecessary external requirement and
would complicate error handling.
