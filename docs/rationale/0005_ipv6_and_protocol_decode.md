# 0005 — IPv6 Support and Protocol Decode Panel

## Context

hexcap initially parsed only IPv4 packets (ethertype `0x0800`). IPv6 traffic
(`0x86DD`) was displayed as "Other" with no header parsing. Additionally,
the detail view showed only the hex dump — users had no structured view of
protocol headers.

## Decision

**Add IPv6 parsing and a decoded fields panel in the detail view.**

### IPv6

- `parse_ipv6` in `packet.rs` handles ethertype `0x86DD`, extracting source
  and destination addresses from the 40-byte fixed header.
- Addresses are formatted as `[ipv6]:port` (bracketed, matching RFC 5952
  conventions) to visually distinguish them from IPv4.
- The next-header field maps to TCP (6), UDP (17), and ICMPv6 (58).

### Protocol decode

- A `DecodedField` struct (`name: &str`, `value: String`) provides a uniform
  representation for decoded header fields.
- Decode helpers for TCP, UDP, ICMP, and ARP extract key fields (ports, flags,
  sequence numbers, checksums, hardware/protocol addresses).
- The detail view (`ui/detail.rs`) renders a "Protocol" panel above the hex
  dump showing these decoded fields.

## Why not a full dissector framework?

hexcap is a lightweight capture tool, not Wireshark. Decoding the most common
protocols (TCP/UDP/ICMP/ARP) covers the vast majority of inspection needs.
A plugin-based dissector framework would add significant complexity for
marginal benefit.
