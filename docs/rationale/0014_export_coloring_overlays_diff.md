# 0014 — Export Auto-Filename, Semantic Coloring, Overlays, and Packet Diff

## Context

Batch 3 of feature development added five capabilities: smarter pcap export,
Wireshark-style packet coloring, a help overlay, a capture statistics popup,
and a hex-level packet diff tool.

## Export Auto-Filename

- Previously, `w` required `--write <path>` on the CLI or it would refuse.
- Now, pressing `w` without `--write` auto-generates a timestamped filename:
  `hexcap_{unix_seconds}.pcap`.
- Uses `SystemTime::now()` duration since UNIX epoch — no chrono dependency.
- Still exports only filtered/visible packets.

## Semantic Packet Coloring

- `CapturedPacket` now stores `tcp_flags: u8`, populated during TCP parsing
  in both IPv4 and IPv6 paths.
- The list view applies Wireshark-style row coloring based on flags/protocol:
  - **RST** packets: red — connection reset
  - **SYN** (no ACK): green — new connection
  - **FIN** packets: amber — connection closing
  - **ICMP**: light blue
  - **ARP**: khaki
  - **DNS**: teal
  - Normal TCP/UDP: retain default flow-based coloring
- Colors are hardcoded RGB values (not theme-dependent) for semantic clarity.
  This mirrors Wireshark's approach where protocol colors have fixed meaning.

### Why not user-configurable rules?

User-defined coloring rules (regex-based or expression-based) would require
a rule engine, parser, and configuration format. The semantic defaults cover
the most important visual signals. User-configurable rules can be layered
on top later if needed.

## Help Overlay (`?`)

- `?` in list view opens a centered popup showing all keybindings.
- Esc, `q`, or `?` dismisses it.
- Binding list is a static `&[(&str, &str)]` array — easy to maintain.
- Key column uses theme `key_bg`/`key_fg` for badge-style rendering.

## Capture Statistics Summary (`I`)

- `I` opens a popup with three sections:
  1. **Protocol distribution** — packet count and bytes per protocol
  2. **Top 5 talkers** — IPs with most bytes (ports stripped)
  3. **Top 5 conversations** — bidirectional flows by packet count
- Computed on-the-fly from current packet buffer each time the overlay opens.
- `Protocol` enum now derives `Hash` for use as `HashMap` key.
- `strip_port` helper extracts bare IPs from `ip:port` / `[ipv6]:port`.

### Why on-the-fly computation?

Pre-computing and maintaining running statistics would add complexity to
every packet insertion and deletion path. With the ring buffer capped at
`--max-packets` (default 10,000), iterating the full buffer is fast enough
(< 1ms) to compute whenever the user opens the popup.

## Packet Diff (`x`)

- Press `x` to mark a packet for comparison. Press `x` on a second packet
  to open a side-by-side hex diff overlay.
- Displays 8 bytes per row from each packet, with differing bytes
  highlighted in bold red and matching bytes in muted gray.
- Rows with any difference are marked with `!`.
- Esc, `q`, or `x` dismisses the diff.
- If the marked packet is evicted from the ring buffer before the second
  selection, a status message warns and clears the mark.

### Why not unified diff format?

Traditional unified diff is designed for text. Hex data is inherently
positional — byte-by-byte alignment with color highlighting communicates
differences more clearly than +/- lines.
