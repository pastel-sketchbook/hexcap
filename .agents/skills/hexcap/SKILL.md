---
name: hexcap
version: 1.0.0
description: |
  Use hexcap to capture, inspect, and analyze network packets from the terminal.
  Covers live capture, pcap import/export, protocol filtering, display filters,
  hex dump inspection, TCP stream follow, TLS handshake decode, DNS resolution,
  GeoIP lookup, flow tracking, process filtering, packet diff, annotations, and
  capture statistics. Use when troubleshooting network issues, analyzing traffic
  patterns, inspecting protocols, or performing packet-level forensics.
allowed-tools:
  - Read
  - Grep
  - Glob
  - Bash
  - Task
  - WebFetch
  - AskUserQuestion
  - TodoWrite
---

# hexcap

A Rust TUI packet capture tool. Captures live network packets with libpcap,
displays them in a ratatui terminal UI, and provides per-packet hex inspection
with hexyl-style rendering.

Binary location: `./target/release/hexcap` (build with `cargo build --release`)
Requires root/sudo for live capture. Reading pcap files does not require root.

## Quick Start

```bash
# Live capture on default interface
sudo hexcap

# Capture on specific interface
sudo hexcap -i en0

# Multi-interface capture
sudo hexcap -i en0,lo0

# Read a pcap file (no root needed)
hexcap --read capture.pcap

# Capture with BPF filter
sudo hexcap --filter "tcp port 443"

# Capture with process filter
sudo hexcap --process curl

# Export to pcap
sudo hexcap --write output.pcap

# With GeoIP country lookup
sudo hexcap --geoip /path/to/GeoLite2-Country.mmdb

# Limit packet buffer
sudo hexcap --max-packets 5000
```

## CLI Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--interface` | `-i` | first non-loopback | Interface(s) to capture on (comma-separated) |
| `--filter` | `-f` | none | BPF filter expression |
| `--process` | `-p` | none | Filter by process name (via lsof) |
| `--read` | `-r` | none | Read packets from pcap file |
| `--write` | `-w` | none | Write packets to pcap file |
| `--max-packets` | `-m` | 10000 | Maximum packets in ring buffer |
| `--geoip` | | none | Path to MaxMind GeoLite2-Country MMDB |

## Keybindings

### List View (main view)

| Key | Action |
|-----|--------|
| `j` / `k` / `↑` / `↓` | Navigate packets |
| `g` / `G` | Jump to first / last packet |
| `d` / `u` / `PgDn` / `PgUp` | Page down / up (20 rows) |
| `Enter` | Open packet detail |
| `Space` | Pause / resume capture |
| `c` | Clear all packets |
| `/` | Search (metadata → ASCII payload → hex pattern) |
| `f` | Cycle protocol filter (All → TCP → UDP → ICMP → DNS → ARP) |
| `\` | Display filter (Wireshark-style, see below) |
| `F` | Cycle follow speed (off / 1 / 5 / 10 / 25) |
| `n` | Open flows view |
| `N` | Clear flow filter |
| `p` | Open process picker |
| `P` | Clear process filter |
| `i` | Switch interface |
| `w` | Export to pcap (auto-generates filename if no `--write`) |
| `m` | Toggle bookmark on selected packet |
| `'` / `"` | Jump to next / previous bookmark |
| `D` | Toggle DNS resolution |
| `t` | Cycle theme (16 themes) |
| `a` | Annotate selected packet |
| `x` | Mark packet for diff / show diff (mark two, then compare) |
| `I` | Capture statistics summary |
| `?` | Keyboard shortcut help |
| `Tab` | Select column to resize |
| `<` / `>` | Narrow / widen selected column |
| `q` | Quit |

### Detail View

| Key | Action |
|-----|--------|
| `j` / `k` | Scroll hex dump |
| `y` | Copy hex dump to clipboard |
| `Y` | Copy raw hex string to clipboard |
| `S` | Follow TCP stream |
| `w` | Export to pcap |
| `Esc` / `q` | Back to list |

### Flows View

| Key | Action |
|-----|--------|
| `j` / `k` | Navigate flows |
| `Enter` | Filter packets by selected flow |
| `Esc` / `q` | Back to list |

### Stream View

| Key | Action |
|-----|--------|
| `j` / `k` | Scroll stream content |
| `y` | Copy stream hex dump |
| `Esc` / `q` | Back to detail |

## Display Filters

Press `\` to open the display filter bar. Tokens are space-separated (AND logic).
Enter an empty filter to clear.

| Token | Matches |
|-------|---------|
| `tcp` | TCP packets |
| `udp` | UDP packets |
| `icmp` | ICMP packets |
| `dns` | DNS packets |
| `arp` | ARP packets |
| `port:443` | Source or destination port 443 |
| `ip:10.0.0.1` | Source or destination IP (prefix match) |
| `syn` | TCP SYN flag set |
| `rst` | TCP RST flag set |
| `fin` | TCP FIN flag set |
| `!token` | Negate any token (e.g. `!arp`, `!port:22`) |

**Examples:**
- `tcp port:443` — HTTPS traffic only
- `tcp syn` — TCP SYN packets (connection initiations)
- `!arp !icmp` — Exclude ARP and ICMP
- `ip:192.168.1 tcp` — TCP traffic from/to 192.168.1.x subnet

## Troubleshooting Workflows

### Diagnose connection failures

```
1. Start capture: sudo hexcap -i en0
2. Reproduce the issue
3. Press Space to pause
4. Press / to search for the target IP or hostname
5. Press \ then type: tcp rst    — to filter TCP resets
6. Enter on a packet to inspect headers
7. Press S to follow the TCP stream
```

### Inspect TLS handshakes

```
1. sudo hexcap --filter "tcp port 443"
2. Press \ then type: tcp syn    — find connection starts
3. Enter on a SYN packet, look for TLS ClientHello in decoded fields
4. SNI (Server Name Indication) is extracted automatically
5. Press S to see the full handshake sequence
```

### Analyze traffic patterns

```
1. Capture traffic for a period
2. Press I for capture statistics (protocol distribution, top talkers)
3. Press n for flows view (connections sorted by packets/bytes)
4. Enter on a flow to filter packets for that connection
```

### Compare packets

```
1. Navigate to first packet, press x to mark it
2. Navigate to second packet, press x again
3. Side-by-side hex diff overlay appears
4. Esc to close diff
```

### Export for Wireshark analysis

```
1. Apply filters to isolate relevant traffic
2. Press w to export (auto-generates hexcap_<timestamp>.pcap)
3. Bookmarks and annotations are saved as sidecar files
4. Open the .pcap in Wireshark for deeper analysis
```

## Pcap Format

hexcap uses classic libpcap format (magic `0xA1B2C3D4`) for universal
compatibility with Wireshark, tcpdump, and other tools. Sidecar files:
- `.pcap.bookmarks` — one packet ID per line
- `.pcap.annotations` — `id<TAB>text` per line

## Themes

16 themes (8 dark + 8 light): Default, Gruvbox, Solarized, Ayu, Flexoki,
Zoegi, FFE Dark, Postrboard, and their light variants. Press `t` to cycle.
Auto-detects Ghostty terminal theme on startup. Persisted to
`~/.config/hexcap/preferences.toml`.

## Architecture Notes

- Capture runs on background thread(s) via `std::thread`; TUI on main thread
- Shared state via `Arc<Mutex<App>>`
- Multi-interface: one thread per interface, shared `AtomicU64` packet counter
- Process filtering: software post-filter via lsof (BPF can't filter by PID)
- TCP stream follow: capture-order concatenation (no sequence reassembly)
- DNS resolution: libc `getnameinfo`, background batch resolver
- GeoIP: `maxminddb` crate, inline during display (not capture)
- Ring buffer: `VecDeque` bounded by `--max-packets`
