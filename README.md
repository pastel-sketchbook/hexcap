# hexcap

TUI packet capture tool with libpcap and hexyl-style hex dump.

Captures live network packets, displays them in a scrollable table with
protocol-colored tags, and provides per-packet hex inspection — all in the
terminal.

## Features

- **Live packet capture** via libpcap with BPF filter support
- **IPv4 and IPv6** parsing with protocol header decode (TCP/UDP/ICMP/ARP)
- **Hexyl-style hex dump** with category-based byte coloring (null, ASCII, whitespace, high, other)
- **16 themes** (8 dark + 8 light) with runtime cycling and persistence
- **Ghostty auto-detection** — matches your terminal theme on first run
- **Process filtering** — filter packets by process name or PID via `lsof`
- **Protocol filtering** — cycle through TCP, UDP, ICMP, DNS, ARP
- **Flow colorization** — 8 pastel colors per bidirectional connection
- **Connection tracking** — flows table view with per-flow filtering
- **Bandwidth sparkline** — live bytes/sec with Unicode sparkline chart
- **Pcap export** — save captures to `.pcap` files (Wireshark-compatible)
- **Pcap import** — load `.pcap` files for offline inspection (`--read`)
- **Interface picker** — switch network interfaces live without restart
- **Clipboard copy** — `y` copies formatted hex dump, `Y` copies raw hex
- **Packet bookmarks** — mark packets with ★, jump between bookmarks
- **Text search** — fuzzy search across addresses, protocols, and lengths
- **Vim keybindings** — j/k, g/G, d/u, Enter, Esc, /

## Install

Requires libpcap development headers.

```sh
# macOS (libpcap is pre-installed)
cargo install --path .

# Linux (Debian/Ubuntu)
sudo apt install libpcap-dev
cargo install --path .
```

## Usage

```sh
# Capture on default interface (requires root)
sudo hexcap

# Specify interface and BPF filter
sudo hexcap -i en0 -f "tcp port 443"

# Filter by process at startup
sudo hexcap --process firefox

# Export packets to file
sudo hexcap --write capture.pcap

# Load a pcap file for offline inspection
hexcap --read capture.pcap

# Limit ring buffer size
sudo hexcap --max-packets 50000
```

## Keybindings

### Packet List

| Key            | Action                        |
|----------------|-------------------------------|
| `j` / `k`     | Navigate up/down              |
| `g` / `G`     | Jump to first/last packet     |
| `d` / `u`     | Page down/up (20 rows)        |
| `PageDown/Up`  | Page down/up (20 rows)       |
| `Enter`        | Open hex dump detail view    |
| `Space`        | Pause/resume capture         |
| `c`            | Clear all packets            |
| `/`            | Search packets               |
| `f`            | Cycle protocol filter        |
| `F`            | Toggle follow mode           |
| `p`            | Open process picker          |
| `P`            | Clear process filter         |
| `n`            | Open flows table             |
| `N`            | Clear flow filter            |
| `i`            | Open interface picker        |
| `w`            | Export to pcap file          |
| `m`            | Toggle bookmark on packet    |
| `'`            | Jump to next bookmark        |
| `"`            | Jump to previous bookmark    |
| `t`            | Cycle theme                  |
| `q`            | Quit                         |

### Detail View

| Key            | Action                        |
|----------------|-------------------------------|
| `j` / `k`     | Scroll hex dump              |
| `y`            | Copy formatted hex dump      |
| `Y`            | Copy raw hex string          |
| `w`            | Export to pcap file          |
| `t`            | Cycle theme                  |
| `q` / `Esc`   | Back to list                 |

### Flows View

| Key            | Action                        |
|----------------|-------------------------------|
| `j` / `k`     | Navigate flows               |
| `Enter`        | Filter list by selected flow |
| `t`            | Cycle theme                  |
| `q` / `Esc`   | Back to list                 |

## Themes

16 themes ported from [pastel-market](https://github.com/anomalyco/pastel-market):

**Dark:** Default, Gruvbox, Solarized, Ayu, Flexoki, Zoegi, FFE Dark, Postrboard
**Light:** Default Light, Gruvbox Light, Solarized Light, Flexoki Light, Ayu Light, Zoegi Light, FFE Light, Postrboard Light

The last selected theme is persisted to `~/.config/hexcap/preferences.toml`.

## Architecture

```
src/
  main.rs       — entry point, terminal setup, event loop, key dispatch
  app.rs        — application state, navigation, filtering, flow tracking
  capture.rs    — libpcap capture thread with AtomicBool stop signal
  clipboard.rs  — system clipboard helper (pbcopy/xclip)
  config.rs     — theme persistence (TOML)
  export.rs     — pcap file writer and reader
  hex.rs        — hexyl-style hex dump renderer
  packet.rs     — packet parsing (IPv4/IPv6), protocol decode
  process.rs    — process-to-socket resolution (lsof)
  theme.rs      — 16 themes, Ghostty auto-detection
  ui/
    mod.rs      — layout dispatcher
    header.rs   — title bar, live/paused badge
    list.rs     — packet table with flow colors, bookmarks
    detail.rs   — decoded fields panel + hex dump
    flows.rs    — connection tracking table
    footer.rs   — key badges, status, theme name
    picker.rs   — process + interface picker overlays
    stats.rs    — protocol counts, bandwidth sparkline
    helpers.rs  — shared UI utilities
```

See [docs/rationale/](docs/rationale/) for design decision rationale:
- [0001 — Architecture](docs/rationale/0001_architecture.md)
- [0002 — Theme System](docs/rationale/0002_theme_system.md)
- [0003 — Process Filtering](docs/rationale/0003_process_filtering.md)
- [0004 — Hex Dump Renderer](docs/rationale/0004_hex_dump_renderer.md)
- [0005 — IPv6 and Protocol Decode](docs/rationale/0005_ipv6_and_protocol_decode.md)
- [0006 — Pcap Export and Import](docs/rationale/0006_pcap_export_import.md)
- [0007 — Flow Tracking](docs/rationale/0007_flow_tracking.md)
- [0008 — Interface Switching](docs/rationale/0008_interface_switching.md)
- [0009 — Clipboard, Bookmarks, Navigation](docs/rationale/0009_clipboard_bookmarks_navigation.md)

## Development

```sh
task build          # debug build
task run:dev        # debug build + run (sudo)
task run            # release build + run (sudo)
task test           # run tests
task lint           # clippy
task fmt            # format code
task check:all      # format + lint + test
task version:show   # show current version
task version:patch  # bump patch version
```

## License

Dual-licensed under MIT and BSD-3-Clause. The BSD-3-Clause license is included
for compatibility with libpcap's upstream BSD license.

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-BSD](LICENSE-BSD).
