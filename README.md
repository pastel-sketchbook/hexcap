# hexcap

TUI packet capture tool with libpcap and hexyl-style hex dump.

Captures live network packets, displays them in a scrollable table with
protocol-colored tags, and provides per-packet hex inspection — all in the
terminal.

## Features

- **Live packet capture** via libpcap with BPF filter support
- **Hexyl-style hex dump** with category-based byte coloring
- **16 themes** (8 dark + 8 light) with runtime cycling and persistence
- **Ghostty auto-detection** — matches your terminal theme on first run
- **Process filtering** — filter packets by process name or PID via `lsof`
- **Protocol filtering** — cycle through TCP, UDP, ICMP, DNS, ARP
- **Text search** — fuzzy search across addresses, protocols, and lengths
- **Vim keybindings** — j/k, g/G, Enter, Esc, /

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

# Limit ring buffer size
sudo hexcap --max-packets 50000
```

## Keybindings

| Key       | Action                        |
|-----------|-------------------------------|
| `j` / `k` | Navigate up/down             |
| `g` / `G` | Jump to first/last packet    |
| `Enter`   | Open hex dump detail view     |
| `Esc`     | Back to list / cancel search  |
| `Space`   | Pause/resume capture          |
| `c`       | Clear all packets             |
| `/`       | Search packets                |
| `f`       | Cycle protocol filter         |
| `F`       | Toggle follow mode            |
| `p`       | Open process picker           |
| `P`       | Clear process filter          |
| `t`       | Cycle theme                   |
| `q`       | Quit                          |

## Themes

16 themes ported from [pastel-market](https://github.com/anomalyco/pastel-market):

**Dark:** Default, Gruvbox, Solarized, Ayu, Flexoki, Zoegi, FFE Dark, Postrboard
**Light:** Default Light, Gruvbox Light, Solarized Light, Flexoki Light, Ayu Light, Zoegi Light, FFE Light, Postrboard Light

The last selected theme is persisted to `~/.config/hexcap/preferences.toml`.

## Architecture

```
src/
  main.rs       — entry point, terminal setup, event loop
  app.rs        — application state, navigation, filtering
  capture.rs    — libpcap capture thread
  config.rs     — theme persistence (TOML)
  hex.rs        — hexyl-style hex dump renderer
  packet.rs     — packet parsing, protocol detection
  process.rs    — process-to-socket resolution (lsof)
  theme.rs      — 16 themes, Ghostty auto-detection
  ui/
    mod.rs      — layout dispatcher
    header.rs   — title bar, live/paused badge
    list.rs     — packet table
    detail.rs   — packet info + hex dump
    footer.rs   — key badges, theme name
    picker.rs   — process picker overlay
    stats.rs    — protocol counts, byte total
    helpers.rs  — shared UI utilities
```

See [docs/rationale/](docs/rationale/) for design decision rationale.

## Development

```sh
task build          # debug build
task run:dev        # debug build + run (sudo)
task run            # release build + run (sudo)
task test           # run tests
task lint           # clippy
task fmt            # format code
task check:all      # format + lint + test
```

## License

Dual-licensed under MIT and BSD-3-Clause. The BSD-3-Clause license is included
for compatibility with libpcap's upstream BSD license.

See [LICENSE-MIT](LICENSE-MIT) and [LICENSE-BSD](LICENSE-BSD).
