# hexcap

TUI packet capture tool with libpcap, hexyl-style hex dump, display filters,
TCP analysis, and protocol hierarchy.

Captures live network packets, displays them in a scrollable table with
protocol-colored tags, and provides per-packet hex inspection — all in the
terminal.

## Features

- **Live packet capture** via libpcap with BPF filter support
- **IPv4 and IPv6** parsing with protocol header decode (TCP/UDP/ICMP/ARP)
- **TLS handshake decode** — record type, version, handshake type, SNI extraction
- **Hexyl-style hex dump** with category-based byte coloring (null, ASCII, whitespace, high, other)
- **16 themes** (8 dark + 8 light) with runtime cycling and persistence
- **Ghostty auto-detection** — matches your terminal theme on first run
- **Process filtering** — filter packets by process name or PID via `lsof`
- **Protocol filtering** — cycle through TCP, UDP, ICMP, DNS, ARP
- **Flow colorization** — 8 pastel colors per bidirectional connection
- **Connection tracking** — flows table view with per-flow filtering
- **Follow TCP stream** — reassembled payload view for any TCP flow
- **Bandwidth sparkline** — live bytes/sec with Unicode sparkline chart
- **Capture duration** — elapsed time and packets-per-second in stats bar
- **Pcap export** — save captures to `.pcap` files (Wireshark-compatible)
- **Pcap import** — load `.pcap` files for offline inspection (`--read`)
- **Interface picker** — switch network interfaces live without restart
- **DNS resolution** — background reverse DNS with `getnameinfo`, opt-in via `D`
- **Payload search** — search inside packet bytes (ASCII substring or hex pattern)
- **Clipboard copy** — `y` copies formatted hex dump, `Y` copies raw hex
- **Packet bookmarks** — mark packets with ★, jump between bookmarks
- **Mouse support** — scroll wheel navigation in all views
- **Column resizing** — adjust table column widths with `Tab`/`<`/`>`
- **Adaptive footer** — key hints truncated to fit terminal width
- **Semantic coloring** — RST (red), SYN (green), FIN (amber), ICMP/ARP/DNS tinted rows
- **Packet diff** — mark two packets and compare hex dumps side-by-side
- **Capture statistics** — protocol distribution, top talkers, top conversations popup
- **Display filters** — `\` key opens filter bar; tokens: `tcp`, `udp`, `icmp`, `dns`, `arp`, `port:N`, `ip:ADDR`, `syn`, `rst`, `fin`, `!` negation
- **Advanced filter syntax** — `||`/`or`, `&&`/`and` combinators; `len>N`/`len<=N` comparisons; `ack`, `psh` flags; `expert`, `expert.warn`, `expert.error` filters
- **TCP sequence analysis** — Wireshark-style retransmission, duplicate ACK, out-of-order, zero window, keep-alive, window full, gap detection
- **Expert information** — severity-graded diagnostic items (Chat/Note/Warn/Error) from TCP analysis, shown in detail view and `E` overlay
- **Time display formats** — absolute (HH:MM:SS), relative (since first packet), delta (since previous); cycle with `T`
- **Time references** — set any packet as t=0 reference point with `R`; `*` prefix indicates reference
- **Go-to-packet** — `:` opens input bar; type packet number and press Enter to jump
- **Protocol hierarchy** — `H` shows protocol layer tree (Ethernet → IPv4 → TCP → TLS) with packet counts and byte percentages
- **Endpoint statistics** — per-IP packet and byte totals in the protocol hierarchy overlay
- **Flow sequence diagram** — `G` in flows view shows arrow-style sequence diagram for the selected flow
- **Conversation details** — directional A→B/B→A packet and byte counts, duration, throughput rate in flows table
- **TCP reassembly** — sequence-number ordered payload reconstruction with overlap deduplication
- **Header status badges** — time format, interface, DNS, active filter, process filter, bookmark count
- **GeoIP lookup** — `--geoip path/to/mmdb` appends country code `[XX]` to IP addresses
- **Packet annotations** — `a` key adds free-text annotation (✎ icon), persisted to `.pcap.annotations` sidecar
- **Follow speed cycling** — `F` cycles follow-mode speed: off / 1 / 5 / 10 / 25 packet intervals
- **Bookmark persistence** — bookmarks saved to `.pcap.bookmarks` sidecar files
- **Multi-interface capture** — `-i en0,lo0` comma-separated; one capture thread per interface
- **Help overlay** — `?` shows all keybindings in a popup
- **Vim keybindings** — j/k, g/G, d/u, Enter, Esc, /
- **Headless/JSON mode** — CLI subcommands and `--json` flag for agent/pipeline consumption
- **Agent pipe** — `--pipe "command"` spawns a child, feeds JSONL to stdin, displays stdout in a bottom split pane
- **Agent socket** — `--socket /path` creates a Unix domain socket broadcasting JSONL to all connected clients
- **Agent picker** — `A` key opens picker to select from Copilot, OpenCode, Gemini, Amp agents
- **Agent spawn modes** — prompt mode (non-interactive CLI) for Copilot/OpenCode/Gemini; split mode (terminal split pane) for Amp
- **Agent markdown rendering** — agent output rendered as markdown in the TUI pane via `tui-markdown`
- **Agent ANSI stripping** — ANSI escape sequences stripped from agent output before display
- **Draggable agent pane** — mouse drag on pane border resizes (20%-80% range)
- **Bidirectional agent socket** — agents send `@@HEXCAP:` commands and queries back via Unix socket; per-client replay on connect
- **Agent commands** — agents control the TUI via `@@HEXCAP:` protocol (filter, goto, pause, export, interface, register, chat, ask, reply, etc.)
- **Agent queries** — agents request data via `@@HEXCAP:{"type":"query",...}` and receive JSON responses (packets, flows, stats, decode, stream, status, interfaces, agents)

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

# Capture on multiple interfaces
sudo hexcap -i en0,lo0

# Enable GeoIP country lookup
sudo hexcap --geoip /path/to/GeoLite2-Country.mmdb

# Pipe packets to an agent process (JSONL to stdin, stdout in pane)
sudo hexcap --pipe "uv run agent.py"

# Stream packets to a Unix domain socket for external agents
sudo hexcap --socket /tmp/hexcap.sock
```

## Agent / Pipeline Mode

hexcap provides CLI subcommands and a `--json` flag for headless, agent-friendly
JSON output — no TUI required.

```sh
# Decode a pcap file to JSON array
hexcap read capture.pcap

# Decode with display filter and limit
hexcap read capture.pcap -f "tcp port:443" -n 100

# Live capture as JSONL (one JSON object per line)
sudo hexcap capture -i en0 -f "tcp port 80" -c 50

# Flow summary
hexcap flows capture.pcap

# Protocol and talker statistics
hexcap stats capture.pcap

# TCP stream payload for a specific flow
hexcap stream capture.pcap --flow 10.0.0.1:4321-93.184.216.34:443

# Decode a single packet by index
hexcap decode capture.pcap --id 42

# List available interfaces
hexcap interfaces

# Compact JSON output (no pretty-printing)
hexcap flows capture.pcap --compact

# Enable DNS enrichment in headless mode
hexcap read capture.pcap --dns

# Pipe packets to an agent with live TUI pane
sudo hexcap --pipe "uv run analyze.py"

# Stream to Unix socket for external agents
sudo hexcap --socket /tmp/hexcap.sock

# --json flag on root CLI (same output, alternate syntax)
hexcap --json --read capture.pcap
sudo hexcap --json -i en0 --max-packets 200
```

### Socket Query Protocol

External agents can connect to the Unix domain socket (created via `--socket`,
`X` key, or automatically for split agents) and send queries to request data:

```sh
# Connect and query flows
echo '@@HEXCAP:{"type":"query","id":"r1","query":"flows"}' | socat - UNIX:/tmp/hexcap_*.sock

# Query packets with filter
echo '@@HEXCAP:{"type":"query","id":"r2","query":"packets","filter":"tcp port:443","limit":10}' | socat - UNIX:/tmp/hexcap_*.sock
```

Supported queries:

| Query | Parameters | Returns |
|-------|-----------|---------|
| `packets` | `filter?`, `limit?` (max 10k) | Matching packets |
| `flows` | — | Flow summary table |
| `stats` | — | Protocol counts, bytes, flow count |
| `decode` | `packet_id` | Full decoded packet |
| `stream` | `flow` | TCP payload for a flow |
| `status` | — | TUI state (packets, view, filters) |
| `interfaces` | — | Available network interfaces |
| `agents` | — | Registered agents (name, capabilities) |

Responses are JSON lines: `{"id":"r1","type":"response","data":...}`

### Agent Registry & Relay

Agents can register with a name and discover each other:

```bash
# Register with hexcap
echo '@@HEXCAP:{"action":"register","name":"copilot","capabilities":["analyze"]}' | socat - UNIX:/tmp/hexcap_*.sock

# List registered agents
echo '@@HEXCAP:{"type":"query","id":"r1","query":"agents"}' | socat - UNIX:/tmp/hexcap_*.sock

# Broadcast chat to all other agents
echo '@@HEXCAP:{"action":"chat","message":"found suspicious traffic on port 443"}' | socat - UNIX:/tmp/hexcap_*.sock

# Send directed message to a named agent
echo '@@HEXCAP:{"action":"ask","to":"copilot","request_id":"a1","message":"analyze packet 42"}' | socat - UNIX:/tmp/hexcap_*.sock

# Reply to an ask
echo '@@HEXCAP:{"action":"reply","to":"opencode","request_id":"a1","message":"it is a retransmission"}' | socat - UNIX:/tmp/hexcap_*.sock
```

Chat messages arrive as: `{"type":"chat","from":"copilot","message":"..."}`
Ask messages arrive as: `{"type":"ask","from":"opencode","request_id":"a1","message":"..."}`
Reply messages arrive as: `{"type":"reply","from":"copilot","request_id":"a1","message":"..."}`

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
| `/`            | Search (metadata + payload)  |
| `f`            | Cycle protocol filter        |
| `F`            | Cycle follow speed (off/1/5/10/25) |
| `\`            | Open display filter bar       |
| `a`            | Annotate selected packet      |
| `p`            | Open process picker          |
| `P`            | Clear process filter         |
| `n`            | Open flows table             |
| `N`            | Clear flow filter            |
| `i`            | Open interface picker        |
| `D`            | Toggle DNS resolution        |
| `w`            | Export to pcap file          |
| `m`            | Toggle bookmark on packet    |
| `'`            | Jump to next bookmark        |
| `"`            | Jump to previous bookmark    |
| `Tab`          | Cycle resize column          |
| `<` / `>`     | Narrow / widen column        |
| `x`            | Mark packet for diff / show diff |
| `I`            | Capture statistics summary   |
| `E`            | Expert information overlay   |
| `H`            | Protocol hierarchy & endpoints |
| `T`            | Cycle time format (abs/rel/delta) |
| `R`            | Toggle time reference on packet |
| `:`            | Go to packet by number       |
| `A`            | Agent picker / toggle pane    |
| `X`            | Create socket / show path    |
| `J` / `K`     | Scroll agent pane down/up    |
| `?`            | Show keybindings help        |
| `t`            | Cycle theme                  |
| `q`            | Quit                         |

### Detail View

| Key            | Action                        |
|----------------|-------------------------------|
| `j` / `k`     | Scroll hex dump              |
| `y`            | Copy formatted hex dump      |
| `Y`            | Copy raw hex string          |
| `S`            | Follow TCP stream            |
| `w`            | Export to pcap file          |
| `t`            | Cycle theme                  |
| `q` / `Esc`   | Back to list                 |

### Stream View

| Key            | Action                        |
|----------------|-------------------------------|
| `j` / `k`     | Scroll stream                |
| `y`            | Copy stream hex dump         |
| `t`            | Cycle theme                  |
| `q` / `Esc`   | Back to detail               |

### Flows View

| Key            | Action                        |
|----------------|-------------------------------|
| `j` / `k`     | Navigate flows               |
| `Enter`        | Filter list by selected flow |
| `G`            | Flow sequence diagram        |
| `t`            | Cycle theme                  |
| `q` / `Esc`   | Back to list                 |

### Mouse

| Action         | Effect                        |
|----------------|-------------------------------|
| Scroll down    | Next item / scroll down      |
| Scroll up      | Previous item / scroll up    |

## Themes

16 themes ported from [pastel-market](https://github.com/anomalyco/pastel-market):

**Dark:** Default, Gruvbox, Solarized, Ayu, Flexoki, Zoegi, FFE Dark, Postrboard
**Light:** Default Light, Gruvbox Light, Solarized Light, Flexoki Light, Ayu Light, Zoegi Light, FFE Light, Postrboard Light

The last selected theme is persisted to `~/.config/hexcap/preferences.toml`.

## Architecture

```
src/
  main.rs       — entry point, CLI structs, terminal setup
  keys.rs       — key/mouse event handlers (list, detail, flows, stream views)
  event_loop.rs — main event loop, agent command execution
  agent.rs      — agent pipe/prompt/split spawn, socket server, query protocol, ANSI stripping
  app.rs        — application state, navigation, filtering, flow tracking
  capture.rs    — libpcap capture thread with AtomicBool stop signal
  clipboard.rs  — system clipboard helper (pbcopy/xclip)
  config.rs     — theme persistence (TOML)
  dns.rs        — reverse DNS resolution (libc getnameinfo)
  expert.rs     — expert information system (Severity, ExpertGroup, ExpertItem)
  export.rs     — pcap file writer and reader
  geoip.rs      — GeoIP country lookup (MaxMind MMDB)
  headless.rs   — JSON output for subcommands and --json flag
  hex.rs        — hexyl-style hex dump renderer
  packet.rs     — packet parsing (IPv4/IPv6), protocol decode, TLS decode, display filters
  process.rs    — process-to-socket resolution (lsof)
  tcp_analysis.rs — Wireshark-style TCP sequence analysis (retransmissions, dup ACKs, etc.)
  theme.rs      — 16 themes, Ghostty auto-detection
  ui/
    mod.rs      — layout dispatcher
    header.rs   — title bar, live/paused badge, status badges
    list.rs     — packet table with flow colors, bookmarks, DNS display
    detail.rs   — decoded fields panel + hex dump + stream view
    flows.rs    — connection tracking table with directional stats
    flow_graph.rs — flow sequence diagram overlay
    footer.rs   — adaptive key hints (priority-ordered, width-aware)
    picker.rs   — process + interface picker overlays
    stats.rs    — protocol counts, bandwidth sparkline, duration, PPS
    helpers.rs  — shared UI utilities, Ghostty detection helper
    help.rs     — keyboard shortcut help overlay
    stats_summary.rs — capture statistics summary overlay
    expert_overlay.rs — expert information overlay
    proto_hierarchy.rs — protocol hierarchy & endpoint stats overlay
    diff.rs     — packet hex diff overlay
    agent_pane.rs — agent output split pane
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
- [0010 — Payload Search](docs/rationale/0010_payload_search.md)
- [0011 — DNS Resolution](docs/rationale/0011_dns_resolution.md)
- [0012 — TCP Stream and TLS Decode](docs/rationale/0012_tcp_stream_and_tls.md)
- [0013 — Mouse, Columns, Footer](docs/rationale/0013_mouse_columns_footer.md)
- [0014 — Export, Coloring, Overlays, Diff](docs/rationale/0014_export_coloring_overlays_diff.md)

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
