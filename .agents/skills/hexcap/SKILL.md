---
name: hexcap
version: 2.0.0
description: |
  Use hexcap to capture, inspect, and analyze network packets from the terminal.
  Covers live capture, pcap import/export, protocol filtering, display filters,
  hex dump inspection, TCP stream follow, TLS handshake decode, DNS resolution,
  GeoIP lookup, flow tracking, process filtering, packet diff, annotations,
  capture statistics, TCP sequence analysis, expert information, protocol
  hierarchy, flow sequence diagrams, time display formats, agent pipe/socket
  communication, and headless JSON output. Use when troubleshooting network
  issues, analyzing traffic patterns, inspecting protocols, or performing
  packet-level forensics.
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
| `--json` | | false | Output JSON instead of launching TUI |
| `--compact` | | false | Compact JSON (no pretty-printing) |
| `--dns` | | false | Enable DNS enrichment in headless mode |
| `--pipe` | | none | Pipe JSONL to child process (e.g. "uv run agent.py") |
| `--socket` | | none | Unix domain socket path for JSONL broadcast |

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
| `E` | Expert information overlay (TCP analysis diagnostics) |
| `H` | Protocol hierarchy & endpoint statistics |
| `T` | Cycle time format (absolute / relative / delta) |
| `R` | Toggle time reference on selected packet (t=0 point) |
| `:` | Go to packet by number |
| `A` | Agent picker / toggle pane |
| `J` / `K` | Scroll agent pane down / up |
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
| `G` | Flow sequence diagram (arrow-style packet timeline) |
| `Esc` / `q` | Back to list |

### Stream View

| Key | Action |
|-----|--------|
| `j` / `k` | Scroll stream content |
| `y` | Copy stream hex dump |
| `Esc` / `q` | Back to detail |

## Display Filters

Press `\` to open the display filter bar. Supports AND/OR combinators and
comparison operators. Enter an empty filter to clear.

### Tokens

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
| `ack` | TCP ACK flag set |
| `psh` | TCP PSH flag set |
| `rst` | TCP RST flag set |
| `fin` | TCP FIN flag set |
| `expert` | Packets with any expert information items |
| `expert.chat` | Packets with Chat-level expert items |
| `expert.note` | Packets with Note-level expert items |
| `expert.warn` | Packets with Warn-level expert items |
| `expert.error` | Packets with Error-level expert items |
| `len>N` / `len<=N` | Packet length comparisons (`>=`, `<=`, `==`, `!=`, `>`, `<`) |
| `!token` | Negate any token (e.g. `!arp`, `!port:22`) |

### Combinators

| Syntax | Meaning |
|--------|---------|
| `tcp port:443` | Implicit AND (space-separated) |
| `tcp && port:443` | Explicit AND |
| `tcp and port:443` | Explicit AND (word form) |
| `tcp || udp` | OR combinator |
| `tcp or udp` | OR combinator (word form) |

**Examples:**
- `tcp port:443` — HTTPS traffic only
- `tcp syn` — TCP SYN packets (connection initiations)
- `!arp !icmp` — Exclude ARP and ICMP
- `ip:192.168.1 tcp` — TCP traffic from/to 192.168.1.x subnet
- `tcp || udp` — TCP or UDP traffic
- `len>100 && tcp` — TCP packets larger than 100 bytes
- `expert.warn || expert.error` — Packets with warnings or errors

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
3. Press H for protocol hierarchy (layered protocol tree with byte percentages)
4. Press n for flows view (connections with directional A→B/B→A stats)
5. Enter on a flow to filter packets for that connection
6. Press G to see the flow sequence diagram (arrow timeline)
```

### Diagnose TCP issues

```
1. Capture traffic, then press Space to pause
2. Press E for expert information overlay
3. Look for Warn/Error items: retransmissions, dup ACKs, zero windows
4. Filter with: expert.warn || expert.error
5. Press : then type a packet number to jump directly to it
6. Enter on a flagged packet to see expert items in the detail view
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

## Agent Usage — Headless JSON Mode

hexcap subcommands bypass the TUI and emit JSON to stdout. Agents should use
these directly instead of tcpdump/tshark workarounds.

### Subcommands

| Command | Output | Description |
|---------|--------|-------------|
| `hexcap read <file> [-f filter] [-n limit]` | JSON array | Decode pcap to JSON |
| `sudo hexcap capture [-i iface] [-f bpf] [-c count] [-d display_filter]` | JSONL | Live capture, one JSON object per line |
| `hexcap flows <file>` | JSON array | Flow summary (proto, endpoints, packets, bytes) |
| `hexcap stats <file>` | JSON object | Protocol distribution, top talkers, top conversations |
| `hexcap stream <file> [--flow src-dst]` | JSON object | TCP stream payload for a flow |
| `hexcap decode <file> --id N` | JSON object | Single packet with full decode |
| `hexcap interfaces` | JSON array | List available capture interfaces |

The `--json` flag on the root CLI provides equivalent output:
- `hexcap --json --read file.pcap` → JSON array (same as `hexcap read`)
- `sudo hexcap --json -i en0` → JSONL (same as `hexcap capture`, bounded by `--max-packets`)

### Agent Workflow Examples

**Capture and analyze HTTP traffic:**
```bash
# Capture 100 packets of HTTP traffic as JSONL
sudo hexcap capture -i en0 -f "tcp port 80" -c 100 > /tmp/http.jsonl

# Pipe to jq for filtering
cat /tmp/http.jsonl | jq 'select(.protocol == "TCP" and .dst_port == 80)'
```

**Inspect a pcap file programmatically:**
```bash
# Read pcap as JSON, extract source IPs
hexcap read capture.pcap | jq '.[].src_ip' | sort -u

# Get flow summary
hexcap flows capture.pcap | jq '.[] | select(.protocol == "TCP")'

# Get capture statistics
hexcap stats capture.pcap | jq '.top_talkers'
```

**Decode a specific packet:**
```bash
# Full decode of packet #42
hexcap decode capture.pcap --id 42 | jq '.decoded_fields'
```

**Follow a TCP stream:**
```bash
# Extract TCP stream payload
hexcap stream capture.pcap --flow 10.0.0.1:4321-93.184.216.34:443
```

**Agent pipe (live JSONL to child process with TUI pane):**
```bash
# Pipe live packets to an agent script, see output in bottom pane
sudo hexcap --pipe "uv run analyze.py"
# Toggle pane: A, scroll: J/K, drag border to resize
```

**Agent socket (bidirectional JSONL + command channel):**
```bash
# Start hexcap with UDS (broadcasts packets, reads @@HEXCAP: commands)
sudo hexcap --socket /tmp/hexcap.sock

# External agent connects to read packets:
socat UNIX-CONNECT:/tmp/hexcap.sock -

# External agent sends commands back:
echo '@@HEXCAP:{"action":"filter","value":"tcp"}' | socat - UNIX-CONNECT:/tmp/hexcap.sock
```

**Agent split mode (Amp in terminal split):**
```bash
# Press A in hexcap, select Amp → opens in Ghostty/tmux right split
# Amp gets HEXCAP_SOCKET env var to send commands back:
echo '@@HEXCAP:{"action":"flows"}' | socat - UNIX-CONNECT:$HEXCAP_SOCKET
# If Amp is already open, selecting it again shows the socket path
```

**Enriched headless output:**
```bash
# DNS + GeoIP enrichment in headless mode
hexcap read capture.pcap --dns --geoip country.mmdb --compact
```

**Agent command protocol (agent → TUI):**
```
# Agent writes these lines to stdout to control hexcap:
@@HEXCAP:{"action":"filter","value":"tcp port:443"}
@@HEXCAP:{"action":"goto","id":42}
@@HEXCAP:{"action":"pause"}
@@HEXCAP:{"action":"resume"}
@@HEXCAP:{"action":"export","file":"/tmp/capture.pcap"}
@@HEXCAP:{"action":"status","message":"Analyzing..."}
@@HEXCAP:{"action":"bookmark","id":10}
@@HEXCAP:{"action":"annotate","id":5,"text":"suspicious retransmission"}
@@HEXCAP:{"action":"flows"}
@@HEXCAP:{"action":"clear"}
@@HEXCAP:{"action":"view","target":"detail"}
@@HEXCAP:{"action":"mark_diff","id":7}
@@HEXCAP:{"action":"interface","name":"en0"}
@@HEXCAP:{"action":"register","name":"copilot","capabilities":["analyze","filter"]}
@@HEXCAP:{"action":"chat","message":"found suspicious traffic"}
@@HEXCAP:{"action":"ask","to":"copilot","request_id":"a1","message":"analyze packet 42"}
@@HEXCAP:{"action":"reply","to":"opencode","request_id":"a1","message":"it is a retransmission"}
```

## Architecture Notes

- Capture runs on background thread(s) via `std::thread`; TUI on main thread
- Shared state via `Arc<Mutex<App>>`
- Multi-interface: one thread per interface, shared `AtomicU64` packet counter
- Process filtering: software post-filter via lsof (BPF can't filter by PID)
- TCP stream follow: sequence-number ordered reassembly with overlap deduplication
- TCP analysis: per-direction state tracking, detects retransmissions, dup ACKs, out-of-order, zero window, keep-alive, window full, gaps
- Expert info: severity-graded items (Chat/Note/Warn/Error) from TCP analysis, displayed in detail view and overlay
- Time formats: absolute (HH:MM:SS.mmm), relative (since first packet), delta (since previous displayed packet); time reference support
- Protocol hierarchy: layered protocol tree (Ethernet → IPv4 → TCP → TLS) with packet counts and byte percentages
- Flow sequence diagram: arrow-style timeline of packets between two endpoints
- DNS resolution: libc `getnameinfo`, background batch resolver
- GeoIP: `maxminddb` crate, inline during display (not capture)
- Ring buffer: `VecDeque` bounded by `--max-packets`
- Agent pipe: spawns child via PTY (`openpty` + `setsid`), JSONL to PTY master, output read into ring buffer, displayed in bottom split pane (ANSI-stripped, markdown-rendered via `tui-markdown`); agents run as interactive TUIs in the PTY
- Agent pane: resizable by dragging the border chrome (mouse drag, clamped 20%-80%); mouse scroll routes to agent pane when scrolling in its area; socket path is automatically broadcast to the agent on spawn as `{"type":"socket","path":"..."}`
- Agent socket: Unix domain socket, bidirectional — broadcasts JSONL to clients AND reads `@@HEXCAP:` commands/queries from clients; auto-created when spawning agents via `A` key or for split agents; socket path copied to clipboard and broadcast to agent on spawn; shows "Socket" header badge; `chown` to `SUDO_UID:SUDO_GID` so non-root agents can connect; per-client replay of buffered packets on connect (bounded `VecDeque` capped at `max_packets`); randomized filename (`hexcap_{pid}_{random}.sock`); permissions `0o700` (owner only); cleaned up on drop
- Agent picker: `A` key opens picker listing Copilot, OpenCode, Gemini, Amp; all agents spawn as interactive TUIs in a PTY within the agent pane; agents stay alive for ongoing chat and socket communication
- Agent split mode: opens agent TUI in a right-side terminal split pane; Ghostty (AppleScript) or tmux supported; auto-detects terminal (tmux takes priority over Ghostty pgrep fallback); `HEXCAP_SOCKET` env var set so agent can send commands back; under sudo, tmux panes drop privileges to original user via `sudo -u $SUDO_USER`; won't spawn duplicate if agent already open
- Agent startup protocol: when spawned by hexcap, the agent receives `HEXCAP_SOCKET` env var and an initial `--prompt` instructing it to: (1) connect to the socket using `socat` or `nc -U`, (2) register with `@@HEXCAP:{"action":"register",...}`, (3) send a chat ACK to confirm the link, (4) keep the session alive for ongoing user queries. A background `socat` listener maintains a persistent socket connection and appends incoming messages (including user chat) to `HEXCAP_INBOX` (a file at `$HEXCAP_SOCKET.inbox`). The agent reads incoming messages with `cat $HEXCAP_INBOX` or `tail -f $HEXCAP_INBOX` and responds via `echo '@@HEXCAP:...' | socat - UNIX-CONNECT:$HEXCAP_SOCKET`.
- Ghostty detection: `GHOSTTY_RESOURCES_DIR` → `TERM_PROGRAM` → `pgrep -xi ghostty` (works under sudo which strips env vars)
- Agent command protocol: agents write `@@HEXCAP:{"action":"..."}` to stdout (pipe mode) or to the Unix socket (split mode) to control TUI; supported actions: `filter`, `goto`, `pause`, `resume`, `export`, `dns`, `status`, `bookmark`, `annotate`, `flows`, `clear`, `view`, `mark_diff`, `interface`, `register`, `chat`, `ask`, `reply`; export paths validated against `..` traversal; interface names validated against available interfaces
- Agent query protocol: agents send `@@HEXCAP:{"type":"query","id":"r1","query":"<kind>",...}` and receive `{"id":"r1","type":"response","data":...}` routed to the requesting client only; supported queries: `packets` (filter/limit), `flows`, `stats`, `decode` (packet_id), `stream` (flow), `status`, `interfaces`, `agents`; per-client IDs for directed response routing
- Agent registry: agents register with `{"action":"register","name":"<name>","capabilities":["..."]}`. Registry maps client_id to name/capabilities. `agents` query returns all registered agents.
- Agent chat: `{"action":"chat","message":"..."}` broadcasts `{"type":"chat","from":"<name>","message":"..."}` to all other connected agents (not the sender).
- Agent relay: `{"action":"ask","to":"<name>","request_id":"<id>","message":"..."}` routes a directed message to a named agent; `{"action":"reply",...}` sends a response back. Messages arrive as `{"type":"ask",...}` / `{"type":"reply",...}` with sender name resolved from registry.
- ANSI stripping: agent stdout/stderr lines have escape sequences stripped before display
