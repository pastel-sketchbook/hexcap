---
description: Rust project conventions for hexcap.
globs: "*.rs, Cargo.toml, Cargo.lock"
alwaysApply: true
---

# Rust — hexcap

A Rust TUI packet capture tool. Captures live network packets with **libpcap**,
displays them in a **ratatui** terminal UI, and provides per-packet hex
inspection powered by **hexyl**-style rendering.

## Goal

Show captured packets in a scrollable TUI list, allow selecting a packet to
view its raw bytes in a hexyl-style hex dump pane. Support filtering by
protocol, process, and flow. Support interface switching, pcap export/import,
clipboard copy, bookmarks, live bandwidth tracking, DNS resolution, TCP stream
follow, TLS handshake decode, mouse scrolling, column resizing, semantic packet
coloring, capture statistics, packet diff, display filters, GeoIP lookup,
packet annotations, follow speed cycling, keyboard shortcut help, and
agent integration (prompt mode, split mode, bidirectional socket).

## Build & Run

- `cargo build` to compile.
- `cargo run` to launch the TUI (requires root/sudo for raw capture).
- `cargo test` to run all tests.
- `cargo clippy` for lints.
- `cargo fmt --all` to format code.
- `task run` to build release and run.
- `task run:dev` for debug build.
- `task check:all` to format + lint + test.
- `task version:show/patch/minor/major/sync/tag` for version management.

## Key Dependencies

- `pcap` — libpcap bindings for packet capture.
- `ratatui` + `crossterm` — terminal UI framework.
- `clap` — CLI argument parsing (interface, filter, process, read, write, etc.).
- `anyhow` — error handling.
- `tracing` + `tracing-subscriber` — structured logging.
- `directories` — XDG config paths for theme persistence.
- `libc` — reverse DNS resolution via `getnameinfo`.
- `maxminddb` — GeoIP country lookup from MaxMind MMDB files.
- `serde_json` — JSON serialization for headless/agent-friendly output.
- `tui-markdown` — markdown rendering for agent pane output.

## Architecture

```
src/
  main.rs       — entry point, CLI structs, terminal setup
  keys.rs       — key/mouse event handlers (handle_key, handle_list_key,
                  handle_detail_key, handle_flows_key, handle_stream_key,
                  handle_mouse)
  event_loop.rs — main event loop (run_loop), agent command execution
                  (execute_agent_command)
  agent.rs      — AgentPipe (PTY-based child process), SpawnMode (Prompt/Split),
                  AgentPreset with command_template/binary/spawn_mode,
                  spawn_pty() for interactive PTY agents, open_split() for
                  terminal split pane agents (Ghostty/tmux/WezTerm/Zellij),
                  SocketServer (UDS broadcast + bidirectional @@HEXCAP: read),
                  strip_ansi(), resolve_binary(), expand_command(), build_prompt()
  app.rs        — App state, View (List/Detail/Flows/Stream), ProcessFilter,
                  ProcessPicker, InterfacePicker, FlowInfo, bookmarks,
                  bandwidth tracking, page nav, column widths, DNS cache,
                  stream data, payload search helpers, diff mark/pair,
                  agent_pane_ratio, agent_pane_dragging
  capture.rs    — libpcap capture thread with AtomicBool stop, list_interfaces()
  clipboard.rs  — pbcopy/xclip clipboard helper
  config.rs     — theme persistence (TOML via directories crate)
  dns.rs        — reverse DNS resolution via libc getnameinfo, batch resolver,
                  display helper
  expert.rs     — Expert information system: Severity (Chat/Note/Warn/Error),
                  ExpertGroup, ExpertItem, severity colors and symbols
  export.rs     — write_pcap + read_pcap (classic libpcap format)
  headless.rs   — JSON output for subcommands and --json flag; serializes
                  packets, flows, stats, streams, and single-packet decode
                  as JSON arrays or JSONL for agent/pipeline consumption;
                  Enrichment struct for GeoIP+DNS in headless mode
  geoip.rs      — MaxMind MMDB lookup, country code [XX] suffix for IPs
  hex.rs        — hexyl-style hex dump renderer, hex_dump_plain, hex_string
  packet.rs     — packet parsing (IPv4/IPv6), DecodedField, FlowKey,
                  TCP/UDP/ICMP/ARP decode, TLS handshake decode (SNI extraction)
  process.rs    — lsof-based process socket resolution
  tcp_analysis.rs — Wireshark-style TCP sequence analysis: retransmissions,
                  dup ACKs, out-of-order, zero window, keep-alive, window full,
                  connection lifecycle (SYN/FIN/RST) detection
  theme.rs      — 16 themes (8 dark + 8 light), Ghostty auto-detection
  ui/
    mod.rs      — main layout dispatcher (list/detail/flows/stream layouts)
    header.rs   — pastel-colored title bar, live/paused badge, packet count
    list.rs     — packet table with flow colors, bookmarks, search bar,
                  adjustable column widths, DNS display
    detail.rs   — packet info bar, decoded fields panel, hex dump pane,
                  TCP stream content view
    flows.rs    — flows table (proto, endpoints, packets, bytes)
    footer.rs   — adaptive key hints (priority-ordered, width-aware),
                  status message, process filter, theme, version
    picker.rs   — process picker + interface picker overlays
    stats.rs    — protocol counts, bytes, filter, flow indicator,
                  bandwidth sparkline, capture duration, packets/sec
    helpers.rs  — shared UI utilities (stripe, highlight, key_badge, muted_span,
                  is_ghostty detection helper)
    help.rs     — keyboard shortcut help overlay
    stats_summary.rs — capture statistics summary overlay
    diff.rs     — packet hex diff overlay
    flow_graph.rs — flow sequence diagram overlay (navigable)
    agent_pane.rs — agent output split pane with markdown rendering
```

## Theme System

16 themes ported from `pastel-market` (8 dark + 8 light):
Default, Gruvbox, Solarized, Ayu, Flexoki, Zoegi, FFE Dark, Postrboard,
and their light variants.

- Press `t` to cycle themes at runtime.
- **Ghostty auto-detection**: `is_ghostty()` helper in `ui/helpers.rs` provides
  3-tier detection: env var `GHOSTTY_RESOURCES_DIR` → `TERM_PROGRAM` →
  `pgrep -xi ghostty` (case-insensitive, works under sudo). On startup, reads
  `~/.config/ghostty/config` (or macOS app support path), parses `theme = <name>`,
  and maps known Ghostty theme families to the matching hexcap theme index.
- Theme persisted to `~/.config/hexcap/preferences.toml`.
- Each theme includes hex dump colors: `hex_null`, `hex_ascii`, `hex_space`,
  `hex_high`, `hex_other`, `hex_offset`.

## Key Design Decisions

- **Layout**: Follows pastel-market's vertical panel pattern — header | content | footer.
- **Vim keybindings**: j/k navigate, Enter opens detail, Esc/q goes back, Space pauses.
- **Background capture**: Packet capture runs on a dedicated `std::thread`; TUI renders on main thread with `Arc<Mutex<App>>`.
- **Ring buffer**: Packets stored in a `VecDeque` bounded by `--max-packets`.
- **Flow tracking**: Bidirectional `FlowKey` normalization, 8 pastel colors round-robin, dedicated flows view.
- **Interface switching**: `AtomicBool` stop signal + capture thread restart; mutex guard dropped before restart to avoid deadlock.
- **Pcap format**: Classic libpcap (magic `0xA1B2C3D4`) for universal Wireshark/tcpdump compatibility.
- **Process filtering**: Software post-filter via lsof socket resolution (BPF can't filter by PID).
- **Payload search**: Search falls back from metadata → ASCII payload → hex pattern matching.
- **DNS resolution**: Background thread resolves IPs via libc `getnameinfo`; opt-in via `D` key.
- **TCP stream follow**: Capture-order payload concatenation per flow; no sequence-number reassembly.
- **TLS decode**: Inline in TCP decode — record type, version, handshake type, SNI extraction.
- **Mouse support**: Scroll wheel for navigation across all views; no click-to-select.
- **Column resizing**: `Tab`/`<`/`>` keyboard-driven; i16 deltas from base widths.
- **Adaptive footer**: Priority-ordered key hints, truncated to fit available width.
- **Semantic coloring**: TCP flags (RST=red, SYN=green, FIN=amber) + protocol tints; `tcp_flags: u8` on `CapturedPacket`.
- **Packet diff**: `x` marks first packet, `x` again on second opens side-by-side hex diff overlay.
- **Capture stats**: On-the-fly protocol distribution, top talkers, top conversations from packet buffer.
- **Export auto-filename**: `w` without `--write` generates `hexcap_{unix_seconds}.pcap`.
- **Display filters**: `\` key opens filter bar; tokens: `tcp`, `udp`, `icmp`, `dns`, `arp`, `port:N`, `ip:ADDR`, `syn`, `rst`, `fin`, `!` negation.
- **GeoIP lookup**: `--geoip path/to/mmdb` enables country code `[XX]` suffix on IP addresses via `maxminddb`.
- **Packet annotations**: `a` key adds free-text annotation (✎ icon); persisted to `.pcap.annotations` sidecar files.
- **Follow speed cycling**: `F` cycles follow-mode speed — off / 1 / 5 / 10 / 25 packet intervals.
- **Bookmark persistence**: Bookmarks saved to `.pcap.bookmarks` sidecar files alongside pcap exports.
- **Multi-interface capture**: `-i en0,lo0` comma-separated interface list; spawns one capture thread per interface.
- **Headless/JSON mode**: CLI subcommands (`read`, `capture`, `flows`, `stats`, `stream`, `decode`, `interfaces`) bypass the TUI and emit JSON (array or JSONL) to stdout for agent/pipeline consumption. The `--json` flag on the root CLI provides the same headless output for `--read` (JSON array) and live capture (JSONL, bounded by `--max-packets`).
- **Agent pipe/socket**: `--pipe "command"` spawns a child process in a PTY, feeds JSONL packets to the PTY master, and displays output in a bottom split pane. `--socket /path/to/sock` creates a Unix domain socket broadcasting JSONL to all connected clients. `A` toggles agent pane visibility; `J`/`K` scroll the pane. Socket is auto-created when spawning an agent via `A` key; path is copied to clipboard and broadcast to the agent.
- **Agent spawn modes**: PTY mode (`spawn_pty`) for interactive TUI agents (Copilot, OpenCode, Gemini, Amp) — agents run as full TUIs inside a pseudo-terminal in the agent pane and stay alive for ongoing interaction; split mode (`open_split`) for agents in a terminal split pane via Ghostty AppleScript, tmux, WezTerm, or Zellij.
- **Agent picker**: `A` key (with no active agent) opens a picker to select from 4 built-in agents: Copilot, OpenCode, Gemini, Amp. All agents spawn as interactive TUIs in a PTY within the agent pane. Duplicate spawns prevented — shows socket path if agent already active.
- **Agent markdown/ANSI**: Agent output is ANSI-stripped (`strip_ansi()`) and rendered as markdown via `tui-markdown` in the agent pane.
- **Draggable agent pane**: Mouse drag on agent pane border resizes between 20%-80%; `agent_pane_ratio` and `agent_pane_dragging` fields in App.
- **Bidirectional socket**: `SocketServer::bind` accepts `&AgentCommands` and `&AgentQueries` for reading commands and queries from connected clients. Per-client IDs for directed response routing. Socket permissions `0o700`; randomized filename; `chown` to `SUDO_UID:SUDO_GID`; per-client replay buffer. Auto-created for split agents with `HEXCAP_SOCKET` env var.
- **Agent command protocol**: Agents send `@@HEXCAP:{"action":"..."}` lines on stdout to control the TUI. Supported actions: `filter`, `goto`, `pause`, `resume`, `export`, `dns`, `status`, `bookmark`, `annotate`, `flows`, `clear`, `view`, `mark_diff`, `interface`, `register`, `chat`, `ask`, `reply`. Export paths validated against `..` traversal. Interface names validated against available interfaces.
- **Agent query protocol**: Agents send `@@HEXCAP:{"type":"query","id":"r1","query":"<kind>",...}` and receive `{"id":"r1","type":"response","data":...}` routed to the requesting client. Supported queries: `packets` (filter, limit), `flows`, `stats`, `decode` (packet_id), `stream` (flow), `status`, `interfaces`, `agents`. Per-client IDs for directed response routing.
- **Agent registry**: Agents register with `{"action":"register","name":"<name>","capabilities":["..."]}`. Registry maps client_id to name/capabilities. `agents` query returns all registered agents.
- **Agent chat**: `{"action":"chat","message":"..."}` broadcasts `{"type":"chat","from":"<name>","message":"..."}` to all other connected agents (not the sender).
- **Agent relay**: `{"action":"ask","to":"<name>","request_id":"<id>","message":"..."}` routes a directed message to a named agent; `{"action":"reply",...}` sends a response back. Messages arrive as `{"type":"ask",...}` / `{"type":"reply",...}` with sender name resolved from registry.

## Conventions

- Use `anyhow::Result` for all fallible functions.
- Use `tracing::{info, warn, error, debug}` instead of `println!` / `eprintln!`.
- Keep modules small and focused; one responsibility per file.
- Packet capture runs on a background thread; TUI runs on the main thread.
- All UI functions take `&Theme` as a parameter — no hardcoded colors.
- Version managed via `VERSION` file + `scripts/version.sh` (GNU sed).
- Dual-licensed MIT + BSD-3-Clause (for libpcap compatibility).
