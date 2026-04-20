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
coloring, capture statistics, packet diff, and keyboard shortcut help.

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

## Architecture

```
src/
  main.rs       — entry point, terminal setup, event loop, key dispatch
                  (handle_key, handle_list_key, handle_detail_key,
                  handle_flows_key, handle_stream_key, handle_mouse)
  app.rs        — App state, View (List/Detail/Flows/Stream), ProcessFilter,
                  ProcessPicker, InterfacePicker, FlowInfo, bookmarks,
                  bandwidth tracking, page nav, column widths, DNS cache,
                  stream data, payload search helpers, diff mark/pair
  capture.rs    — libpcap capture thread with AtomicBool stop, list_interfaces()
  clipboard.rs  — pbcopy/xclip clipboard helper
  config.rs     — theme persistence (TOML via directories crate)
  dns.rs        — reverse DNS resolution via libc getnameinfo, batch resolver,
                  display helper
  export.rs     — write_pcap + read_pcap (classic libpcap format)
  hex.rs        — hexyl-style hex dump renderer, hex_dump_plain, hex_string
  packet.rs     — packet parsing (IPv4/IPv6), DecodedField, FlowKey,
                  TCP/UDP/ICMP/ARP decode, TLS handshake decode (SNI extraction)
  process.rs    — lsof-based process socket resolution
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
    helpers.rs  — shared UI utilities (stripe, highlight, key_badge, muted_span)
    help.rs     — keyboard shortcut help overlay
    stats_summary.rs — capture statistics summary overlay
    diff.rs     — packet hex diff overlay
```

## Theme System

16 themes ported from `pastel-market` (8 dark + 8 light):
Default, Gruvbox, Solarized, Ayu, Flexoki, Zoegi, FFE Dark, Postrboard,
and their light variants.

- Press `t` to cycle themes at runtime.
- **Ghostty auto-detection**: on startup, reads `~/.config/ghostty/config`
  (or macOS app support path), parses `theme = <name>`, and maps known
  Ghostty theme families (gruvbox, solarized, ayu, flexoki, ffe, etc.)
  to the matching hexcap theme index.
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

## Conventions

- Use `anyhow::Result` for all fallible functions.
- Use `tracing::{info, warn, error, debug}` instead of `println!` / `eprintln!`.
- Keep modules small and focused; one responsibility per file.
- Packet capture runs on a background thread; TUI runs on the main thread.
- All UI functions take `&Theme` as a parameter — no hardcoded colors.
- Version managed via `VERSION` file + `scripts/version.sh` (GNU sed).
- Dual-licensed MIT + BSD-3-Clause (for libpcap compatibility).
