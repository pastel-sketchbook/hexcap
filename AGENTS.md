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
protocol, interface selection, and live/paused capture modes.

## Build & Run

- `cargo build` to compile.
- `cargo run` to launch the TUI (requires root/sudo for raw capture).
- `cargo test` to run all tests.
- `cargo clippy` for lints.
- `cargo fmt --all` to format code.
- `task run` to build release and run.
- `task run:dev` for debug build.

## Key Dependencies

- `pcap` — libpcap bindings for packet capture.
- `ratatui` + `crossterm` — terminal UI framework.
- `clap` — CLI argument parsing (interface, filter, etc.).
- `anyhow` — error handling.
- `tracing` + `tracing-subscriber` — structured logging.

## Architecture

```
src/
  main.rs       — entry point, terminal setup, event loop, key dispatch
  app.rs        — application state (View, theme_index), navigation, theme cycling
  theme.rs      — 16 themes (8 dark + 8 light), Ghostty auto-detection
  capture.rs    — libpcap capture thread, packet producer
  packet.rs     — packet parsing, protocol detection, display structs
  hex.rs        — hexyl-style hex dump renderer (theme-colored)
  ui/
    mod.rs      — main layout dispatcher (header | table | footer)
    header.rs   — pastel-colored title bar, live/paused badge, packet count
    list.rs     — packet table with protocol-colored tags, row striping
    detail.rs   — packet info bar + hex dump pane
    footer.rs   — key badge bar + theme name + version
    helpers.rs  — size guard, stripe_style, highlight_style, key_badge, muted_span
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
- Each theme includes hex dump colors: `hex_null`, `hex_ascii`, `hex_space`,
  `hex_high`, `hex_other`, `hex_offset`.

## Key Design Decisions

- **Layout**: Follows pastel-market's vertical panel pattern — header | content | footer.
- **Vim keybindings**: j/k navigate, Enter opens detail, Esc/q goes back, Space pauses.
- **Background capture**: Packet capture runs on a dedicated `std::thread`; TUI renders on main thread with `Arc<Mutex<App>>`.
- **Ring buffer**: Packets stored in a `VecDeque` bounded by `--max-packets`.

## Conventions

- Use `anyhow::Result` for all fallible functions.
- Use `tracing::{info, warn, error, debug}` instead of `println!` / `eprintln!`.
- Keep modules small and focused; one responsibility per file.
- Packet capture runs on a background thread; TUI runs on the main thread.
- All UI functions take `&Theme` as a parameter — no hardcoded colors.
