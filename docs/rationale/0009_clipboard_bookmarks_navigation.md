# 0009 — Clipboard, Bookmarks, and Page Navigation

## Context

Several small but high-value quality-of-life features were added together
to improve the packet inspection workflow.

## Clipboard (`y` / `Y`)

- `y` copies the hex dump (formatted with offsets and ASCII) to the system
  clipboard.
- `Y` copies the raw hex string (no formatting, no spaces) for use in
  tools like `xxd -r` or Wireshark's hex import.
- Implementation uses `pbcopy` on macOS and `xclip`/`xsel` on Linux,
  invoked via `std::process::Command`. The clipboard module
  (`clipboard.rs`) abstracts this.

## Bookmarks (`m` / `'` / `"`)

- `m` toggles a bookmark on the selected packet.
- `'` jumps to the next bookmarked packet, `"` jumps to the previous.
- Bookmarked packets display a ★ prefix in the # column.
- Bookmarks are stored as a `HashSet<u64>` of packet IDs in `App`.

### Why per-packet-ID instead of per-index?

Packet IDs are stable across filtering and sorting. Index-based bookmarks
would shift when the display is filtered, causing users to lose their marks.

## Page navigation (`PageDown`/`d`, `PageUp`/`u`)

- 20-row jumps for fast scrolling through large captures.
- `d`/`u` mirror Vim's `Ctrl-D`/`Ctrl-U` half-page scroll convention.
- Standard `PageDown`/`PageUp` keys also work for users not familiar with
  Vim bindings.
