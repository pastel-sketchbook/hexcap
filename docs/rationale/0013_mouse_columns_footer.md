# 0013 — Mouse Support, Column Resizing, and Adaptive Footer

## Context

Several usability improvements were grouped together as a single batch
of quality-of-life enhancements.

## Mouse Support

- Mouse scroll wheel navigates the packet list, scrolls hex dump in
  detail view, and scrolls flows in flows view.
- Enabled via crossterm's `EnableMouseCapture` / `DisableMouseCapture`.
- No click-to-select (yet) — scroll only. This avoids complex hit-testing
  against table rows while covering the most common mouse interaction.

## Column Resizing (`Tab`, `<`, `>`)

- `Tab` cycles through the 6 table columns (selected for resizing).
- `<` / `>` narrows or widens the selected column by 2 characters.
- Adjustments are stored as `i16` deltas from base widths, applied at
  render time. Minimum column width is clamped at 4 characters.

### Why not drag-to-resize?

Mouse drag events in terminal UIs require tracking mouse position
relative to column borders, which is fragile and terminal-dependent.
Keyboard-based resizing is deterministic and works everywhere.

## Adaptive Footer

- The footer now computes available width and renders key hints in
  priority order, truncating when space runs out.
- Most important keys (Quit, Enter, Nav) appear first; less critical
  keys (Theme, DNS) are shown only when there's room.
- Unicode symbols (`↵`, `␣`) replace verbose labels ("Enter", "Space")
  to save horizontal space.

### Why priority-based truncation?

Fixed-layout footers either overflow on narrow terminals or waste space
on wide ones. Priority-ordered adaptive rendering ensures the most
useful hints are always visible regardless of terminal width.

## Capture Duration and Packets-per-Second

- The stats bar now shows elapsed capture time (`HH:MM:SS`) and current
  packets-per-second rate.
- PPS is computed per 1-second window alongside the bandwidth tracking,
  reusing the same tick mechanism.
