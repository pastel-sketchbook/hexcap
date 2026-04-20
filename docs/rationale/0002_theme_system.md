# 0002 — Theme System: 16 Themes with Ghostty Auto-Detection

## Context

Terminal applications that hardcode colors look broken on non-default terminal
themes. hexcap is designed to be used across different terminals and color
schemes, so it needs a flexible theme system.

## Decision

**16 built-in themes (8 dark + 8 light) ported from pastel-market, with
runtime cycling and persistence.**

Each `Theme` struct defines 18 color slots covering UI chrome (bg, fg, accent,
border, highlight, stripe, key badges) and hex dump categories (null, ASCII,
whitespace, high bytes, other, offset).

### Theme persistence

Following pastel-market's pattern:
- Preferences are stored as TOML at `~/.config/hexcap/preferences.toml` via
  the `directories` crate (`ProjectDirs`).
- The file contains a single field: `theme = "Gruvbox"`.
- On startup, the persisted theme is loaded. If no preferences file exists,
  Ghostty auto-detection is attempted as a fallback.
- Every `t` keypress saves the new theme immediately.

### Ghostty auto-detection

On first run (no preferences file), hexcap reads the Ghostty terminal config
and maps known theme families (gruvbox, solarized, ayu, flexoki, ffe) to the
closest hexcap theme. This gives a good default without user configuration.

## Why not `Color::Reset` everywhere?

`Color::Reset` defers to the terminal's default, which works for simple apps
but breaks hex dump coloring and row striping — both require specific
background colors to create visual structure. Explicit colors per theme give
full control.

## Why 18 color slots?

Fewer slots force reuse that creates visual ambiguity (e.g., the selected row
highlight blending with protocol tags). More slots would be harder to
maintain across 16 themes. 18 is the sweet spot that covers all distinct
visual roles.
