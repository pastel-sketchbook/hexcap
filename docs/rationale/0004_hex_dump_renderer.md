# 0004 — Hexyl-Style Hex Dump Renderer

## Context

The core value proposition of hexcap is inspecting raw packet bytes in-terminal.
A plain hex dump is hard to read — bytes blend together without visual
differentiation. hexyl (the standalone hex viewer) solves this with
category-based coloring.

## Decision

**Theme-colored hex dump with 5 byte categories.**

Each byte is colored based on its value:

| Category    | Rule                  | Theme Slot    |
|-------------|-----------------------|---------------|
| Null        | `0x00`                | `hex_null`    |
| ASCII       | printable graphic     | `hex_ascii`   |
| Whitespace  | ASCII whitespace      | `hex_space`   |
| High        | `0xFF`                | `hex_high`    |
| Other       | everything else       | `hex_other`   |

The layout follows hexyl's format:
```
OFFSET │ HH HH HH HH  HH HH HH HH │ HH HH HH HH  HH HH HH HH │ ASCII...
```

16 bytes per line, split into two groups of 8 with extra spacing for
readability.

## Why not embed hexyl as a library?

hexyl is a standalone binary, not a library crate. Its rendering is
tightly coupled to terminal output via `ansi_term`. Reimplementing the
coloring logic in ~50 lines of ratatui `Span` construction is simpler
than forking hexyl or shelling out to it.

## Why 5 categories instead of hexyl's full set?

hexyl distinguishes more categories (control chars, extended ASCII ranges).
For packet inspection, the important distinctions are: "is this null padding?",
"is this readable text?", "is this whitespace?", and "is this a boundary
marker (0xFF)?" Five categories cover these cases. More granularity would
add theme complexity without aiding packet analysis.
