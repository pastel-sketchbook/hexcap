# 0010 — Payload Search (Hex and ASCII)

## Context

The existing `/` search only matched packet metadata (protocol, addresses,
length). Users inspecting traffic often need to find packets containing
specific byte patterns — a magic number like `FF D8 FF` for JPEG, a
cookie value, or an API key fragment.

## Decision

**Extend the search filter to fall back to payload matching when metadata
doesn't match.**

The search pipeline:
1. Try matching the query against metadata (protocol, src, dst, length).
2. If no metadata match, try case-insensitive ASCII substring search in
   the raw packet bytes.
3. If no ASCII match, try interpreting the query as a hex pattern
   (e.g. `ffd8ff` or `ff d8 ff`) and search for that byte sequence.

### Why not a separate search mode?

A single search bar with automatic detection is simpler than requiring
users to toggle between "metadata", "ASCII", and "hex" modes. The
fallback chain is unambiguous — hex patterns like `ff` could match ASCII
metadata too, but metadata match takes priority, which is the expected
behavior.

## Trade-offs

- Payload search is O(n × m) per packet where m is the query length.
  For large captures this is noticeable, but search only runs on
  keystrokes (not every frame), so the UX impact is minimal.
- Hex queries must have an even number of hex digits to be recognized
  as hex patterns. Odd-length strings are treated as ASCII only.
