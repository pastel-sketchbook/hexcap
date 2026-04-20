# 0015 — Follow Speed, Bookmark Persistence, Annotations, Multi-Interface, GeoIP, Display Filters

## Context

Batch 4 added six capabilities: follow speed cycling, bookmark persistence,
packet annotations, multi-interface capture, GeoIP lookup, and Wireshark-style
display filters.

## Follow Speed Cycling

`F` key cycles through follow modes: off → every packet → every 5th → every
10th → every 25th → off. This lets users keep the view near the latest traffic
without the full CPU cost of scrolling on every packet during high-rate captures.

## Bookmark Persistence

Bookmarks are saved to a `.pcap.bookmarks` sidecar file alongside pcap exports.
When loading a pcap with `--read`, the sidecar is automatically loaded if present.
Format is one packet ID per line — simple, human-readable, and easy to edit.

## Packet Annotations

`a` key opens an annotation input bar for the selected packet. Annotations are
stored in a `HashMap<u64, String>` keyed by packet ID. Annotated packets show a
`✎` icon in the `#` column. Annotations are persisted to a `.pcap.annotations`
sidecar file (one `id<TAB>text` per line) alongside exports and loaded on import.

## Multi-Interface Capture

The `-i` flag accepts comma-separated interface names (e.g. `-i en0,lo0`).
`CaptureGroup` spawns one capture thread per interface, all sharing:
- The same `Arc<Mutex<App>>` for packet storage
- A shared `Arc<AtomicU64>` counter for globally unique packet IDs
- A shared `Arc<AtomicBool>` stop signal

This avoids the complexity of multiplexing pcap handles on a single thread.

## GeoIP Lookup

`--geoip <path>` loads a MaxMind GeoLite2-Country MMDB file. Country codes are
displayed as `[US]` suffixes on IP addresses. Private/link-local IPs are skipped
via `is_global()` checks. The lookup runs inline during packet display (not
during capture) to avoid adding latency to the capture path.

**Design choice**: GeoIP is always-on when the flag is provided — no toggle key.
`G` was already taken (go to last packet), and the overhead of MMDB lookups is
negligible for display-time resolution.

**API note**: `maxminddb` v0.27 uses `reader.lookup(ip).ok()?.decode().ok()??`
— `lookup` returns `Result<LookupResult>`, then `decode()` returns
`Result<Option<T>>`, requiring the double `?`.

## Display Filters

`\` key opens a Wireshark-style display filter bar. Supported tokens
(space-separated, all must match = AND logic):

| Token | Matches |
|-------|---------|
| `tcp`, `udp`, `icmp`, `dns`, `arp` | Protocol |
| `port:443` | Source or destination port |
| `ip:10.0.0.1` | Source or destination IP prefix |
| `syn`, `rst`, `fin` | TCP flags |
| `!token` | Negation of any token |

Active filter is shown in the stats row. Enter an empty filter to clear.

**Design choice**: software post-filter rather than BPF, consistent with the
process filter approach. BPF can't express all these conditions (especially
TCP flag inspection combined with protocol filtering), and software filtering
on the display buffer is fast enough for interactive use.

## Files Changed

- `src/app.rs` — follow speed state, bookmark/annotation persistence hooks,
  `display_filter` fields, `matches_display_filter()` function
- `src/capture.rs` — `CaptureGroup` for multi-interface
- `src/export.rs` — bookmark/annotation sidecar save/load
- `src/geoip.rs` — new module for MaxMind MMDB lookup
- `src/main.rs` — `F` key, `a` key, `\` key, `--geoip` flag, multi-interface startup
- `src/ui/list.rs` — annotation `✎` icon, GeoIP display, display filter bar
- `src/ui/stats.rs` — display filter indicator
- `src/ui/footer.rs` — `\` hint
- `src/ui/help.rs` — `\` binding
