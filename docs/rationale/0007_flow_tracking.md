# 0007 — Flow Colorization and Connection Tracking

## Context

In a busy capture, it is hard to visually follow a single TCP conversation
across hundreds of interleaved packets. Users need to see which packets
belong to the same connection at a glance.

## Decision

**Bidirectional flow keys with per-flow pastel colors, plus a dedicated
flows table view.**

### Flow colorization

- A `FlowKey` struct normalizes bidirectional flows by sorting
  `(protocol, addr:port, addr:port)` so that `A→B` and `B→A` produce the
  same key.
- 8 pastel colors are assigned round-robin to flows as they appear.
- In the packet list, source and destination columns are colored by their
  flow, making conversations visually trackable.

### Connection tracking (`View::Flows`)

- Pressing `n` opens a flows table showing: protocol, source, destination,
  packet count, total bytes, first/last seen times.
- `Enter` on a flow filters the packet list to show only that flow's packets.
- `N` clears the flow filter.
- Flow state is maintained in `App::flows: Vec<FlowInfo>` with a
  `HashMap<FlowKey, usize>` index for O(1) lookup on each new packet.

### Bandwidth sparkline

- A 30-sample ring buffer tracks bytes-per-second over 1-second windows.
- The stats bar renders a Unicode sparkline (`▁▂▃▄▅▆▇█`) showing recent
  bandwidth alongside a human-readable rate (KB/s, MB/s).

## Why normalize flow keys bidirectionally?

TCP and UDP connections are inherently bidirectional. Without normalization,
a single HTTP request would show as two separate flows (client→server and
server→client), defeating the purpose of flow tracking.

## Why 8 colors?

8 distinct pastel colors provide enough differentiation for the most recent
active flows visible on screen. More colors would reduce contrast between
similar hues. The round-robin assignment means colors recycle, but in
practice the visible window of packets rarely exceeds 8 simultaneous flows.
