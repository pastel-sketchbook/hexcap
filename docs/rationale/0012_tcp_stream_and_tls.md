# 0012 — Follow TCP Stream and TLS Handshake Decode

## Context

Inspecting individual packet hex dumps is tedious when analyzing a TCP
conversation. Users need to see the full reassembled payload (e.g., an
HTTP request/response) and identify TLS handshake details (SNI, version).

## Decisions

### Follow TCP Stream (`S` key in detail view)

- Pressing `S` on a TCP packet opens a Stream view showing the
  concatenated TCP payload for that flow (all packets matching the
  same bidirectional `FlowKey`).
- Payloads are concatenated in capture order (not TCP sequence number
  order). This is a deliberate simplification — for most interactive
  inspection, capture order matches delivery order.
- The stream view displays a hex dump of the full reassembled payload,
  scrollable with j/k and copyable with `y`.

### TLS Handshake Decode

- When a TCP packet contains a TLS record (content type byte at the
  start of the TCP payload), the protocol decode panel shows:
  - Record type (Handshake, Alert, `ChangeCipherSpec`, `ApplicationData`)
  - TLS version (1.0, 1.1, 1.2, 1.3)
  - Handshake message type (`ClientHello`, `ServerHello`, Certificate, etc.)
  - SNI hostname (extracted from the `ClientHello` extensions)
  - Handshake version

### Why not full TCP reassembly with sequence numbers?

Proper TCP reassembly requires tracking sequence numbers, handling
retransmissions, out-of-order segments, and overlapping data. This is
a significant implementation effort for a feature that capture-order
concatenation handles well in practice. If out-of-order delivery is
common, users can export to pcap and use Wireshark.

### Why decode TLS inline rather than as a separate protocol?

TLS rides on TCP — it's not a separate IP protocol. Showing TLS fields
in the existing TCP decode section keeps the detail view compact and
avoids a separate "TLS" protocol classification that would obscure
whether the underlying transport is TCP.

## Trade-offs

- Capture-order concatenation may produce garbled output if packets
  arrive out of order.
- Only the first TLS record per TCP segment is decoded.
- Encrypted application data after the handshake is opaque (by design).
