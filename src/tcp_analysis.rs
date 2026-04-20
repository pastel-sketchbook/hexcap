//! TCP sequence analysis — Wireshark-style stateful TCP analysis.
//!
//! Tracks per-flow TCP state (expected sequence/ack numbers) and produces
//! `ExpertItem`s for anomalies: retransmissions, dup ACKs, out-of-order,
//! zero window, keep-alive, fast retransmit, window full, etc.

use std::collections::HashMap;

use crate::expert::{ExpertGroup, ExpertItem, Severity};
use crate::packet::{CapturedPacket, Protocol};

/// Per-direction state for one side of a TCP connection.
#[derive(Debug, Clone, Default)]
struct DirectionState {
    /// Next expected sequence number (seq + segment_len).
    next_seq: u32,
    /// Last-seen acknowledgment number.
    last_ack: u32,
    /// Last-seen window size.
    last_window: u16,
    /// Number of consecutive duplicate ACKs.
    dup_ack_count: u32,
    /// Whether we've seen any data (next_seq has been set).
    initialized: bool,
}

/// A directional key: (src, dst) as strings, NOT normalized.
/// This lets us track forward vs reverse independently.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DirectionalKey(String, String);

/// TCP analysis engine. Accumulates state across packets.
pub struct TcpAnalyser {
    /// Per-direction state. Key is (src_addr, dst_addr) — not normalized.
    state: HashMap<DirectionalKey, DirectionState>,
}

impl TcpAnalyser {
    pub fn new() -> Self {
        Self {
            state: HashMap::new(),
        }
    }

    /// Analyse a single packet and return expert items (may be empty).
    pub fn analyse(&mut self, pkt: &CapturedPacket) -> Vec<ExpertItem> {
        if pkt.protocol != Protocol::Tcp && pkt.protocol != Protocol::Dns {
            return vec![];
        }
        // Only analyse TCP (DNS-over-TCP still has tcp_flags).
        if pkt.tcp_flags == 0 && pkt.protocol != Protocol::Tcp {
            return vec![];
        }

        let Some(tcp_info) = Self::extract_tcp_fields(pkt) else {
            return vec![];
        };

        let mut items = Vec::new();

        let fwd_key = DirectionalKey(pkt.src.clone(), pkt.dst.clone());
        let rev_key = DirectionalKey(pkt.dst.clone(), pkt.src.clone());

        let flags = tcp_info.flags;
        let seq = tcp_info.seq;
        let ack = tcp_info.ack;
        let segment_len = tcp_info.segment_len;
        let window = tcp_info.window;
        let is_syn = flags & 0x02 != 0;
        let is_fin = flags & 0x01 != 0;
        let is_rst = flags & 0x04 != 0;
        let is_ack = flags & 0x10 != 0;

        // Effective segment length: SYN and FIN each consume one sequence number.
        let effective_len = segment_len
            + u32::from(is_syn)
            + u32::from(is_fin);

        // --- Chat-level: connection lifecycle events ---
        if is_syn && !is_ack {
            items.push(ExpertItem {
                severity: Severity::Chat,
                group: ExpertGroup::Sequence,
                summary: "TCP connection initiation (SYN)".into(),
            });
        } else if is_syn && is_ack {
            items.push(ExpertItem {
                severity: Severity::Chat,
                group: ExpertGroup::Sequence,
                summary: "TCP SYN-ACK".into(),
            });
        } else if is_fin {
            items.push(ExpertItem {
                severity: Severity::Chat,
                group: ExpertGroup::Sequence,
                summary: "TCP connection closing (FIN)".into(),
            });
        }

        // --- Error-level: RST ---
        if is_rst {
            items.push(ExpertItem {
                severity: Severity::Error,
                group: ExpertGroup::Sequence,
                summary: "TCP connection reset (RST)".into(),
            });
        }

        // --- Sequence analysis (forward direction) ---
        let fwd = self.state.entry(fwd_key.clone()).or_default();

        if fwd.initialized && !is_syn && !is_rst {
            let expected = fwd.next_seq;

            if effective_len > 0 || is_syn || is_fin {
                if seq != expected && seq < expected && !is_syn {
                    // Check if it's a keep-alive (1 byte behind expected).
                    if segment_len <= 1 && seq == expected.wrapping_sub(1) {
                        items.push(ExpertItem {
                            severity: Severity::Note,
                            group: ExpertGroup::Sequence,
                            summary: "TCP Keep-Alive".into(),
                        });
                    } else {
                        // Retransmission: seq < expected.
                        items.push(ExpertItem {
                            severity: Severity::Note,
                            group: ExpertGroup::Sequence,
                            summary: format!(
                                "TCP Retransmission (expected seq {expected}, got {seq})"
                            ),
                        });
                    }
                } else if seq > expected {
                    // Previous segment not captured / out-of-order.
                    let gap = seq.wrapping_sub(expected);
                    items.push(ExpertItem {
                        severity: Severity::Warn,
                        group: ExpertGroup::Sequence,
                        summary: format!(
                            "TCP Previous segment not captured ({gap} bytes missing)"
                        ),
                    });
                }
            }

            // Duplicate ACK detection (forward direction).
            if is_ack && segment_len == 0 && !is_syn && !is_fin && !is_rst {
                if ack == fwd.last_ack && window == fwd.last_window && fwd.last_ack != 0 {
                    fwd.dup_ack_count += 1;
                    items.push(ExpertItem {
                        severity: Severity::Note,
                        group: ExpertGroup::Sequence,
                        summary: format!("TCP Dup ACK #{}", fwd.dup_ack_count),
                    });
                } else {
                    fwd.dup_ack_count = 0;
                }
            } else {
                fwd.dup_ack_count = 0;
            }
        }

        // Update forward state.
        if is_syn || effective_len > 0 || !fwd.initialized {
            fwd.next_seq = seq.wrapping_add(effective_len);
            fwd.initialized = true;
        }
        if is_ack {
            fwd.last_ack = ack;
        }
        fwd.last_window = window;

        // --- Window analysis (reverse direction) ---
        // Zero window: the *receiver* (reverse direction) advertises window=0.
        if window == 0 && !is_syn && !is_fin && !is_rst {
            items.push(ExpertItem {
                severity: Severity::Warn,
                group: ExpertGroup::Sequence,
                summary: "TCP Zero Window".into(),
            });
        }

        // Window Full: our segment fills the receiver's advertised window.
        if segment_len > 0 {
            let rev = self.state.get(&rev_key);
            if let Some(rev_state) = rev
                && rev_state.last_window > 0
                && segment_len >= u32::from(rev_state.last_window)
            {
                items.push(ExpertItem {
                    severity: Severity::Warn,
                    group: ExpertGroup::Sequence,
                    summary: "TCP Window Full".into(),
                });
            }
        }

        // --- Keep-Alive ACK (reverse saw keep-alive) ---
        // Simplified: if segment_len == 0 and window unchanged and ack unchanged
        // and reverse last packet was keep-alive, this is a keep-alive ACK.
        // (We skip this for now — requires tracking the last packet type per direction.)

        items
    }

    /// Extract TCP header fields from a captured packet.
    fn extract_tcp_fields(pkt: &CapturedPacket) -> Option<TcpFields> {
        let data = &pkt.data;
        if data.len() < 14 {
            return None;
        }
        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        let ip = &data[14..];
        let ip_hdr_len = match ethertype {
            0x0800 => {
                if ip.is_empty() { return None; }
                ((ip[0] & 0x0F) as usize) * 4
            }
            0x86DD => 40,
            _ => return None,
        };
        if ip.len() < ip_hdr_len + 20 {
            return None;
        }
        let tcp = &ip[ip_hdr_len..];
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let ack_num = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        let flags = tcp[13];
        let window = u16::from_be_bytes([tcp[14], tcp[15]]);
        let data_offset = ((tcp[12] >> 4) as usize) * 4;

        // IP total length to compute TCP segment payload.
        let ip_total_len = match ethertype {
            0x0800 => u16::from_be_bytes([ip[2], ip[3]]) as usize,
            0x86DD => (u16::from_be_bytes([ip[4], ip[5]]) as usize) + 40,
            _ => return None,
        };
        let tcp_total = ip_total_len.saturating_sub(ip_hdr_len);
        let segment_len = tcp_total.saturating_sub(data_offset) as u32;

        Some(TcpFields {
            seq,
            ack: ack_num,
            flags,
            window,
            segment_len,
        })
    }
}

struct TcpFields {
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    segment_len: u32,
}
