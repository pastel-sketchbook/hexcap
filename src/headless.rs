//! Headless (non-TUI) output for agent and pipeline consumption.
//!
//! Each public function corresponds to a CLI subcommand and writes JSON to
//! stdout.  Live capture outputs one JSON object per line (JSONL); file-based
//! commands output a single JSON value.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;

use anyhow::{Result, bail};
use serde::Serialize;

use crate::app::FlowInfo;
use crate::capture;
use crate::export;
use crate::packet::{self, CapturedPacket, FlowKey, Protocol};

// ---------------------------------------------------------------------------
// Display filter (reuse logic from app.rs — standalone version)
// ---------------------------------------------------------------------------

/// Evaluate a display filter expression against a packet.
///
/// Tokens are space-separated (AND logic).  Supported:
///   tcp, udp, icmp, dns, arp, port:N, ip:ADDR, syn, rst, fin, !negation
pub fn matches_display_filter(pkt: &CapturedPacket, filter: &str) -> bool {
    for token in filter.split_whitespace() {
        let (negated, tok) = if let Some(rest) = token.strip_prefix('!') {
            (true, rest)
        } else {
            (false, token)
        };
        let matched = match tok.to_ascii_lowercase().as_str() {
            "tcp" => pkt.protocol == Protocol::Tcp,
            "udp" => pkt.protocol == Protocol::Udp,
            "icmp" => pkt.protocol == Protocol::Icmp,
            "dns" => pkt.protocol == Protocol::Dns,
            "arp" => pkt.protocol == Protocol::Arp,
            "syn" => pkt.tcp_flags & 0x02 != 0,
            "rst" => pkt.tcp_flags & 0x04 != 0,
            "fin" => pkt.tcp_flags & 0x01 != 0,
            other => {
                if let Some(port_str) = other.strip_prefix("port:") {
                    if let Ok(port) = port_str.parse::<u16>() {
                        let src_port = extract_port(&pkt.src);
                        let dst_port = extract_port(&pkt.dst);
                        src_port == Some(port) || dst_port == Some(port)
                    } else {
                        false
                    }
                } else if let Some(ip_str) = other.strip_prefix("ip:") {
                    pkt.src.starts_with(ip_str) || pkt.dst.starts_with(ip_str)
                } else {
                    false
                }
            }
        };
        if negated == matched {
            return false;
        }
    }
    true
}

fn extract_port(addr: &str) -> Option<u16> {
    let colon_pos = addr.rfind(':')?;
    addr[colon_pos + 1..].parse().ok()
}

// ---------------------------------------------------------------------------
// Subcommand: read
// ---------------------------------------------------------------------------

/// Read a pcap file, decode packets, optionally filter, and output as JSON array.
pub fn cmd_read(file: &str, filter: Option<&str>, limit: usize) -> Result<()> {
    let raw = export::read_pcap(Path::new(file))?;
    let stdout = io::stdout();
    let mut out = stdout.lock();

    out.write_all(b"[")?;
    let mut first = true;
    let mut count = 0usize;

    for (i, (timestamp, data)) in raw.into_iter().enumerate() {
        let mut pkt = packet::parse_packet((i + 1) as u64, &data);
        pkt.timestamp = timestamp;

        if let Some(f) = filter
            && !matches_display_filter(&pkt, f)
        {
            continue;
        }

        if !first {
            out.write_all(b",")?;
        }
        first = false;

        serde_json::to_writer(&mut out, &pkt)?;

        count += 1;
        if limit > 0 && count >= limit {
            break;
        }
    }

    out.write_all(b"]\n")?;
    out.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: capture
// ---------------------------------------------------------------------------

/// Capture packets headless, outputting one JSON object per line (JSONL).
pub fn cmd_capture(
    interface: Option<&str>,
    bpf_filter: Option<&str>,
    count: usize,
    display_filter: Option<&str>,
) -> Result<()> {
    let iface = if let Some(i) = interface {
        i.to_string()
    } else {
        let ifaces = capture::list_interfaces()?;
        ifaces
            .first()
            .map(|i| i.name.clone())
            .ok_or_else(|| anyhow::anyhow!("no capture interface found"))?
    };

    let device = pcap::Device::from(iface.as_str());
    let mut cap = pcap::Capture::from_device(device)?
        .promisc(true)
        .timeout(100)
        .open()?;

    if let Some(f) = bpf_filter {
        cap.filter(f, true)?;
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut id = 1u64;
    let mut emitted = 0usize;

    loop {
        match cap.next_packet() {
            Ok(pkt_data) => {
                let pkt = packet::parse_packet(id, pkt_data.data);
                id += 1;

                if let Some(f) = display_filter
                    && !matches_display_filter(&pkt, f)
                {
                    continue;
                }

                serde_json::to_writer(&mut out, &pkt)?;
                out.write_all(b"\n")?;
                out.flush()?;
                emitted += 1;

                if count > 0 && emitted >= count {
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => bail!("capture error: {e}"),
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: flows
// ---------------------------------------------------------------------------

/// Extract flows from a pcap file and output as JSON array.
pub fn cmd_flows(file: &str) -> Result<()> {
    let raw = export::read_pcap(Path::new(file))?;
    let mut flows: HashMap<FlowKey, FlowInfo> = HashMap::new();

    for (i, (timestamp, data)) in raw.into_iter().enumerate() {
        let mut pkt = packet::parse_packet((i + 1) as u64, &data);
        pkt.timestamp = timestamp;

        let key = FlowKey::new(&pkt.src, &pkt.dst);
        let entry = flows.entry(key.clone()).or_insert_with(|| FlowInfo {
            key,
            protocol: pkt.protocol,
            src: pkt.src.clone(),
            dst: pkt.dst.clone(),
            packet_count: 0,
            total_bytes: 0,
        });
        entry.packet_count += 1;
        entry.total_bytes += pkt.length as u64;
    }

    let mut flow_list: Vec<&FlowInfo> = flows.values().collect();
    flow_list.sort_by_key(|f| Reverse(f.total_bytes));

    serde_json::to_writer_pretty(io::stdout().lock(), &flow_list)?;
    println!();
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: stats
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StatsOutput {
    total_packets: usize,
    total_bytes: u64,
    protocols: HashMap<String, u64>,
    top_talkers: Vec<TalkerEntry>,
    top_conversations: Vec<ConversationEntry>,
}

#[derive(Serialize)]
struct TalkerEntry {
    address: String,
    packets: u64,
}

#[derive(Serialize)]
struct ConversationEntry {
    src: String,
    dst: String,
    packets: u64,
    bytes: u64,
}

/// Compute capture statistics from a pcap file and output as JSON.
pub fn cmd_stats(file: &str) -> Result<()> {
    let raw = export::read_pcap(Path::new(file))?;
    let total_packets = raw.len();
    let mut protocols: HashMap<String, u64> = HashMap::new();
    let mut talkers: HashMap<String, u64> = HashMap::new();
    let mut conversations: HashMap<String, (String, String, u64, u64)> = HashMap::new();
    let mut total_bytes: u64 = 0;

    for (i, (timestamp, data)) in raw.into_iter().enumerate() {
        let mut pkt = packet::parse_packet((i + 1) as u64, &data);
        pkt.timestamp = timestamp;

        *protocols.entry(format!("{}", pkt.protocol)).or_insert(0) += 1;
        total_bytes += pkt.length as u64;

        // Extract IP (strip port).
        let src_ip = pkt.src.rsplit_once(':').map_or(&*pkt.src, |(ip, _)| ip);
        let dst_ip = pkt.dst.rsplit_once(':').map_or(&*pkt.dst, |(ip, _)| ip);
        *talkers.entry(src_ip.to_string()).or_insert(0) += 1;
        *talkers.entry(dst_ip.to_string()).or_insert(0) += 1;

        let conv_key = FlowKey::new(&pkt.src, &pkt.dst);
        let conv = conversations
            .entry(format!("{conv_key}"))
            .or_insert_with(|| (pkt.src.clone(), pkt.dst.clone(), 0, 0));
        conv.2 += 1;
        conv.3 += pkt.length as u64;
    }

    let mut top_talkers: Vec<TalkerEntry> = talkers
        .into_iter()
        .map(|(address, packets)| TalkerEntry { address, packets })
        .collect();
    top_talkers.sort_by_key(|t| Reverse(t.packets));
    top_talkers.truncate(10);

    let mut top_conversations: Vec<ConversationEntry> = conversations
        .into_values()
        .map(|(src, dst, packets, bytes)| ConversationEntry {
            src,
            dst,
            packets,
            bytes,
        })
        .collect();
    top_conversations.sort_by_key(|c| Reverse(c.bytes));
    top_conversations.truncate(10);

    let output = StatsOutput {
        total_packets,
        total_bytes,
        protocols,
        top_talkers,
        top_conversations,
    };

    serde_json::to_writer_pretty(io::stdout().lock(), &output)?;
    println!();
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: stream
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct StreamOutput {
    flow: String,
    packets: usize,
    payload_bytes: usize,
    payload_hex: String,
    payload_ascii: String,
}

/// Follow a TCP stream from a pcap file and output as JSON.
pub fn cmd_stream(file: &str, flow_str: Option<&str>) -> Result<()> {
    let raw = export::read_pcap(Path::new(file))?;
    let mut packets: Vec<CapturedPacket> = Vec::new();

    for (i, (timestamp, data)) in raw.into_iter().enumerate() {
        let mut pkt = packet::parse_packet((i + 1) as u64, &data);
        pkt.timestamp = timestamp;
        packets.push(pkt);
    }

    // Determine the flow to follow.
    let target_flow = if let Some(f) = flow_str {
        // Parse "src-dst" format.
        let parts: Vec<&str> = f.split('-').collect();
        if parts.len() != 2 {
            bail!("flow format should be 'src:port-dst:port' (e.g. '10.0.0.1:443-10.0.0.2:52100')");
        }
        FlowKey::new(parts[0], parts[1])
    } else {
        // Find the flow with the most TCP packets.
        let mut flow_counts: HashMap<FlowKey, u64> = HashMap::new();
        for pkt in &packets {
            if pkt.protocol == Protocol::Tcp {
                *flow_counts
                    .entry(FlowKey::new(&pkt.src, &pkt.dst))
                    .or_insert(0) += 1;
            }
        }
        flow_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(key, _)| key)
            .ok_or_else(|| anyhow::anyhow!("no TCP flows found"))?
    };

    // Collect TCP payload for the target flow.
    let mut payload = Vec::new();
    let mut stream_pkt_count = 0usize;

    for pkt in &packets {
        if pkt.protocol == Protocol::Tcp {
            let pkt_flow = FlowKey::new(&pkt.src, &pkt.dst);
            if pkt_flow == target_flow
                && let Some(tcp_payload) = extract_tcp_payload(&pkt.data)
                && !tcp_payload.is_empty()
            {
                payload.extend_from_slice(tcp_payload);
                stream_pkt_count += 1;
            }
        }
    }

    let hex_str: Vec<String> = payload.iter().map(|b| format!("{b:02x}")).collect();
    let ascii_str: String = payload
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect();

    let output = StreamOutput {
        flow: format!("{target_flow}"),
        packets: stream_pkt_count,
        payload_bytes: payload.len(),
        payload_hex: hex_str.join(" "),
        payload_ascii: ascii_str,
    };

    serde_json::to_writer_pretty(io::stdout().lock(), &output)?;
    println!();
    Ok(())
}

/// Extract TCP payload from a raw Ethernet frame (same logic as app.rs).
fn extract_tcp_payload(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let ip = &data[14..];
    let ip_hdr_len = match ethertype {
        0x0800 => {
            if ip.is_empty() {
                return None;
            }
            ((ip[0] & 0x0F) as usize) * 4
        }
        0x86DD => 40,
        _ => return None,
    };
    if ip.len() < ip_hdr_len + 20 {
        return None;
    }
    let tcp = &ip[ip_hdr_len..];
    let tcp_hdr_len = ((tcp[12] >> 4) as usize) * 4;
    if tcp.len() <= tcp_hdr_len {
        return None;
    }
    Some(&tcp[tcp_hdr_len..])
}

// ---------------------------------------------------------------------------
// Subcommand: decode
// ---------------------------------------------------------------------------

/// Decode a single packet from a pcap file and output as pretty JSON.
pub fn cmd_decode(file: &str, id: u64) -> Result<()> {
    let raw = export::read_pcap(Path::new(file))?;
    #[allow(clippy::cast_possible_truncation)]
    let idx = id as usize;
    if id == 0 || idx > raw.len() {
        bail!("packet ID {id} out of range (1..{})", raw.len());
    }
    let (timestamp, data) = &raw[idx - 1];
    let mut pkt = packet::parse_packet(id, data);
    pkt.timestamp = *timestamp;

    serde_json::to_writer_pretty(io::stdout().lock(), &pkt)?;
    println!();
    Ok(())
}

// ---------------------------------------------------------------------------
// --json flag on root CLI
// ---------------------------------------------------------------------------

/// Dump a pcap file as a JSON array (for `--read --json`).
pub fn cmd_json_read(file: &str) -> Result<()> {
    cmd_read(file, None, 0)
}

/// Live capture with JSON output (for `--json` without `--read`).
pub fn cmd_json_live(
    interface: Option<&str>,
    bpf_filter: Option<&str>,
    count: usize,
) -> Result<()> {
    cmd_capture(interface, bpf_filter, count, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn sample_packet() -> CapturedPacket {
        CapturedPacket {
            id: 1,
            timestamp: SystemTime::UNIX_EPOCH,
            protocol: Protocol::Tcp,
            src: "10.0.0.1:443".into(),
            dst: "10.0.0.2:52100".into(),
            length: 100,
            data: vec![0x00, 0xff, 0x42],
            decoded: vec![packet::DecodedField {
                label: "Src Port".into(),
                value: "443".into(),
            }],
            tcp_flags: 0x02, // SYN
        }
    }

    #[test]
    fn packet_serializes_to_json() {
        let pkt = sample_packet();
        let json = serde_json::to_string(&pkt).unwrap();
        assert!(json.contains("\"protocol\":\"Tcp\""));
        assert!(json.contains("\"src\":\"10.0.0.1:443\""));
        assert!(json.contains("\"data\":\"00 ff 42\""));
        assert!(json.contains("\"tcp_flags\":2"));
    }

    #[test]
    fn display_filter_protocol() {
        let pkt = sample_packet();
        assert!(matches_display_filter(&pkt, "tcp"));
        assert!(!matches_display_filter(&pkt, "udp"));
        assert!(matches_display_filter(&pkt, "!udp"));
        assert!(!matches_display_filter(&pkt, "!tcp"));
    }

    #[test]
    fn display_filter_port() {
        let pkt = sample_packet();
        assert!(matches_display_filter(&pkt, "port:443"));
        assert!(matches_display_filter(&pkt, "port:52100"));
        assert!(!matches_display_filter(&pkt, "port:80"));
    }

    #[test]
    fn display_filter_ip() {
        let pkt = sample_packet();
        assert!(matches_display_filter(&pkt, "ip:10.0.0.1"));
        assert!(matches_display_filter(&pkt, "ip:10.0.0"));
        assert!(!matches_display_filter(&pkt, "ip:192.168"));
    }

    #[test]
    fn display_filter_flags() {
        let pkt = sample_packet();
        assert!(matches_display_filter(&pkt, "syn"));
        assert!(!matches_display_filter(&pkt, "rst"));
        assert!(!matches_display_filter(&pkt, "fin"));
    }

    #[test]
    fn display_filter_combined() {
        let pkt = sample_packet();
        assert!(matches_display_filter(&pkt, "tcp port:443 syn"));
        assert!(!matches_display_filter(&pkt, "tcp port:80"));
        assert!(matches_display_filter(&pkt, "!udp !rst"));
    }

    #[test]
    fn flow_key_display() {
        let key = FlowKey::new("10.0.0.1:443", "10.0.0.2:52100");
        assert_eq!(format!("{key}"), "10.0.0.1:443-10.0.0.2:52100");
    }
}
