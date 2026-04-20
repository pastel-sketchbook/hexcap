use std::collections::HashMap;

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::app::App;
use crate::packet::Protocol;
use crate::theme::Theme;

/// Protocol hierarchy node: packets, bytes.
struct HierNode {
    packets: usize,
    bytes: u64,
    children: HashMap<&'static str, HierNode>,
}

impl HierNode {
    fn new() -> Self {
        Self {
            packets: 0,
            bytes: 0,
            children: HashMap::new(),
        }
    }

    fn add(&mut self, packets: usize, bytes: u64) {
        self.packets += packets;
        self.bytes += bytes;
    }

    fn child(&mut self, name: &'static str) -> &mut Self {
        self.children.entry(name).or_insert_with(Self::new)
    }
}

/// Build the protocol hierarchy tree from captured packets.
fn build_hierarchy(app: &App) -> HierNode {
    let mut root = HierNode::new();

    for pkt in &app.packets {
        #[allow(clippy::cast_possible_truncation)]
        let bytes = pkt.length as u64;

        root.add(1, bytes);

        // L2: Ethernet (all captures go through libpcap Ethernet).
        let eth = root.child("Ethernet");
        eth.add(1, bytes);

        match pkt.protocol {
            Protocol::Arp => {
                let arp = eth.child("ARP");
                arp.add(1, bytes);
            }
            Protocol::Icmp => {
                let ipv = eth.child("IPv4");
                ipv.add(1, bytes);
                let icmp = ipv.child("ICMP");
                icmp.add(1, bytes);
            }
            Protocol::Tcp | Protocol::Dns => {
                // Determine IPv4 vs IPv6 from address format.
                let l3_name = if is_ipv6_addr(&pkt.src) {
                    "IPv6"
                } else {
                    "IPv4"
                };
                let ipv = eth.child(l3_name);
                ipv.add(1, bytes);

                let tcp = ipv.child("TCP");
                tcp.add(1, bytes);

                // DNS over TCP or application-layer DNS.
                if pkt.protocol == Protocol::Dns {
                    let dns = tcp.child("DNS");
                    dns.add(1, bytes);
                } else {
                    // Check for TLS (decoded fields contain TLS record info).
                    let has_tls = pkt.decoded.iter().any(|f| f.label.contains("TLS"));
                    if has_tls {
                        let tls = tcp.child("TLS");
                        tls.add(1, bytes);
                    }
                }
            }
            Protocol::Udp => {
                let l3_name = if is_ipv6_addr(&pkt.src) {
                    "IPv6"
                } else {
                    "IPv4"
                };
                let ipv = eth.child(l3_name);
                ipv.add(1, bytes);

                let udp = ipv.child("UDP");
                udp.add(1, bytes);

                // DNS over UDP (check port 53).
                let is_dns =
                    extract_port(&pkt.src) == Some(53) || extract_port(&pkt.dst) == Some(53);
                if is_dns {
                    let dns = udp.child("DNS");
                    dns.add(1, bytes);
                }
            }
            Protocol::Other(_) => {
                let l3_name = if is_ipv6_addr(&pkt.src) {
                    "IPv6"
                } else {
                    "IPv4"
                };
                let ipv = eth.child(l3_name);
                ipv.add(1, bytes);
            }
        }
    }

    root
}

/// Flatten the hierarchy tree into indented lines for display.
#[allow(clippy::cast_precision_loss)] // percentages — precision loss acceptable
fn flatten_tree<'a>(
    node: &HierNode,
    name: &'a str,
    depth: usize,
    total_packets: usize,
    total_bytes: u64,
    out: &mut Vec<(usize, &'a str, usize, u64, f64, f64)>,
) {
    let pkt_pct = if total_packets > 0 {
        node.packets as f64 / total_packets as f64 * 100.0
    } else {
        0.0
    };
    let byte_pct = if total_bytes > 0 {
        node.bytes as f64 / total_bytes as f64 * 100.0
    } else {
        0.0
    };
    out.push((depth, name, node.packets, node.bytes, pkt_pct, byte_pct));

    // Sort children by packet count descending.
    let mut children: Vec<_> = node.children.iter().collect();
    children.sort_by_key(|(_, n)| std::cmp::Reverse(n.packets));
    for (child_name, child_node) in children {
        flatten_tree(
            child_node,
            child_name,
            depth + 1,
            total_packets,
            total_bytes,
            out,
        );
    }
}

/// Build endpoint statistics: per-IP packet count and byte total.
fn build_endpoints(app: &App) -> Vec<(String, usize, u64)> {
    let mut map: HashMap<String, (usize, u64)> = HashMap::new();

    for pkt in &app.packets {
        #[allow(clippy::cast_possible_truncation)]
        let bytes = pkt.length as u64;
        for addr in [&pkt.src, &pkt.dst] {
            let ip = strip_port(addr);
            let entry = map.entry(ip).or_insert((0, 0));
            entry.0 += 1;
            entry.1 += bytes;
        }
    }

    let mut endpoints: Vec<_> = map
        .into_iter()
        .map(|(ip, (pkts, bytes))| (ip, pkts, bytes))
        .collect();
    endpoints.sort_by_key(|(_, pkts, _)| std::cmp::Reverse(*pkts));
    endpoints
}

/// Strip port from address string to get bare IP.
fn strip_port(addr: &str) -> String {
    if let Some(rest) = addr.strip_prefix('[') {
        rest.split(']').next().unwrap_or(addr).to_string()
    } else if let Some(idx) = addr.rfind(':') {
        let after = &addr[idx + 1..];
        if after.chars().all(|c| c.is_ascii_digit()) {
            addr[..idx].to_string()
        } else {
            addr.to_string()
        }
    } else {
        addr.to_string()
    }
}

fn is_ipv6_addr(addr: &str) -> bool {
    addr.starts_with('[') || addr.contains("::")
}

fn extract_port(addr: &str) -> Option<u16> {
    if let Some(rest) = addr.strip_prefix('[') {
        // [ipv6]:port
        let after_bracket = rest.split(']').nth(1)?;
        after_bracket.strip_prefix(':')?.parse().ok()
    } else {
        let idx = addr.rfind(':')?;
        addr[idx + 1..].parse().ok()
    }
}

#[allow(clippy::cast_precision_loss)]
fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{bytes} B")
    }
}

/// Render the protocol hierarchy and endpoint stats overlay.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn draw_proto_hierarchy(frame: &mut Frame, app: &App, theme: &Theme) {
    let area = frame.area();

    let hierarchy = build_hierarchy(app);
    let endpoints = build_endpoints(app);

    let total_packets = hierarchy.packets;
    let total_bytes = hierarchy.bytes;

    let mut rows: Vec<(usize, &str, usize, u64, f64, f64)> = Vec::new();
    // Skip root node, start from children.
    let mut children: Vec<_> = hierarchy.children.iter().collect();
    children.sort_by_key(|(_, n)| std::cmp::Reverse(n.packets));
    for (name, node) in children {
        flatten_tree(node, name, 0, total_packets, total_bytes, &mut rows);
    }

    let mut lines: Vec<Line> = Vec::new();
    let bold = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);
    let normal = Style::default().fg(theme.fg);
    let muted = Style::default().fg(theme.muted);

    // ── Protocol Hierarchy ──────────────────────────────────
    lines.push(Line::from(Span::styled("Protocol Hierarchy", bold)));
    lines.push(Line::from(""));

    for (depth, name, pkts, bytes, pkt_pct, _byte_pct) in &rows {
        let indent = "  ".repeat(*depth);
        let bar_len = (*pkt_pct / 5.0).round() as usize;
        let bar: String = "█".repeat(bar_len);
        lines.push(Line::from(vec![
            Span::styled(format!("{indent}{name:<12}"), normal),
            Span::styled(format!("{pkts:>7} "), muted),
            Span::styled(format!("{:>8} ", format_bytes(*bytes)), muted),
            Span::styled(format!("{pkt_pct:5.1}% "), normal),
            Span::styled(bar, Style::default().fg(theme.accent)),
        ]));
    }

    lines.push(Line::from(""));

    // ── Endpoint Statistics ─────────────────────────────────
    lines.push(Line::from(Span::styled("Endpoint Statistics", bold)));
    lines.push(Line::from(""));

    let max_endpoints = 12;
    for (ip, pkts, bytes) in endpoints.iter().take(max_endpoints) {
        lines.push(Line::from(vec![
            Span::styled(format!("  {ip:<36}"), normal),
            Span::styled(format!("{pkts:>7} pkts  "), muted),
            Span::styled(format_bytes(*bytes), muted),
        ]));
    }
    if endpoints.len() > max_endpoints {
        lines.push(Line::from(Span::styled(
            format!("  … and {} more", endpoints.len() - max_endpoints),
            muted,
        )));
    }

    let popup_w = 68u16.min(area.width.saturating_sub(4));
    let popup_h = (lines.len() as u16 + 3).min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup = Rect::new(x, y, popup_w, popup_h);

    frame.render_widget(Clear, popup);

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent))
            .title(" Protocol Hierarchy ")
            .title_style(bold)
            .style(Style::default().bg(theme.panel_bg)),
    );

    frame.render_widget(paragraph, popup);
}
