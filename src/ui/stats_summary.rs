use std::collections::HashMap;

use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::app::App;
use crate::packet::{FlowKey, Protocol};
use crate::theme::Theme;

/// Render a centered capture statistics summary overlay.
pub fn draw_stats_summary(frame: &mut Frame, app: &App, theme: &Theme) {
    let area = frame.area();

    let popup_w = 56.min(area.width.saturating_sub(4));
    let popup_h = 24u16.min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup = Rect::new(x, y, popup_w, popup_h);

    frame.render_widget(Clear, popup);

    let mut lines: Vec<Line> = Vec::new();
    let bold = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);
    let normal = Style::default().fg(theme.fg);
    let muted = Style::default().fg(theme.muted);

    // ── Protocol distribution ───────────────────────────────
    let mut proto_counts: HashMap<Protocol, (usize, u64)> = HashMap::new();
    let mut ip_bytes: HashMap<String, u64> = HashMap::new();
    let mut flow_counts: HashMap<FlowKey, (usize, u64)> = HashMap::new();

    for p in &app.packets {
        let entry = proto_counts.entry(p.protocol).or_insert((0, 0));
        entry.0 += 1;
        #[allow(clippy::cast_possible_truncation)]
        {
            entry.1 += p.length as u64;
        }

        // Extract IP (strip port).
        for addr in [&p.src, &p.dst] {
            let ip = strip_port(addr);
            #[allow(clippy::cast_possible_truncation)]
            {
                *ip_bytes.entry(ip).or_insert(0) += p.length as u64;
            }
        }

        let flow = FlowKey::new(&p.src, &p.dst);
        let fe = flow_counts.entry(flow).or_insert((0, 0));
        fe.0 += 1;
        #[allow(clippy::cast_possible_truncation)]
        {
            fe.1 += p.length as u64;
        }
    }

    lines.push(Line::from(Span::styled("Protocol Distribution", bold)));
    let mut protos: Vec<_> = proto_counts.into_iter().collect();
    protos.sort_by_key(|e| std::cmp::Reverse(e.1.0));
    for (proto, (count, bytes)) in &protos {
        lines.push(Line::from(vec![
            Span::styled(format!("  {proto:<8}"), normal),
            Span::styled(format!("{count:>6} pkts  "), muted),
            Span::styled(format_bytes(*bytes), muted),
        ]));
    }

    lines.push(Line::from(""));

    // ── Top talkers (by bytes) ──────────────────────────────
    lines.push(Line::from(Span::styled("Top Talkers (by bytes)", bold)));
    let mut talkers: Vec<_> = ip_bytes.into_iter().collect();
    talkers.sort_by_key(|e| std::cmp::Reverse(e.1));
    for (ip, bytes) in talkers.iter().take(5) {
        lines.push(Line::from(vec![
            Span::styled(format!("  {ip:<30}"), normal),
            Span::styled(format_bytes(*bytes), muted),
        ]));
    }

    lines.push(Line::from(""));

    // ── Top conversations (by packets) ──────────────────────
    lines.push(Line::from(Span::styled("Top Conversations", bold)));
    let mut convos: Vec<_> = flow_counts.into_iter().collect();
    convos.sort_by_key(|e| std::cmp::Reverse(e.1.0));
    for (flow, (count, bytes)) in convos.iter().take(5) {
        let label = format!("{} <> {}", flow.0, flow.1);
        let truncated = if label.len() > 36 {
            format!("{}...", &label[..35])
        } else {
            label
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {truncated:<38}"), normal),
            Span::styled(format!("{count:>5}p "), muted),
            Span::styled(format_bytes(*bytes), muted),
        ]));
    }

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent))
            .title(" Capture Statistics ")
            .title_style(bold)
            .style(Style::default().bg(theme.panel_bg)),
    );

    frame.render_widget(paragraph, popup);
}

/// Strip port from address string to get bare IP.
fn strip_port(addr: &str) -> String {
    if let Some(rest) = addr.strip_prefix('[') {
        // [ipv6]:port -> ipv6
        rest.split(']').next().unwrap_or(addr).to_string()
    } else if let Some(idx) = addr.rfind(':') {
        // ip:port -> ip (but only if the part after : is numeric)
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

/// Format bytes into human-readable form.
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
