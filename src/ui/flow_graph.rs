use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::app::App;
use crate::packet::FlowKey;
use crate::theme::Theme;

/// Render a sequence diagram overlay for the currently selected flow.
#[allow(clippy::cast_possible_truncation)]
pub fn draw_flow_graph(frame: &mut Frame, app: &App, theme: &Theme) {
    let area = frame.area();

    let flow = match app.flows.get(app.flow_selected) {
        Some(f) => f,
        None => return,
    };

    let flow_key = &flow.key;

    // Collect packets belonging to this flow.
    let packets: Vec<_> = app
        .packets
        .iter()
        .filter(|p| FlowKey::new(&p.src, &p.dst) == *flow_key)
        .collect();

    if packets.is_empty() {
        return;
    }

    // The two endpoints (use FlowInfo src/dst for consistent labeling).
    let left = &flow.src;
    let right = &flow.dst;

    // Truncate endpoint labels.
    let max_label = 22;
    let left_label = truncate(left, max_label);
    let right_label = truncate(right, max_label);

    let mut lines: Vec<Line> = Vec::new();
    let bold = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);
    let normal = Style::default().fg(theme.fg);
    let muted = Style::default().fg(theme.muted);

    // Column header with endpoint names.
    let col_width = 24;
    lines.push(Line::from(vec![
        Span::styled(format!("{left_label:>col_width$}"), bold),
        Span::styled("          ", normal),
        Span::styled(format!("{right_label:<col_width$}"), bold),
    ]));

    // Vertical lines header.
    lines.push(Line::from(vec![
        Span::styled(format!("{:>col_width$}", "│"), muted),
        Span::styled("          ", normal),
        Span::styled(format!("{:<col_width$}", "│"), muted),
    ]));

    // Max visible packet rows.
    let max_rows = area.height.saturating_sub(8) as usize;
    let visible = if packets.len() > max_rows {
        &packets[..max_rows]
    } else {
        &packets
    };

    for pkt in visible {
        let is_left_to_right = pkt.src == *left
            || (pkt.src != *right && strip_port(&pkt.src) == strip_port(left));

        // Build the info label: protocol + length + optional flags.
        let info = build_info_label(pkt);

        let arrow_width = 8;
        let arrow_line = if is_left_to_right {
            let arrow = format!("──{info}──>");
            let padded = format!("{arrow:^arrow_width$}");
            Line::from(vec![
                Span::styled(format!("{:>col_width$}", "│"), muted),
                Span::styled(padded, Style::default().fg(theme.accent)),
                Span::styled(format!("{:<col_width$}", "│"), muted),
            ])
        } else {
            let arrow = format!("<──{info}──");
            let padded = format!("{arrow:^arrow_width$}");
            Line::from(vec![
                Span::styled(format!("{:>col_width$}", "│"), muted),
                Span::styled(padded, Style::default().fg(theme.tag)),
                Span::styled(format!("{:<col_width$}", "│"), muted),
            ])
        };
        lines.push(arrow_line);
    }

    if packets.len() > max_rows {
        lines.push(Line::from(Span::styled(
            format!("  … {} more packets", packets.len() - max_rows),
            muted,
        )));
    }

    let popup_w = 68u16.min(area.width.saturating_sub(4));
    let popup_h = (lines.len() as u16 + 3).min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup = Rect::new(x, y, popup_w, popup_h);

    frame.render_widget(Clear, popup);

    let title = format!(" Flow: {} ↔ {} ", left_label, right_label);
    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent))
            .title(title)
            .title_style(bold)
            .style(Style::default().bg(theme.panel_bg)),
    );

    frame.render_widget(paragraph, popup);
}

fn build_info_label(pkt: &crate::packet::CapturedPacket) -> String {
    let proto = format!("{}", pkt.protocol);
    let flags = tcp_flag_str(pkt.tcp_flags);
    if flags.is_empty() {
        format!("{proto} {}", pkt.length)
    } else {
        format!("{proto} [{flags}] {}", pkt.length)
    }
}

fn tcp_flag_str(flags: u8) -> String {
    let mut parts = Vec::new();
    if flags & 0x02 != 0 {
        parts.push("SYN");
    }
    if flags & 0x10 != 0 {
        parts.push("ACK");
    }
    if flags & 0x08 != 0 {
        parts.push("PSH");
    }
    if flags & 0x01 != 0 {
        parts.push("FIN");
    }
    if flags & 0x04 != 0 {
        parts.push("RST");
    }
    parts.join(",")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max - 1])
    }
}

fn strip_port(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        rest.split(']').next().unwrap_or(addr)
    } else if let Some(idx) = addr.rfind(':') {
        let after = &addr[idx + 1..];
        if after.chars().all(|c| c.is_ascii_digit()) {
            &addr[..idx]
        } else {
            addr
        }
    } else {
        addr
    }
}
