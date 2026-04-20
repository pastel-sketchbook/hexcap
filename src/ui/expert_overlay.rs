use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::app::App;
use crate::expert;
use crate::theme::Theme;

/// Render the expert information overlay — shows all packets with expert items.
pub fn draw_expert(frame: &mut Frame, app: &App, theme: &Theme) {
    let area = frame.area();

    let popup_w = 80.min(area.width.saturating_sub(4));
    let popup_h = (area.height - 4).min(40);
    let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup = Rect::new(x, y, popup_w, popup_h);

    frame.render_widget(Clear, popup);

    // Collect all expert items from all packets.
    let mut lines: Vec<Line> = Vec::new();
    let mut counts = [0u32; 4]; // Chat, Note, Warn, Error

    for pkt in &app.packets {
        for item in &pkt.expert {
            let idx = match item.severity {
                expert::Severity::Chat => 0,
                expert::Severity::Note => 1,
                expert::Severity::Warn => 2,
                expert::Severity::Error => 3,
            };
            counts[idx] += 1;

            let sev_color = expert::severity_color(item.severity);
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" #{:<6} ", pkt.id),
                    Style::default().fg(theme.muted),
                ),
                Span::styled(
                    format!("{} ", expert::severity_symbol(item.severity)),
                    Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<5} ", item.severity),
                    Style::default().fg(sev_color),
                ),
                Span::styled(
                    format!("{:<10} ", item.group),
                    Style::default().fg(theme.accent),
                ),
                Span::raw(&item.summary),
            ]));
        }
    }

    // Summary header.
    let summary = format!(
        " Chat:{} Note:{} Warn:{} Error:{} — Total:{} ",
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        lines.len()
    );

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No expert information items",
            Style::default().fg(theme.muted),
        )));
    }

    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.accent))
                .title(" Expert Information ")
                .title_style(
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                )
                .title_bottom(Line::from(summary).centered())
                .style(Style::default().bg(theme.panel_bg)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(paragraph, popup);
}
