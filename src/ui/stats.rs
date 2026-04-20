use ratatui::prelude::*;
use ratatui::text::Span;

use crate::app::App;
use crate::theme::Theme;

/// Render a one-line stats row showing protocol counts and total bytes.
pub fn draw_stats_row(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let counts = app.proto_counts();

    let parts: Vec<Span> = vec![
        Span::styled(
            " TCP:",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("{} ", counts.tcp), Style::default().fg(theme.fg)),
        Span::styled(
            "UDP:",
            Style::default().fg(theme.tag).add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("{} ", counts.udp), Style::default().fg(theme.fg)),
        Span::styled(
            "ICMP:",
            Style::default()
                .fg(theme.highlight_fg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("{} ", counts.icmp), Style::default().fg(theme.fg)),
        Span::styled(
            "DNS:",
            Style::default()
                .fg(theme.hex_ascii)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("{} ", counts.dns), Style::default().fg(theme.fg)),
        Span::styled(
            "ARP:",
            Style::default()
                .fg(theme.muted)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("{} ", counts.arp), Style::default().fg(theme.fg)),
        Span::styled("│ ", Style::default().fg(theme.border)),
        Span::styled(
            format_bytes(app.total_bytes),
            Style::default().fg(theme.muted),
        ),
        Span::styled(
            format!(" │ filter: {}", app.proto_filter),
            Style::default().fg(theme.muted),
        ),
    ];

    let line = Line::from(parts);
    let paragraph =
        ratatui::widgets::Paragraph::new(line).style(Style::default().bg(theme.panel_bg));
    frame.render_widget(paragraph, area);
}

#[allow(clippy::cast_precision_loss)] // Display-only formatting; precision loss acceptable.
fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
