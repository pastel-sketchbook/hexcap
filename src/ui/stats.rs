use ratatui::prelude::*;
use ratatui::text::Span;

use crate::app::App;
use crate::theme::Theme;

/// Unicode sparkline blocks from lowest to highest.
const SPARK_CHARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Render a one-line stats row showing protocol counts, total bytes, and bandwidth sparkline.
pub fn draw_stats_row(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let counts = app.proto_counts();

    let mut parts: Vec<Span> = vec![
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
            format!(" │ filter: {} ", app.proto_filter),
            Style::default().fg(theme.muted),
        ),
    ];

    // Flow filter indicator.
    if app.flow_filter.is_some() {
        parts.push(Span::styled("│ flow ✓ ", Style::default().fg(theme.accent)));
    }

    // Display filter indicator.
    if !app.display_filter.is_empty() {
        parts.push(Span::styled(
            format!("│ {} ", app.display_filter),
            Style::default().fg(theme.accent),
        ));
    }

    // Capture duration and PPS.
    let elapsed = app.capture_start.elapsed().as_secs();
    let dur_h = elapsed / 3600;
    let dur_m = (elapsed % 3600) / 60;
    let dur_s = elapsed % 60;
    parts.push(Span::styled("│ ", Style::default().fg(theme.border)));
    parts.push(Span::styled(
        format!("{dur_h:02}:{dur_m:02}:{dur_s:02}"),
        Style::default().fg(theme.muted),
    ));
    parts.push(Span::styled(
        format!(" {}/s ", app.pps),
        Style::default().fg(theme.muted),
    ));

    // Bandwidth sparkline.
    if !app.bandwidth_history.is_empty() {
        parts.push(Span::styled("│ ", Style::default().fg(theme.border)));
        let spark = sparkline_string(&app.bandwidth_history);
        parts.push(Span::styled(spark, Style::default().fg(theme.accent)));
        // Show current rate.
        if let Some(&last) = app.bandwidth_history.back() {
            parts.push(Span::styled(
                format!(" {}/s", format_bytes(last)),
                Style::default().fg(theme.muted),
            ));
        }
    }

    let line = Line::from(parts);
    let paragraph =
        ratatui::widgets::Paragraph::new(line).style(Style::default().bg(theme.panel_bg));
    frame.render_widget(paragraph, area);
}

/// Convert a sequence of values into a sparkline string.
fn sparkline_string(values: &std::collections::VecDeque<u64>) -> String {
    let max = values.iter().copied().max().unwrap_or(1).max(1);
    values
        .iter()
        .map(|&v| {
            #[allow(clippy::cast_possible_truncation)]
            let idx = ((v * 7) / max) as usize;
            SPARK_CHARS[idx.min(7)]
        })
        .collect()
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
