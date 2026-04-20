use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Padding, Paragraph};

use crate::app::App;
use crate::theme::Theme;

const PASTEL_PALETTE: [Color; 5] = [
    Color::Rgb(255, 154, 162),
    Color::Rgb(255, 218, 193),
    Color::Rgb(226, 240, 203),
    Color::Rgb(163, 226, 233),
    Color::Rgb(199, 178, 232),
];

fn title_spans(theme: &Theme) -> Vec<Span<'static>> {
    let title = "HEXCAP";
    let mut spans = Vec::with_capacity(title.len() + 1);
    for (i, ch) in title.chars().enumerate() {
        spans.push(Span::styled(
            String::from(ch),
            Style::default()
                .fg(PASTEL_PALETTE[i % PASTEL_PALETTE.len()])
                .add_modifier(Modifier::BOLD),
        ));
    }
    spans.push(Span::styled(
        " TERMINAL",
        Style::default().fg(theme.fg).add_modifier(Modifier::BOLD),
    ));
    spans
}

fn status_badge(paused: bool, theme: &Theme) -> Span<'static> {
    if paused {
        Span::styled(
            " ⏸ PAUSED ",
            Style::default()
                .fg(theme.highlight_fg)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " ● LIVE ",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )
    }
}

pub fn draw_header(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let border_color = if app.paused {
        theme.highlight_fg
    } else {
        theme.accent
    };

    let header_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .padding(Padding::horizontal(1));
    let inner = header_block.inner(area);
    frame.render_widget(header_block, area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(inner);

    // Left: title + status badge
    let mut left_spans = title_spans(theme);
    left_spans.push(Span::raw(" "));
    left_spans.push(status_badge(app.paused, theme));
    frame.render_widget(Paragraph::new(Line::from(left_spans)), cols[0]);

    // Right: status badges + packet count
    let mut right_spans: Vec<Span> = Vec::new();
    let badge_style = |fg| Style::default().fg(fg).add_modifier(Modifier::BOLD);
    let sep = || Span::raw("  ");

    // Time format badge.
    {
        use crate::app::TimeFormat;
        let label = match app.time_format {
            TimeFormat::Absolute => "Abs",
            TimeFormat::Relative => "Rel",
            TimeFormat::Delta => "Δt",
        };
        right_spans.push(Span::styled(label, badge_style(theme.muted)));
        right_spans.push(sep());
    }

    // Interface name.
    if !app.interface_name.is_empty() {
        right_spans.push(Span::styled(
            app.interface_name.clone(),
            badge_style(theme.fg),
        ));
        right_spans.push(sep());
    }

    // DNS badge.
    if app.dns_enabled {
        right_spans.push(Span::styled("DNS", badge_style(theme.tag)));
        right_spans.push(sep());
    }

    // Active display filter.
    if !app.display_filter.is_empty() {
        right_spans.push(Span::styled("\\", badge_style(theme.highlight_fg)));
        right_spans.push(sep());
    }

    // Process filter.
    if let Some(ref pf) = app.process_filter {
        let label = format!("⚙ {}", pf.name);
        right_spans.push(Span::styled(label, badge_style(theme.hex_ascii)));
        right_spans.push(sep());
    }

    // Bookmark count (only when bookmarks exist).
    if !app.bookmarks.is_empty() {
        right_spans.push(Span::styled(
            format!("★{}", app.bookmarks.len()),
            badge_style(theme.highlight_fg),
        ));
        right_spans.push(sep());
    }

    // GeoIP badge.
    if app.geoip_enabled {
        right_spans.push(Span::styled("GeoIP", badge_style(theme.accent)));
        right_spans.push(sep());
    }

    // Packet count.
    right_spans.push(Span::styled(
        format!("{}", app.packets.len()),
        Style::default().add_modifier(Modifier::BOLD),
    ));
    right_spans.push(Span::styled(" pkts", Style::default().fg(theme.muted)));
    frame.render_widget(
        Paragraph::new(Line::from(right_spans)).alignment(Alignment::Right),
        cols[1],
    );
}
