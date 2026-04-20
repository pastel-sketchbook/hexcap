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

    // Right: GeoIP badge (if loaded) + packet count
    let mut right_spans = Vec::new();
    if app.geoip_enabled {
        right_spans.push(Span::styled(
            "GeoIP",
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
        ));
        right_spans.push(Span::raw("  "));
    }
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
