use std::time::UNIX_EPOCH;

use ratatui::prelude::*;
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

use crate::app::App;
use crate::packet::{CapturedPacket, Protocol};
use crate::theme::Theme;

use super::helpers::{highlight_style, stripe_style};

/// Column widths for the packet table.
const TABLE_WIDTHS: [Constraint; 6] = [
    Constraint::Length(7),
    Constraint::Length(12),
    Constraint::Length(8),
    Constraint::Min(18),
    Constraint::Min(18),
    Constraint::Length(6),
];

/// Build the table header row.
fn table_header(theme: &Theme) -> Row<'static> {
    Row::new(vec![
        Cell::from("#"),
        Cell::from("Time"),
        Cell::from("Proto"),
        Cell::from("Source"),
        Cell::from("Destination"),
        Cell::from("Len"),
    ])
    .style(
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    )
}

/// Protocol tag color.
fn proto_color(proto: Protocol, theme: &Theme) -> Color {
    match proto {
        Protocol::Tcp => theme.accent,
        Protocol::Udp => theme.tag,
        Protocol::Icmp => theme.highlight_fg,
        Protocol::Arp | Protocol::Other(_) => theme.muted,
        Protocol::Dns => theme.hex_ascii,
    }
}

/// Render the packet list table.
pub fn draw_packet_table(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let header = table_header(theme);

    let rows: Vec<Row> = app
        .packets
        .iter()
        .enumerate()
        .map(|(idx, p)| {
            let color = proto_color(p.protocol, theme);
            Row::new(vec![
                Cell::from(format!("{}", p.id)),
                Cell::from(format_time(p)),
                Cell::from(p.protocol.to_string()).style(Style::default().fg(color)),
                Cell::from(p.src.clone()),
                Cell::from(p.dst.clone()),
                Cell::from(format!("{}", p.length)),
            ])
            .style(stripe_style(idx, theme))
        })
        .collect();

    let pause_label = if app.paused { " ⏸" } else { "" };
    let title = format!(" Packets: {}{pause_label} ", app.packets.len());

    let title_style = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);

    let table = Table::new(rows, TABLE_WIDTHS)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(title)
                .title_style(title_style),
        )
        .row_highlight_style(highlight_style(theme));

    let mut state = TableState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(table, area, &mut state);
}

/// Render the search input bar.
pub fn draw_search_bar(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let text = Line::from(vec![
        Span::styled(
            " / ",
            Style::default()
                .fg(theme.key_fg)
                .bg(theme.key_bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {}", app.search_query),
            Style::default().fg(theme.fg),
        ),
        Span::styled("▌", Style::default().fg(theme.accent)),
    ]);
    let paragraph =
        ratatui::widgets::Paragraph::new(text).style(Style::default().bg(theme.panel_bg));
    frame.render_widget(paragraph, area);
}

fn format_time(p: &CapturedPacket) -> String {
    let secs = p
        .timestamp
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    let s = secs % 86400.0;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let h = (s / 3600.0) as u32;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let m = ((s % 3600.0) / 60.0) as u32;
    let sec = s % 60.0;
    format!("{h:02}:{m:02}:{sec:06.3}")
}
