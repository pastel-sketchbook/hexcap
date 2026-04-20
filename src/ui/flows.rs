use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

use crate::app::App;
use crate::theme::Theme;

use super::helpers::{highlight_style, stripe_style};

/// Column widths for the flows table.
const FLOW_WIDTHS: [Constraint; 5] = [
    Constraint::Length(8),  // Protocol
    Constraint::Min(18),    // Endpoint A
    Constraint::Min(18),    // Endpoint B
    Constraint::Length(8),  // Packets
    Constraint::Length(10), // Bytes
];

/// Format byte count as human-readable string.
#[allow(clippy::cast_precision_loss)]
fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

pub fn draw_flows_table(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let header = Row::new(vec![
        Cell::from("Proto"),
        Cell::from("Endpoint A"),
        Cell::from("Endpoint B"),
        Cell::from("Packets"),
        Cell::from("Bytes"),
    ])
    .style(
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .flows
        .iter()
        .enumerate()
        .map(|(idx, f)| {
            Row::new(vec![
                Cell::from(f.protocol.to_string()),
                Cell::from(f.src.clone()),
                Cell::from(f.dst.clone()),
                Cell::from(f.packet_count.to_string()),
                Cell::from(format_bytes(f.total_bytes)),
            ])
            .style(stripe_style(idx, theme))
        })
        .collect();

    let title = format!(" Flows: {} ", app.flows.len());
    let title_style = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);

    let table = Table::new(rows, FLOW_WIDTHS)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(title)
                .title_style(title_style),
        )
        .row_highlight_style(highlight_style(theme));

    let mut state = TableState::default().with_selected(Some(app.flow_selected));
    frame.render_stateful_widget(table, area, &mut state);
}
