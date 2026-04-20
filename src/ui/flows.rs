use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Row, Table, TableState};

use crate::app::App;
use crate::theme::Theme;

use super::helpers::{highlight_style, stripe_style};

/// Column widths for the flows table.
const FLOW_WIDTHS: [Constraint; 9] = [
    Constraint::Length(6),  // Protocol
    Constraint::Min(16),    // Endpoint A
    Constraint::Min(16),    // Endpoint B
    Constraint::Length(6),  // Pkts A→B
    Constraint::Length(8),  // Bytes A→B
    Constraint::Length(6),  // Pkts B→A
    Constraint::Length(8),  // Bytes B→A
    Constraint::Length(10), // Duration
    Constraint::Length(10), // Throughput
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

/// Format duration in seconds.
fn format_duration(secs: f64) -> String {
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{secs:.1}s")
    } else if secs < 3600.0 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let m = (secs / 60.0) as u32;
        let s = secs % 60.0;
        format!("{m}m{s:.0}s")
    } else {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let h = (secs / 3600.0) as u32;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let m = ((secs % 3600.0) / 60.0) as u32;
        format!("{h}h{m}m")
    }
}

/// Format throughput (bytes/sec).
#[allow(clippy::cast_precision_loss)]
fn format_rate(bytes: u64, secs: f64) -> String {
    if secs <= 0.0 {
        return "—".into();
    }
    let bps = bytes as f64 / secs;
    if bps < 1024.0 {
        format!("{:.0} B/s", bps)
    } else if bps < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", bps / 1024.0)
    } else {
        format!("{:.1} MB/s", bps / (1024.0 * 1024.0))
    }
}

pub fn draw_flows_table(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let header = Row::new(vec![
        Cell::from("Proto"),
        Cell::from("Endpoint A"),
        Cell::from("Endpoint B"),
        Cell::from("A→B"),
        Cell::from("A→B"),
        Cell::from("B→A"),
        Cell::from("B→A"),
        Cell::from("Duration"),
        Cell::from("Rate"),
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
            let duration_secs = match (f.first_seen, f.last_seen) {
                (Some(first), Some(last)) => {
                    last.duration_since(first).unwrap_or_default().as_secs_f64()
                }
                _ => 0.0,
            };

            Row::new(vec![
                Cell::from(f.protocol.to_string()),
                Cell::from(f.src.clone()),
                Cell::from(f.dst.clone()),
                Cell::from(f.packets_a_to_b.to_string()),
                Cell::from(format_bytes(f.bytes_a_to_b)),
                Cell::from(f.packets_b_to_a.to_string()),
                Cell::from(format_bytes(f.bytes_b_to_a)),
                Cell::from(format_duration(duration_secs)),
                Cell::from(format_rate(f.total_bytes, duration_secs)),
            ])
            .style(stripe_style(idx, theme))
        })
        .collect();

    let total_pkts: u64 = app.flows.iter().map(|f| f.packet_count).sum();
    let title = format!(" Conversations: {} ({total_pkts} pkts) ", app.flows.len());
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
