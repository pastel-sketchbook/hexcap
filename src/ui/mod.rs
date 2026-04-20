mod detail;
mod footer;
mod header;
pub mod helpers;
mod list;
mod picker;
mod stats;

use ratatui::prelude::*;
use ratatui::widgets::{Block, Clear};

use crate::app::{App, InputMode, View};

use helpers::render_size_guard;

/// Render the entire TUI into the given frame.
pub fn render(frame: &mut Frame, app: &App) {
    let theme = app.theme();

    if render_size_guard(frame, theme) {
        return;
    }

    let area = frame.area();

    // Paint background.
    frame.render_widget(Clear, area);
    frame.render_widget(
        Block::default().style(Style::default().bg(theme.bg).fg(theme.fg)),
        area,
    );

    match app.view {
        View::List => draw_list_layout(frame, app),
        View::Detail => draw_detail_layout(frame, app),
    }

    // Overlay: process picker popup.
    if app.process_picker.is_some() {
        picker::draw_process_picker(frame, app, theme);
    }
}

/// List layout: header | stats | table | search bar? | footer.
fn draw_list_layout(frame: &mut Frame, app: &App) {
    let theme = app.theme();
    let area = frame.area();

    let search_height = u16::from(app.input_mode == InputMode::Search);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),             // header
            Constraint::Length(1),             // stats row
            Constraint::Min(5),                // packet table (flexible)
            Constraint::Length(search_height), // search bar (conditional)
            Constraint::Length(1),             // footer
        ])
        .split(area);

    header::draw_header(frame, app, theme, chunks[0]);
    stats::draw_stats_row(frame, app, theme, chunks[1]);
    list::draw_packet_table(frame, app, theme, chunks[2]);
    if app.input_mode == InputMode::Search {
        list::draw_search_bar(frame, app, theme, chunks[3]);
    }
    footer::draw_footer(frame, app, theme, chunks[4]);
}

/// Detail layout: header | packet info | hex dump | footer.
fn draw_detail_layout(frame: &mut Frame, app: &App) {
    let theme = app.theme();
    let area = frame.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(3), // packet info
            Constraint::Min(5),    // hex dump (flexible)
            Constraint::Length(1), // footer
        ])
        .split(area);

    header::draw_header(frame, app, theme, chunks[0]);
    detail::draw_packet_info(frame, app, theme, chunks[1]);
    detail::draw_hex_dump(frame, app, theme, chunks[2]);
    footer::draw_footer(frame, app, theme, chunks[3]);
}
