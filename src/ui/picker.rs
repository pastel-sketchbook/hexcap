use ratatui::prelude::*;
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

use crate::app::App;
use crate::theme::Theme;

/// Render the process picker overlay (centered popup).
pub fn draw_process_picker(frame: &mut Frame, app: &App, theme: &Theme) {
    let Some(picker) = &app.process_picker else {
        return;
    };

    let area = frame.area();
    let popup_width = (area.width * 60 / 100).clamp(40, 70);
    let popup_height = (area.height * 70 / 100).clamp(10, 30);
    let x = (area.width.saturating_sub(popup_width)) / 2;
    let y = (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // search input
            Constraint::Min(3),    // process list
        ])
        .split(popup_area);

    // Search bar.
    let search_line = Line::from(vec![
        Span::styled(
            " / ",
            Style::default()
                .fg(theme.key_fg)
                .bg(theme.key_bg)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!(" {}", picker.query), Style::default().fg(theme.fg)),
        Span::styled("▌", Style::default().fg(theme.accent)),
    ]);
    let search_widget = Paragraph::new(search_line).style(Style::default().bg(theme.panel_bg));
    frame.render_widget(search_widget, chunks[0]);

    // Process list.
    let items: Vec<ListItem> = picker
        .filtered
        .iter()
        .map(|&idx| {
            let p = &picker.processes[idx];
            let port_str = if p.ports.is_empty() {
                String::from("(no ports)")
            } else {
                let mut ports: Vec<u16> = p.ports.iter().copied().collect();
                ports.sort_unstable();
                let display: Vec<String> = ports.iter().take(6).map(ToString::to_string).collect();
                if ports.len() > 6 {
                    format!("{}...", display.join(","))
                } else {
                    display.join(",")
                }
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:>6} ", p.pid), Style::default().fg(theme.muted)),
                Span::styled(
                    format!("{:<20} ", p.name),
                    Style::default().fg(theme.fg).add_modifier(Modifier::BOLD),
                ),
                Span::styled(port_str, Style::default().fg(theme.accent)),
            ]))
        })
        .collect();

    let title = format!(" Processes ({}) ", picker.filtered.len());
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.accent))
                .title(title)
                .title_style(
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
        )
        .highlight_style(
            Style::default()
                .bg(theme.highlight_bg)
                .fg(theme.highlight_fg)
                .add_modifier(Modifier::BOLD),
        );

    let mut state = ListState::default().with_selected(Some(picker.selected));
    frame.render_stateful_widget(list, chunks[1], &mut state);
}
