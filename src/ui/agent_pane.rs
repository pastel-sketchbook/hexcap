use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::App;
use crate::theme::Theme;

/// Render the agent output pane at the bottom of the screen.
pub fn draw_agent_pane(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let output = app
        .agent_output
        .lock()
        .expect("agent output mutex poisoned");
    let total = output.len();

    // Visible lines (area height minus border chrome).
    let visible = area.height.saturating_sub(2) as usize;

    // Compute scroll window.
    let scroll_end = if app.agent_scroll == 0 {
        total // auto-scroll to bottom
    } else {
        total.saturating_sub(app.agent_scroll)
    };
    let scroll_start = scroll_end.saturating_sub(visible);

    let lines: Vec<Line> = output
        .iter()
        .skip(scroll_start)
        .take(visible)
        .map(|s| Line::from(Span::styled(s.as_str(), Style::default().fg(theme.fg))))
        .collect();

    let agent_label = app.agent_name.as_deref().unwrap_or("Agent");
    let title = format!(" {agent_label} Output ({total} lines) ");
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.accent))
        .title(title)
        .title_style(
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )
        .style(Style::default().bg(theme.panel_bg));

    let paragraph = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false });

    frame.render_widget(paragraph, area);
}
