use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::App;
use crate::theme::Theme;

/// Render the agent output pane at the bottom of the screen.
///
/// Agent output is joined into a single markdown string and rendered via
/// `tui_markdown` so headings, bold, code blocks, lists, etc. display nicely.
pub fn draw_agent_pane(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let output = app
        .agent_output
        .lock()
        .expect("agent output mutex poisoned");
    let total = output.len();

    // Join all output lines into a single markdown document.
    let md_source: String = output.iter().fold(String::new(), |mut acc, line| {
        acc.push_str(line);
        acc.push('\n');
        acc
    });
    drop(output);

    // Parse markdown into ratatui Text.
    let text = tui_markdown::from_str(&md_source);
    let line_count = text.lines.len();

    // Visible lines (area height minus border chrome).
    let visible = area.height.saturating_sub(2) as usize;

    // Compute scroll offset (from the bottom).
    let scroll_offset = if app.agent_scroll == 0 {
        line_count.saturating_sub(visible) // auto-scroll to bottom
    } else {
        line_count
            .saturating_sub(visible)
            .saturating_sub(app.agent_scroll)
    };

    let agent_label = app.agent_name.as_deref().unwrap_or("Agent");
    let title = format!(" {agent_label} ({total} lines) ");
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

    let paragraph = Paragraph::new(text)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((
            #[allow(clippy::cast_possible_truncation)]
            {
                scroll_offset as u16
            },
            0,
        ));

    frame.render_widget(paragraph, area);
}
