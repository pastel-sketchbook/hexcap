use ratatui::Frame;
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::theme::Theme;

pub const MIN_TERM_WIDTH: u16 = 60;
pub const MIN_TERM_HEIGHT: u16 = 10;

/// Render a centered size warning if terminal is too small. Returns true if too small.
pub fn render_size_guard(frame: &mut Frame, theme: &Theme) -> bool {
    let area = frame.area();
    if area.width >= MIN_TERM_WIDTH && area.height >= MIN_TERM_HEIGHT {
        return false;
    }
    frame.render_widget(Clear, area);
    let msg = format!(
        "Terminal too small ({}×{}). Need {}×{}.",
        area.width, area.height, MIN_TERM_WIDTH, MIN_TERM_HEIGHT,
    );
    let paragraph = Paragraph::new(msg)
        .style(Style::default().fg(theme.accent))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border)),
        );
    frame.render_widget(paragraph, area);
    true
}

/// Apply row striping.
pub fn stripe_style(index: usize, theme: &Theme) -> Style {
    if index.is_multiple_of(2) {
        Style::default().bg(theme.stripe_bg)
    } else {
        Style::default()
    }
}

/// Style for the highlighted (selected) row.
pub fn highlight_style(theme: &Theme) -> Style {
    Style::default()
        .bg(theme.highlight_bg)
        .fg(theme.highlight_fg)
        .add_modifier(Modifier::BOLD)
}

/// Create a key badge span (e.g. " q " styled with `key_fg`/`key_bg`).
pub fn key_badge<'a>(key: &str, theme: &Theme) -> Span<'a> {
    Span::styled(
        format!(" {key} "),
        Style::default()
            .fg(theme.key_fg)
            .bg(theme.key_bg)
            .add_modifier(Modifier::BOLD),
    )
}

/// Create a muted text span.
pub fn muted_span<'a>(text: &str, theme: &Theme) -> Span<'a> {
    Span::styled(text.to_string(), Style::default().fg(theme.muted))
}
