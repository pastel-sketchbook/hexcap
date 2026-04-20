use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, View};
use crate::theme::Theme;

use super::helpers::{key_badge, muted_span};

pub fn draw_footer(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let sep = muted_span("│", theme);

    let spans = match app.view {
        View::List => vec![
            key_badge("q", theme),
            muted_span(" Quit ", theme),
            sep.clone(),
            key_badge("j/k", theme),
            muted_span(" Nav ", theme),
            sep.clone(),
            key_badge("Enter", theme),
            muted_span(" Detail ", theme),
            sep.clone(),
            key_badge("Space", theme),
            muted_span(" Pause ", theme),
            sep.clone(),
            key_badge("c", theme),
            muted_span(" Clear ", theme),
            sep.clone(),
            key_badge("p", theme),
            muted_span(" Process ", theme),
            sep.clone(),
            key_badge("w", theme),
            muted_span(" Export ", theme),
            sep.clone(),
            key_badge("n", theme),
            muted_span(" Flows ", theme),
            sep.clone(),
            key_badge("t", theme),
            muted_span(" Theme ", theme),
        ],
        View::Detail => vec![
            key_badge("q/Esc", theme),
            muted_span(" Back ", theme),
            sep.clone(),
            key_badge("j/k", theme),
            muted_span(" Scroll ", theme),
            sep.clone(),
            key_badge("y", theme),
            muted_span(" Copy ", theme),
            sep.clone(),
            key_badge("w", theme),
            muted_span(" Export ", theme),
            sep.clone(),
            key_badge("t", theme),
            muted_span(" Theme ", theme),
        ],
        View::Flows => vec![
            key_badge("q/Esc", theme),
            muted_span(" Back ", theme),
            sep.clone(),
            key_badge("j/k", theme),
            muted_span(" Nav ", theme),
            sep.clone(),
            key_badge("Enter", theme),
            muted_span(" Filter ", theme),
            sep.clone(),
            key_badge("t", theme),
            muted_span(" Theme ", theme),
        ],
    };

    let left = Paragraph::new(Line::from(spans));

    let theme_name = app.theme().name;
    let version = env!("CARGO_PKG_VERSION");
    let mut right_spans = vec![];
    if let Some((ref msg, _)) = app.status_message {
        right_spans.push(Span::styled(
            format!("{msg} "),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ));
        right_spans.push(muted_span("│ ", theme));
    }
    if let Some(ref pf) = app.process_filter {
        right_spans.push(muted_span(&format!("{} ", pf.name), theme));
        right_spans.push(muted_span("│ ", theme));
    }
    right_spans.push(muted_span(&format!("{theme_name} "), theme));
    right_spans.push(muted_span(&format!("v{version} "), theme));

    let right_width: u16 =
        u16::try_from(right_spans.iter().map(|s| s.content.len()).sum::<usize>() + 1)
            .unwrap_or(u16::MAX);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(right_width)])
        .split(area);

    frame.render_widget(left, cols[0]);
    frame.render_widget(
        Paragraph::new(Line::from(right_spans)).alignment(Alignment::Right),
        cols[1],
    );
}
