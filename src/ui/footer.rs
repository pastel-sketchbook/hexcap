use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, View};
use crate::theme::Theme;

use super::helpers::{key_badge, muted_span};

/// A key hint: badge text + description.
struct Hint {
    key: &'static str,
    desc: &'static str,
}

impl Hint {
    const fn new(key: &'static str, desc: &'static str) -> Self {
        Self { key, desc }
    }

    /// Rendered width: " key " + " desc" + "│"
    fn width(&self) -> usize {
        self.key.len() + 2 + self.desc.len() + 1 + 1
    }
}

/// Build spans from hints, fitting within `max_width`.
fn build_hints(hints: &[Hint], max_width: u16, theme: &Theme) -> Vec<Span<'static>> {
    let sep = muted_span("│", theme);
    let mut spans = Vec::new();
    let mut used: usize = 0;

    for (i, h) in hints.iter().enumerate() {
        let needed = h.width();
        if used + needed > max_width as usize {
            break;
        }
        if i > 0 {
            spans.push(sep.clone());
            used += 1;
        }
        spans.push(key_badge(h.key, theme));
        spans.push(muted_span(h.desc, theme));
        used += needed;
    }
    spans
}

pub fn draw_footer(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    // Build right side first to know how much space the left side gets.
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
    right_spans.push(key_badge("?", theme));
    right_spans.push(muted_span(" Help ", theme));
    right_spans.push(muted_span("│ ", theme));
    right_spans.push(muted_span(&format!("{theme_name} "), theme));
    right_spans.push(muted_span(&format!("v{version} "), theme));

    let right_width: u16 =
        u16::try_from(right_spans.iter().map(|s| s.content.len()).sum::<usize>() + 1)
            .unwrap_or(u16::MAX);

    let left_budget = area.width.saturating_sub(right_width);

    // Hints ordered by priority (most important first).
    let hints: Vec<Hint> = match app.view {
        View::List => vec![
            Hint::new("q", " Quit"),
            Hint::new("↵", " Detail"),
            Hint::new("j/k", " Nav"),
            Hint::new("␣", " Pause"),
            Hint::new("/", " Search"),
            Hint::new("w", " Export"),
            Hint::new("n", " Flows"),
            Hint::new("p", " Proc"),
            Hint::new("i", " Iface"),
            Hint::new("m", " Mark"),
            Hint::new("D", " DNS"),
            Hint::new("\\", " Filter"),
            Hint::new("t", " Theme"),
        ],
        View::Detail => vec![
            Hint::new("Esc", " Back"),
            Hint::new("j/k", " Scroll"),
            Hint::new("y", " Copy"),
            Hint::new("S", " Stream"),
            Hint::new("w", " Export"),
            Hint::new("t", " Theme"),
        ],
        View::Flows => vec![
            Hint::new("Esc", " Back"),
            Hint::new("j/k", " Nav"),
            Hint::new("↵", " Filter"),
            Hint::new("t", " Theme"),
        ],
        View::Stream => vec![
            Hint::new("Esc", " Back"),
            Hint::new("j/k", " Scroll"),
            Hint::new("y", " Copy"),
            Hint::new("t", " Theme"),
        ],
    };

    let spans = build_hints(&hints, left_budget, theme);
    let left = Paragraph::new(Line::from(spans));

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
