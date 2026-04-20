use ratatui::Frame;
use ratatui::style::{Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::theme::Theme;

pub const MIN_TERM_WIDTH: u16 = 60;
pub const MIN_TERM_HEIGHT: u16 = 10;
/// Default popup overlay width (used by help, pickers, etc.).
pub const POPUP_WIDTH: u16 = 66;
/// Maximum popup height relative to terminal.
pub const POPUP_MAX_HEIGHT: u16 = 40;
/// Popup margin from terminal edges.
pub const POPUP_MARGIN: u16 = 4;
/// Vertical padding inside popups (borders + title).
pub const POPUP_CHROME: u16 = 3;

// Overlay-specific widths.
/// Expert information overlay width.
pub const EXPERT_POPUP_WIDTH: u16 = 80;
/// Packet diff overlay width.
pub const DIFF_POPUP_WIDTH: u16 = 72;
/// Capture statistics summary overlay width.
pub const STATS_POPUP_WIDTH: u16 = 56;
/// Capture statistics summary overlay height.
pub const STATS_POPUP_HEIGHT: u16 = 24;

// Flow graph layout constants.
/// Width of each endpoint label column in the flow sequence diagram.
pub const FLOW_COL_WIDTH: usize = 22;
/// Width of the center arrow column in the flow sequence diagram.
pub const FLOW_CENTER_WIDTH: usize = 26;
/// Maximum endpoint label length before truncation.
pub const FLOW_MAX_LABEL: usize = 22;
/// Flow graph popup width.
pub const FLOW_POPUP_WIDTH: u16 = 74;

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

/// Detect if we're running inside Ghostty.
///
/// Checks `GHOSTTY_RESOURCES_DIR` first (fast path), then `TERM_PROGRAM`,
/// then falls back to checking if the Ghostty process is running (macOS).
/// The fallback is needed because `sudo` strips environment variables.
pub fn is_ghostty() -> bool {
    if std::env::var("GHOSTTY_RESOURCES_DIR").is_ok() {
        return true;
    }
    if std::env::var("TERM_PROGRAM").is_ok_and(|v| v.eq_ignore_ascii_case("ghostty")) {
        return true;
    }
    std::process::Command::new("pgrep")
        .args(["-xi", "ghostty"])
        .output()
        .is_ok_and(|o| o.status.success())
}
