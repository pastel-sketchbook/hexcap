use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::theme::Theme;

/// Key binding entries: (key, description).
const BINDINGS: &[(&str, &str)] = &[
    ("j/k", "Navigate up/down"),
    ("g/G", "Jump to first/last packet"),
    ("d/u", "Page down/up"),
    ("Enter", "Open packet detail"),
    ("Esc/q", "Back / Quit"),
    ("Space", "Pause/resume capture"),
    ("c", "Clear packets"),
    ("/", "Search (metadata → payload → hex)"),
    ("f", "Cycle protocol filter"),
    ("F", "Cycle follow speed (1/5/10/25)"),
    ("n", "Open flows view"),
    ("N", "Clear flow filter"),
    ("t", "Cycle theme"),
    ("p", "Open process picker"),
    ("P", "Clear process filter"),
    ("i", "Switch interface"),
    ("w", "Export to pcap"),
    ("m", "Toggle bookmark"),
    ("' / \"", "Jump next/prev bookmark"),
    ("D", "Toggle DNS resolution"),
    ("S", "Follow TCP stream (detail)"),
    ("y", "Copy hex dump (detail)"),
    ("Y", "Copy raw hex (detail)"),
    ("Tab", "Select column to resize"),
    ("< / >", "Narrow/widen column"),
    ("I", "Capture statistics summary"),
    ("E", "Expert information overlay"),
    ("H", "Protocol hierarchy & endpoints"),
    ("G", "Flow sequence diagram (flows view)"),
    ("T", "Cycle time format (abs/rel/delta)"),
    ("R", "Toggle time reference on packet"),
    ("x", "Mark packet for diff / show diff"),
    ("a", "Annotate packet"),
    ("\\", "Display filter (tcp, port:443, !arp)"),
    (":", "Go to packet by number"),
    ("?", "Toggle this help"),
];

/// Render a centered help overlay showing all keybindings.
pub fn draw_help(frame: &mut Frame, theme: &Theme) {
    let area = frame.area();

    // Size the popup: width fits longest line, height fits all bindings + border.
    let popup_w = 66.min(area.width.saturating_sub(4));
    #[allow(clippy::cast_possible_truncation)]
    let popup_h = (BINDINGS.len() as u16 + 3).min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup = Rect::new(x, y, popup_w, popup_h);

    frame.render_widget(Clear, popup);

    let lines: Vec<Line> = BINDINGS
        .iter()
        .map(|(key, desc)| {
            Line::from(vec![
                Span::styled(
                    format!(" {key:>9} "),
                    Style::default()
                        .fg(theme.key_fg)
                        .bg(theme.key_bg)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("  {desc}"), Style::default().fg(theme.fg)),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent))
            .title(" Keybindings ")
            .title_style(
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            )
            .style(Style::default().bg(theme.panel_bg)),
    );

    frame.render_widget(paragraph, popup);
}
