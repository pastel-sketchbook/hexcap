use ratatui::prelude::*;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::App;
use crate::hex;
use crate::theme::Theme;

/// Render the packet info bar (protocol, addresses, length).
pub fn draw_packet_info(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let label_style = Style::default().fg(theme.accent);

    let content = if let Some(pkt) = app.selected_packet() {
        vec![Line::from(vec![
            Span::styled("Packet: ", label_style),
            Span::styled(
                format!("#{}", pkt.id),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled("Proto: ", label_style),
            Span::styled(pkt.protocol.to_string(), Style::default().fg(theme.tag)),
            Span::raw("  "),
            Span::styled("Src: ", label_style),
            Span::raw(&pkt.src),
            Span::raw("  "),
            Span::styled("Dst: ", label_style),
            Span::raw(&pkt.dst),
            Span::raw("  "),
            Span::styled("Len: ", label_style),
            Span::raw(format!("{}", pkt.length)),
        ])]
    } else {
        vec![Line::from(Span::styled(
            "No packet selected",
            Style::default().fg(theme.muted),
        ))]
    };

    let title_style = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);

    let info = Paragraph::new(content).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.border))
            .title(" Details ")
            .title_style(title_style),
    );

    frame.render_widget(info, area);
}

/// Render the hex dump pane.
pub fn draw_hex_dump(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let title_style = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);

    if let Some(pkt) = app.selected_packet() {
        let lines = hex::hex_lines(&pkt.data, theme);
        let hex_widget = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(theme.border))
                    .title(" Hex Dump ")
                    .title_style(title_style),
            )
            .wrap(Wrap { trim: false })
            .scroll((app.hex_scroll, 0));
        frame.render_widget(hex_widget, area);
    } else {
        let empty = Paragraph::new("").block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(" Hex Dump ")
                .title_style(title_style),
        );
        frame.render_widget(empty, area);
    }
}
