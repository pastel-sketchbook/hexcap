use ratatui::prelude::*;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::App;
use crate::expert;
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

/// Render decoded protocol fields between info bar and hex dump.
pub fn draw_decoded_fields(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let title_style = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);
    let label_style = Style::default().fg(theme.accent);

    let lines: Vec<Line> = if let Some(pkt) = app.selected_packet() {
        if pkt.decoded.is_empty() && pkt.expert.is_empty() {
            vec![Line::from(Span::styled(
                "No decoded fields",
                Style::default().fg(theme.muted),
            ))]
        } else {
            let mut lines: Vec<Line> = pkt
                .decoded
                .iter()
                .map(|f| {
                    Line::from(vec![
                        Span::styled(format!("{}: ", f.label), label_style),
                        Span::raw(&f.value),
                    ])
                })
                .collect();
            // Append expert items with severity coloring.
            if !pkt.expert.is_empty() {
                lines.push(Line::from(Span::styled(
                    "── Expert Info ──",
                    Style::default().fg(theme.muted),
                )));
                for item in &pkt.expert {
                    let sev_color = expert::severity_color(item.severity);
                    lines.push(Line::from(vec![
                        Span::styled(
                            format!(" {} ", expert::severity_symbol(item.severity)),
                            Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("[{}] ", item.severity),
                            Style::default().fg(sev_color),
                        ),
                        Span::raw(&item.summary),
                    ]));
                }
            }
            lines
        }
    } else {
        vec![]
    };

    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(" Protocol ")
                .title_style(title_style),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(widget, area);
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

/// Render the TCP stream content (mixed hex dump + ASCII view).
pub fn draw_stream_content(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let title_style = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);

    let size = app.stream_data.len();
    let title = format!(" TCP Stream ({size} bytes) ");

    if app.stream_data.is_empty() {
        let empty = Paragraph::new("No stream data").block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(title)
                .title_style(title_style),
        );
        frame.render_widget(empty, area);
        return;
    }

    // Show as hex dump with the stream data.
    let lines = hex::hex_lines(&app.stream_data, theme);
    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.border))
                .title(title)
                .title_style(title_style),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.stream_scroll, 0));
    frame.render_widget(widget, area);
}
