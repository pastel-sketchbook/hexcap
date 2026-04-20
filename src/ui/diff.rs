use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::app::App;
use crate::theme::Theme;
use crate::ui::helpers::{DIFF_POPUP_WIDTH, POPUP_CHROME, POPUP_MARGIN, POPUP_MAX_HEIGHT};

/// Render a hex diff overlay comparing two packets byte-by-byte.
pub fn draw_diff(frame: &mut Frame, app: &App, theme: &Theme) {
    let Some((idx_a, idx_b)) = app.diff_pair else {
        return;
    };
    let (Some(pkt_a), Some(pkt_b)) = (app.packets.get(idx_a), app.packets.get(idx_b)) else {
        return;
    };

    let area = frame.area();
    let popup_w = DIFF_POPUP_WIDTH.min(area.width.saturating_sub(POPUP_MARGIN));
    let popup_h = area
        .height
        .saturating_sub(POPUP_MARGIN)
        .min(POPUP_MAX_HEIGHT);
    let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup = Rect::new(x, y, popup_w, popup_h);

    frame.render_widget(Clear, popup);

    let bold = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);
    let normal = Style::default().fg(theme.fg);
    let diff_style = Style::default()
        .fg(Color::Rgb(255, 80, 80))
        .add_modifier(Modifier::BOLD);
    let same_style = Style::default().fg(theme.muted);
    let offset_style = Style::default().fg(theme.hex_offset);

    let max_len = pkt_a.data.len().max(pkt_b.data.len());
    let content_h = popup_h.saturating_sub(POPUP_CHROME) as usize;

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(format!("  #{:<6}", pkt_a.id), bold),
        Span::styled("  vs  ", normal),
        Span::styled(format!("#{}", pkt_b.id), bold),
        Span::styled(
            format!("  ({} vs {} bytes)", pkt_a.data.len(), pkt_b.data.len()),
            Style::default().fg(theme.muted),
        ),
    ]));
    lines.push(Line::from(""));

    // Show hex rows: offset | pkt_a hex | pkt_b hex | marker
    let mut row = 0;
    let mut offset = 0;
    while offset < max_len && row < content_h {
        let mut spans: Vec<Span> = Vec::new();

        // Offset column
        spans.push(Span::styled(format!("{offset:04x}  "), offset_style));

        // Packet A hex (8 bytes per side for compact display)
        let bytes_per_row = 8;
        let mut has_diff = false;

        for i in 0..bytes_per_row {
            let pos = offset + i;
            let byte_a = pkt_a.data.get(pos);
            let byte_b = pkt_b.data.get(pos);
            let differs = byte_a != byte_b;
            if differs {
                has_diff = true;
            }
            let style = if differs { diff_style } else { same_style };
            let text = byte_a.map_or("  ".to_string(), |b| format!("{b:02x}"));
            spans.push(Span::styled(format!("{text} "), style));
        }

        spans.push(Span::styled(" │ ", Style::default().fg(theme.border)));

        // Packet B hex
        for i in 0..bytes_per_row {
            let pos = offset + i;
            let byte_a = pkt_a.data.get(pos);
            let byte_b = pkt_b.data.get(pos);
            let differs = byte_a != byte_b;
            let style = if differs { diff_style } else { same_style };
            let text = byte_b.map_or("  ".to_string(), |b| format!("{b:02x}"));
            spans.push(Span::styled(format!("{text} "), style));
        }

        if has_diff {
            spans.push(Span::styled(" !", diff_style));
        }

        lines.push(Line::from(spans));
        offset += bytes_per_row;
        row += 1;
    }

    if offset < max_len {
        lines.push(Line::from(Span::styled(
            format!("  ... {} more bytes", max_len - offset),
            Style::default().fg(theme.muted),
        )));
    }

    let title = format!(" Packet Diff: #{} vs #{} ", pkt_a.id, pkt_b.id);
    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(theme.accent))
            .title(title)
            .title_style(bold)
            .style(Style::default().bg(theme.panel_bg)),
    );

    frame.render_widget(paragraph, popup);
}
