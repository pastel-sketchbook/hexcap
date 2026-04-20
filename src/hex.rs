use ratatui::prelude::*;
use ratatui::text::{Line, Span};

use crate::theme::Theme;

const BYTES_PER_LINE: usize = 16;

/// Render raw bytes into hexyl-style `Line`s for ratatui, colored by theme.
///
/// Each line: `OFFSET │ HH HH HH HH  HH HH HH HH │ HH HH HH HH  HH HH HH HH │ ASCII...`
pub fn hex_lines(data: &[u8], theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = Vec::new();

    for (i, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        let offset = i * BYTES_PER_LINE;
        let mut spans = Vec::new();

        // Offset column
        spans.push(Span::styled(
            format!("{offset:08x}"),
            Style::default().fg(theme.hex_offset),
        ));
        spans.push(Span::raw(" │ "));

        // Hex bytes — two groups of 8
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                spans.push(Span::raw(" "));
            }
            let color = byte_color(*byte, theme);
            spans.push(Span::styled(
                format!("{byte:02x}"),
                Style::default().fg(color),
            ));
            if j < BYTES_PER_LINE - 1 {
                spans.push(Span::raw(" "));
            }
        }

        // Pad if chunk is shorter than BYTES_PER_LINE
        let missing = BYTES_PER_LINE - chunk.len();
        for m in 0..missing {
            if chunk.len() + m == 8 {
                spans.push(Span::raw(" "));
            }
            spans.push(Span::raw("   "));
        }

        spans.push(Span::raw(" │ "));

        // ASCII column
        for byte in chunk {
            let ch = if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '·'
            };
            let color = byte_color(*byte, theme);
            spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
        }

        lines.push(Line::from(spans));
    }

    lines
}

/// Colour bytes by category using theme palette.
fn byte_color(b: u8, theme: &Theme) -> Color {
    match b {
        0x00 => theme.hex_null,
        b if b.is_ascii_graphic() => theme.hex_ascii,
        b if b.is_ascii_whitespace() => theme.hex_space,
        0xFF => theme.hex_high,
        _ => theme.hex_other,
    }
}
