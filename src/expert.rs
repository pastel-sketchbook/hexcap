//! Expert information system — Wireshark-style anomaly detection.
//!
//! Each packet may carry zero or more expert items with a severity level.
//! The TCP analysis module is the primary producer; other analysers can be
//! added later.

use std::fmt;

use serde::Serialize;

/// Expert severity levels, from lowest to highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Severity {
    /// Informational (e.g. SYN seen, connection established).
    Chat,
    /// Notable (e.g. retransmission, dup ACK).
    Note,
    /// Warning (e.g. zero window, high retransmission rate).
    Warn,
    /// Error (e.g. malformed packet, RST).
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chat => write!(f, "Chat"),
            Self::Note => write!(f, "Note"),
            Self::Warn => write!(f, "Warn"),
            Self::Error => write!(f, "Error"),
        }
    }
}

/// A single expert information entry attached to a packet.
#[derive(Debug, Clone, Serialize)]
pub struct ExpertItem {
    pub severity: Severity,
    pub group: ExpertGroup,
    pub summary: String,
}

/// Expert item grouping (modelled after Wireshark).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[allow(dead_code)]
pub enum ExpertGroup {
    Sequence,
    Protocol,
    Malformed,
    Comment,
}

impl fmt::Display for ExpertGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sequence => write!(f, "Sequence"),
            Self::Protocol => write!(f, "Protocol"),
            Self::Malformed => write!(f, "Malformed"),
            Self::Comment => write!(f, "Comment"),
        }
    }
}

/// Short symbol for the highest severity on a packet (for the list column).
pub fn severity_symbol(severity: Severity) -> &'static str {
    match severity {
        Severity::Chat => "·",
        Severity::Note => "●",
        Severity::Warn => "▲",
        Severity::Error => "✖",
    }
}

/// Color for a severity level (used by UI).
pub fn severity_color(severity: Severity) -> ratatui::style::Color {
    use ratatui::style::Color;
    match severity {
        Severity::Chat => Color::Rgb(100, 160, 255), // blue
        Severity::Note => Color::Rgb(80, 200, 200),  // cyan
        Severity::Warn => Color::Rgb(230, 200, 60),  // yellow
        Severity::Error => Color::Rgb(255, 80, 80),  // red
    }
}
