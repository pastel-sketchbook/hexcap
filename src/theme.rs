use ratatui::style::Color;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct Theme {
    pub name: &'static str,
    pub bg: Color,
    pub fg: Color,
    pub accent: Color,
    pub muted: Color,
    pub border: Color,
    pub highlight_bg: Color,
    pub highlight_fg: Color,
    pub stripe_bg: Color,
    pub key_bg: Color,
    pub key_fg: Color,
    pub tag: Color,
    pub panel_bg: Color,
    // Hex dump colors
    pub hex_null: Color,
    pub hex_ascii: Color,
    pub hex_space: Color,
    pub hex_high: Color,
    pub hex_other: Color,
    pub hex_offset: Color,
}

pub const THEMES: &[Theme] = &[
    // ── Dark themes ─────────────────────────────────────────────────
    // 0: Default
    Theme {
        name: "Default",
        bg: Color::Reset,
        fg: Color::White,
        accent: Color::Rgb(0, 217, 255),
        muted: Color::DarkGray,
        border: Color::DarkGray,
        highlight_bg: Color::Rgb(40, 40, 60),
        highlight_fg: Color::Rgb(255, 220, 100),
        stripe_bg: Color::Rgb(28, 28, 34),
        key_bg: Color::DarkGray,
        key_fg: Color::Black,
        tag: Color::Rgb(180, 140, 255),
        panel_bg: Color::Rgb(24, 24, 30),
        hex_null: Color::DarkGray,
        hex_ascii: Color::Rgb(0, 200, 80),
        hex_space: Color::Rgb(0, 180, 200),
        hex_high: Color::Rgb(180, 140, 255),
        hex_other: Color::Rgb(255, 200, 60),
        hex_offset: Color::DarkGray,
    },
    // 1: Gruvbox
    Theme {
        name: "Gruvbox",
        bg: Color::Rgb(29, 32, 33),
        fg: Color::Rgb(235, 219, 178),
        accent: Color::Rgb(215, 153, 33),
        muted: Color::Rgb(146, 131, 116),
        border: Color::Rgb(62, 57, 54),
        highlight_bg: Color::Rgb(50, 48, 47),
        highlight_fg: Color::Rgb(250, 189, 47),
        stripe_bg: Color::Rgb(40, 40, 40),
        key_bg: Color::Rgb(80, 73, 69),
        key_fg: Color::Rgb(235, 219, 178),
        tag: Color::Rgb(131, 165, 152),
        panel_bg: Color::Rgb(37, 36, 36),
        hex_null: Color::Rgb(146, 131, 116),
        hex_ascii: Color::Rgb(184, 187, 38),
        hex_space: Color::Rgb(131, 165, 152),
        hex_high: Color::Rgb(211, 134, 155),
        hex_other: Color::Rgb(250, 189, 47),
        hex_offset: Color::Rgb(146, 131, 116),
    },
    // 2: Solarized
    Theme {
        name: "Solarized",
        bg: Color::Rgb(0, 43, 54),
        fg: Color::Rgb(253, 246, 227),
        accent: Color::Rgb(42, 161, 152),
        muted: Color::Rgb(131, 148, 150),
        border: Color::Rgb(16, 58, 68),
        highlight_bg: Color::Rgb(7, 54, 66),
        highlight_fg: Color::Rgb(253, 246, 227),
        stripe_bg: Color::Rgb(3, 48, 58),
        key_bg: Color::Rgb(88, 110, 117),
        key_fg: Color::Rgb(253, 246, 227),
        tag: Color::Rgb(108, 113, 196),
        panel_bg: Color::Rgb(7, 54, 66),
        hex_null: Color::Rgb(131, 148, 150),
        hex_ascii: Color::Rgb(133, 153, 0),
        hex_space: Color::Rgb(42, 161, 152),
        hex_high: Color::Rgb(108, 113, 196),
        hex_other: Color::Rgb(181, 137, 0),
        hex_offset: Color::Rgb(131, 148, 150),
    },
    // 3: Ayu
    Theme {
        name: "Ayu",
        bg: Color::Rgb(10, 14, 20),
        fg: Color::Rgb(191, 191, 191),
        accent: Color::Rgb(255, 153, 64),
        muted: Color::Rgb(92, 103, 115),
        border: Color::Rgb(40, 44, 52),
        highlight_bg: Color::Rgb(20, 24, 32),
        highlight_fg: Color::Rgb(255, 180, 84),
        stripe_bg: Color::Rgb(15, 19, 26),
        key_bg: Color::Rgb(60, 66, 76),
        key_fg: Color::Rgb(191, 191, 191),
        tag: Color::Rgb(210, 154, 230),
        panel_bg: Color::Rgb(18, 22, 30),
        hex_null: Color::Rgb(92, 103, 115),
        hex_ascii: Color::Rgb(170, 217, 76),
        hex_space: Color::Rgb(95, 196, 220),
        hex_high: Color::Rgb(210, 154, 230),
        hex_other: Color::Rgb(255, 180, 84),
        hex_offset: Color::Rgb(92, 103, 115),
    },
    // 4: Flexoki
    Theme {
        name: "Flexoki",
        bg: Color::Rgb(16, 15, 15),
        fg: Color::Rgb(206, 205, 195),
        accent: Color::Rgb(36, 131, 123),
        muted: Color::Rgb(135, 133, 128),
        border: Color::Rgb(40, 39, 38),
        highlight_bg: Color::Rgb(28, 27, 26),
        highlight_fg: Color::Rgb(208, 162, 21),
        stripe_bg: Color::Rgb(22, 21, 20),
        key_bg: Color::Rgb(52, 51, 49),
        key_fg: Color::Rgb(206, 205, 195),
        tag: Color::Rgb(142, 139, 206),
        panel_bg: Color::Rgb(24, 23, 22),
        hex_null: Color::Rgb(135, 133, 128),
        hex_ascii: Color::Rgb(102, 156, 72),
        hex_space: Color::Rgb(36, 131, 123),
        hex_high: Color::Rgb(142, 139, 206),
        hex_other: Color::Rgb(208, 162, 21),
        hex_offset: Color::Rgb(135, 133, 128),
    },
    // 5: Zoegi
    Theme {
        name: "Zoegi",
        bg: Color::Rgb(20, 20, 20),
        fg: Color::Rgb(204, 204, 204),
        accent: Color::Rgb(64, 128, 104),
        muted: Color::Rgb(89, 89, 89),
        border: Color::Rgb(48, 48, 48),
        highlight_bg: Color::Rgb(34, 34, 34),
        highlight_fg: Color::Rgb(128, 200, 160),
        stripe_bg: Color::Rgb(27, 27, 27),
        key_bg: Color::Rgb(64, 64, 64),
        key_fg: Color::Rgb(204, 204, 204),
        tag: Color::Rgb(150, 180, 210),
        panel_bg: Color::Rgb(28, 28, 28),
        hex_null: Color::Rgb(89, 89, 89),
        hex_ascii: Color::Rgb(80, 180, 120),
        hex_space: Color::Rgb(80, 160, 180),
        hex_high: Color::Rgb(150, 180, 210),
        hex_other: Color::Rgb(128, 200, 160),
        hex_offset: Color::Rgb(89, 89, 89),
    },
    // 6: FFE Dark
    Theme {
        name: "FFE Dark",
        bg: Color::Rgb(30, 35, 43),
        fg: Color::Rgb(216, 222, 233),
        accent: Color::Rgb(79, 214, 190),
        muted: Color::Rgb(155, 162, 175),
        border: Color::Rgb(59, 66, 82),
        highlight_bg: Color::Rgb(46, 52, 64),
        highlight_fg: Color::Rgb(240, 169, 136),
        stripe_bg: Color::Rgb(26, 31, 39),
        key_bg: Color::Rgb(59, 66, 82),
        key_fg: Color::Rgb(216, 222, 233),
        tag: Color::Rgb(137, 220, 235),
        panel_bg: Color::Rgb(26, 31, 39),
        hex_null: Color::Rgb(155, 162, 175),
        hex_ascii: Color::Rgb(163, 190, 140),
        hex_space: Color::Rgb(79, 214, 190),
        hex_high: Color::Rgb(137, 220, 235),
        hex_other: Color::Rgb(240, 169, 136),
        hex_offset: Color::Rgb(155, 162, 175),
    },
    // 7: Postrboard
    Theme {
        name: "Postrboard",
        bg: Color::Rgb(26, 27, 38),
        fg: Color::Rgb(226, 232, 240),
        accent: Color::Rgb(79, 182, 232),
        muted: Color::Rgb(124, 141, 163),
        border: Color::Rgb(42, 45, 61),
        highlight_bg: Color::Rgb(54, 58, 79),
        highlight_fg: Color::Rgb(251, 138, 77),
        stripe_bg: Color::Rgb(30, 31, 43),
        key_bg: Color::Rgb(54, 58, 79),
        key_fg: Color::Rgb(226, 232, 240),
        tag: Color::Rgb(96, 165, 250),
        panel_bg: Color::Rgb(22, 23, 31),
        hex_null: Color::Rgb(124, 141, 163),
        hex_ascii: Color::Rgb(74, 222, 128),
        hex_space: Color::Rgb(79, 182, 232),
        hex_high: Color::Rgb(96, 165, 250),
        hex_other: Color::Rgb(251, 138, 77),
        hex_offset: Color::Rgb(124, 141, 163),
    },
    // ── Light themes ────────────────────────────────────────────────
    // 8: Default Light
    Theme {
        name: "Default Light",
        bg: Color::Reset,
        fg: Color::Rgb(40, 40, 50),
        accent: Color::Rgb(0, 140, 180),
        muted: Color::Rgb(120, 120, 130),
        border: Color::Rgb(180, 180, 190),
        highlight_bg: Color::Rgb(220, 225, 235),
        highlight_fg: Color::Rgb(30, 30, 40),
        stripe_bg: Color::Rgb(240, 240, 245),
        key_bg: Color::Rgb(180, 180, 190),
        key_fg: Color::Rgb(40, 40, 50),
        tag: Color::Rgb(100, 80, 180),
        panel_bg: Color::Rgb(235, 235, 240),
        hex_null: Color::Rgb(120, 120, 130),
        hex_ascii: Color::Rgb(22, 120, 50),
        hex_space: Color::Rgb(0, 120, 150),
        hex_high: Color::Rgb(100, 80, 180),
        hex_other: Color::Rgb(160, 100, 10),
        hex_offset: Color::Rgb(120, 120, 130),
    },
    // 9: Gruvbox Light
    Theme {
        name: "Gruvbox Light",
        bg: Color::Rgb(251, 241, 199),
        fg: Color::Rgb(60, 56, 54),
        accent: Color::Rgb(215, 153, 33),
        muted: Color::Rgb(146, 131, 116),
        border: Color::Rgb(213, 196, 161),
        highlight_bg: Color::Rgb(235, 219, 178),
        highlight_fg: Color::Rgb(60, 56, 54),
        stripe_bg: Color::Rgb(249, 236, 186),
        key_bg: Color::Rgb(213, 196, 161),
        key_fg: Color::Rgb(60, 56, 54),
        tag: Color::Rgb(69, 133, 136),
        panel_bg: Color::Rgb(242, 233, 185),
        hex_null: Color::Rgb(146, 131, 116),
        hex_ascii: Color::Rgb(121, 116, 14),
        hex_space: Color::Rgb(69, 133, 136),
        hex_high: Color::Rgb(143, 63, 113),
        hex_other: Color::Rgb(175, 58, 3),
        hex_offset: Color::Rgb(146, 131, 116),
    },
    // 10: Solarized Light
    Theme {
        name: "Solarized Light",
        bg: Color::Rgb(253, 246, 227),
        fg: Color::Rgb(88, 110, 117),
        accent: Color::Rgb(42, 161, 152),
        muted: Color::Rgb(147, 161, 161),
        border: Color::Rgb(220, 212, 188),
        highlight_bg: Color::Rgb(238, 232, 213),
        highlight_fg: Color::Rgb(7, 54, 66),
        stripe_bg: Color::Rgb(245, 239, 218),
        key_bg: Color::Rgb(220, 212, 188),
        key_fg: Color::Rgb(88, 110, 117),
        tag: Color::Rgb(108, 113, 196),
        panel_bg: Color::Rgb(238, 232, 213),
        hex_null: Color::Rgb(147, 161, 161),
        hex_ascii: Color::Rgb(133, 153, 0),
        hex_space: Color::Rgb(42, 161, 152),
        hex_high: Color::Rgb(108, 113, 196),
        hex_other: Color::Rgb(181, 137, 0),
        hex_offset: Color::Rgb(147, 161, 161),
    },
    // 11: Flexoki Light
    Theme {
        name: "Flexoki Light",
        bg: Color::Rgb(255, 252, 240),
        fg: Color::Rgb(16, 15, 15),
        accent: Color::Rgb(36, 131, 123),
        muted: Color::Rgb(111, 110, 105),
        border: Color::Rgb(230, 228, 217),
        highlight_bg: Color::Rgb(242, 240, 229),
        highlight_fg: Color::Rgb(16, 15, 15),
        stripe_bg: Color::Rgb(247, 245, 234),
        key_bg: Color::Rgb(230, 228, 217),
        key_fg: Color::Rgb(16, 15, 15),
        tag: Color::Rgb(100, 92, 187),
        panel_bg: Color::Rgb(244, 241, 230),
        hex_null: Color::Rgb(111, 110, 105),
        hex_ascii: Color::Rgb(76, 128, 46),
        hex_space: Color::Rgb(36, 131, 123),
        hex_high: Color::Rgb(100, 92, 187),
        hex_other: Color::Rgb(173, 131, 1),
        hex_offset: Color::Rgb(111, 110, 105),
    },
    // 12: Ayu Light
    Theme {
        name: "Ayu Light",
        bg: Color::Rgb(252, 252, 252),
        fg: Color::Rgb(92, 97, 102),
        accent: Color::Rgb(255, 153, 64),
        muted: Color::Rgb(153, 160, 166),
        border: Color::Rgb(207, 209, 210),
        highlight_bg: Color::Rgb(230, 230, 230),
        highlight_fg: Color::Rgb(92, 97, 102),
        stripe_bg: Color::Rgb(243, 244, 245),
        key_bg: Color::Rgb(207, 209, 210),
        key_fg: Color::Rgb(92, 97, 102),
        tag: Color::Rgb(163, 122, 204),
        panel_bg: Color::Rgb(242, 242, 242),
        hex_null: Color::Rgb(153, 160, 166),
        hex_ascii: Color::Rgb(134, 179, 0),
        hex_space: Color::Rgb(55, 160, 190),
        hex_high: Color::Rgb(163, 122, 204),
        hex_other: Color::Rgb(230, 138, 0),
        hex_offset: Color::Rgb(153, 160, 166),
    },
    // 13: Zoegi Light
    Theme {
        name: "Zoegi Light",
        bg: Color::Rgb(255, 255, 255),
        fg: Color::Rgb(51, 51, 51),
        accent: Color::Rgb(55, 121, 97),
        muted: Color::Rgb(89, 89, 89),
        border: Color::Rgb(230, 230, 230),
        highlight_bg: Color::Rgb(235, 235, 235),
        highlight_fg: Color::Rgb(51, 51, 51),
        stripe_bg: Color::Rgb(247, 247, 247),
        key_bg: Color::Rgb(230, 230, 230),
        key_fg: Color::Rgb(51, 51, 51),
        tag: Color::Rgb(80, 120, 160),
        panel_bg: Color::Rgb(245, 245, 245),
        hex_null: Color::Rgb(89, 89, 89),
        hex_ascii: Color::Rgb(40, 120, 70),
        hex_space: Color::Rgb(40, 110, 130),
        hex_high: Color::Rgb(80, 120, 160),
        hex_other: Color::Rgb(150, 110, 30),
        hex_offset: Color::Rgb(89, 89, 89),
    },
    // 14: FFE Light
    Theme {
        name: "FFE Light",
        bg: Color::Rgb(232, 236, 240),
        fg: Color::Rgb(30, 35, 43),
        accent: Color::Rgb(42, 157, 132),
        muted: Color::Rgb(74, 80, 96),
        border: Color::Rgb(201, 205, 214),
        highlight_bg: Color::Rgb(221, 225, 232),
        highlight_fg: Color::Rgb(192, 121, 32),
        stripe_bg: Color::Rgb(245, 247, 250),
        key_bg: Color::Rgb(201, 205, 214),
        key_fg: Color::Rgb(30, 35, 43),
        tag: Color::Rgb(58, 142, 164),
        panel_bg: Color::Rgb(245, 247, 250),
        hex_null: Color::Rgb(74, 80, 96),
        hex_ascii: Color::Rgb(80, 140, 70),
        hex_space: Color::Rgb(42, 157, 132),
        hex_high: Color::Rgb(58, 142, 164),
        hex_other: Color::Rgb(192, 121, 32),
        hex_offset: Color::Rgb(74, 80, 96),
    },
    // 15: Postrboard Light
    Theme {
        name: "Postrboard Light",
        bg: Color::Rgb(250, 250, 250),
        fg: Color::Rgb(17, 24, 39),
        accent: Color::Rgb(2, 132, 199),
        muted: Color::Rgb(100, 116, 139),
        border: Color::Rgb(203, 213, 225),
        highlight_bg: Color::Rgb(226, 232, 240),
        highlight_fg: Color::Rgb(194, 65, 12),
        stripe_bg: Color::Rgb(248, 250, 252),
        key_bg: Color::Rgb(203, 213, 225),
        key_fg: Color::Rgb(17, 24, 39),
        tag: Color::Rgb(12, 74, 110),
        panel_bg: Color::Rgb(241, 245, 249),
        hex_null: Color::Rgb(100, 116, 139),
        hex_ascii: Color::Rgb(22, 128, 61),
        hex_space: Color::Rgb(2, 132, 199),
        hex_high: Color::Rgb(12, 74, 110),
        hex_other: Color::Rgb(194, 65, 12),
        hex_offset: Color::Rgb(100, 116, 139),
    },
];

#[allow(dead_code)]
pub fn theme_index_by_name(name: &str) -> usize {
    THEMES.iter().position(|t| t.name == name).unwrap_or(0)
}

/// Detect theme from Ghostty terminal config.
///
/// Reads `~/.config/ghostty/config` (or macOS app support path) and
/// parses `theme = <name>` to map known Ghostty themes to hexcap themes.
pub fn detect_ghostty_theme() -> Option<usize> {
    let is_ghostty = std::env::var("TERM_PROGRAM").is_ok_and(|v| v.eq_ignore_ascii_case("ghostty"))
        || std::env::var("GHOSTTY_RESOURCES_DIR").is_ok();

    if !is_ghostty {
        return None;
    }

    let home = std::env::var("HOME").ok()?;
    let candidates = [
        format!("{home}/.config/ghostty/config"),
        format!("{home}/Library/Application Support/com.mitchellh.ghostty/config"),
    ];

    let content = candidates
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())?;

    let theme_value = content.lines().find_map(|line| {
        let trimmed = line.trim();
        let rest = trimmed.strip_prefix("theme")?;
        let rest = rest.trim_start();
        let rest = rest.strip_prefix('=')?;
        let rest = rest.trim();
        if rest.is_empty() {
            return None;
        }
        Some(rest.to_string())
    })?;

    // Handle `dark:X,light:Y` syntax — extract dark part
    let theme_name = if theme_value.contains(':') {
        theme_value
            .split(',')
            .find_map(|part| {
                let part = part.trim();
                part.strip_prefix("dark:").map(|v| v.trim().to_string())
            })
            .unwrap_or(theme_value)
    } else {
        theme_value
    };

    let lower = theme_name.to_ascii_lowercase();

    // Order matters: check "light" variant first for each family
    if lower.contains("gruvbox") && lower.contains("light") {
        return Some(9);
    }
    if lower.contains("gruvbox") {
        return Some(1);
    }
    if lower.contains("solarized") && lower.contains("light") {
        return Some(10);
    }
    if lower.contains("solarized") {
        return Some(2);
    }
    if lower.contains("ayu") && lower.contains("light") {
        return Some(12);
    }
    if lower.contains("ayu") {
        return Some(3);
    }
    if lower.contains("flexoki") && lower.contains("light") {
        return Some(11);
    }
    if lower.contains("flexoki") {
        return Some(4);
    }
    if lower.contains("ffe") && lower.contains("light") {
        return Some(14);
    }
    if lower.contains("ffe") {
        return Some(6);
    }

    // Generic light fallback
    if lower.contains("light") {
        return Some(8);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn theme_count() {
        assert_eq!(THEMES.len(), 16);
    }

    #[test]
    fn default_is_first() {
        assert_eq!(THEMES[0].name, "Default");
    }

    #[test]
    fn lookup_by_name() {
        assert_eq!(theme_index_by_name("Gruvbox"), 1);
        assert_eq!(theme_index_by_name("FFE Dark"), 6);
        assert_eq!(theme_index_by_name("Nonexistent"), 0);
    }

    #[test]
    fn all_unique_names() {
        let names: Vec<&str> = THEMES.iter().map(|t| t.name).collect();
        for (i, name) in names.iter().enumerate() {
            assert!(!names[..i].contains(name), "Duplicate: {name}");
        }
    }
}
