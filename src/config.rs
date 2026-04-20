//! User preferences persistence (TOML).

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::theme;

const APP_NAME: &str = "hexcap";

/// Persistent user preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preferences {
    pub theme: String,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: theme::THEMES[0].name.to_string(),
        }
    }
}

/// Resolve the preferences file path.
fn preferences_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", APP_NAME)
        .map(|dirs| dirs.config_dir().join("preferences.toml"))
}

/// Check whether a preferences file exists on disk.
#[must_use]
pub fn has_preferences_file() -> bool {
    preferences_path().is_some_and(|p| p.exists())
}

/// Load preferences from disk, falling back to defaults on any error.
#[must_use]
pub fn load_preferences() -> Preferences {
    preferences_path()
        .and_then(|p| fs::read_to_string(&p).ok())
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

/// Save preferences to disk.
pub fn save_preferences(prefs: &Preferences) -> Result<()> {
    let path = preferences_path().context("could not determine config directory")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("could not create config directory")?;
    }
    let content = toml::to_string_pretty(prefs).context("could not serialize preferences")?;
    fs::write(&path, content).context("could not write preferences file")?;
    Ok(())
}
