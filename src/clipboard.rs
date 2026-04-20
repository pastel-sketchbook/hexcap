use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

/// Copy text to the system clipboard.
///
/// Uses `pbcopy` on macOS and `xclip` on Linux.
pub fn copy_to_clipboard(text: &str) -> Result<()> {
    let cmd = if cfg!(target_os = "macos") {
        "pbcopy"
    } else {
        "xclip"
    };

    let mut child = Command::new(cmd)
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {cmd}"))?;

    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(text.as_bytes())
            .context("failed to write to clipboard")?;
    }

    child.wait().context("clipboard command failed")?;
    Ok(())
}
