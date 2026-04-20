//! Agent communication: pipe to child process and/or unix domain socket.
//!
//! - `AgentPipe`: spawns a child process, writes JSONL to its stdin, reads
//!   stdout lines into a ring buffer for display in the TUI split pane.
//!   Lines prefixed with `@@HEXCAP:` are parsed as JSON commands and routed
//!   to a separate command queue for the main loop to execute.
//! - `SocketServer`: creates a Unix domain socket, accepts multiple clients,
//!   broadcasts JSONL to all connected clients.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

/// Strip ANSI escape sequences from a string so agent output renders cleanly.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // CSI sequence: ESC [ ... final_byte
            if let Some(next) = chars.next()
                && next == '['
            {
                // Consume until final byte (0x40-0x7E).
                for c in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&c) {
                        break;
                    }
                }
            }
            // OSC (ESC ]) or other sequences: already consumed by the
            // `chars.next()` in the `if let` above.
        } else {
            out.push(ch);
        }
    }
    out
}

use anyhow::{Context, Result};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Agent presets
// ---------------------------------------------------------------------------

/// How an agent preset should be spawned.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SpawnMode {
    /// Run non-interactively: pipe stdout into the agent pane.
    Prompt,
    /// Open in a terminal split pane (Ghostty/tmux/WezTerm/Zellij) or
    /// full-screen takeover when no split support is detected.
    Split,
}

/// Built-in agent presets available in the agent picker.
pub struct AgentPreset {
    pub name: &'static str,
    /// Shell command template. `{pcap}` is replaced with the snapshot pcap path,
    /// `{prompt}` is replaced with the analysis prompt.
    pub command_template: &'static str,
    /// The binary name (for `which` resolution in split mode).
    pub binary: &'static str,
    pub description: &'static str,
    pub spawn_mode: SpawnMode,
}

/// The 4 supported coding agents.
pub const AGENT_PRESETS: &[AgentPreset] = &[
    AgentPreset {
        name: "Copilot",
        command_template: "copilot -p {prompt} --allow-all-tools",
        binary: "copilot",
        description: "GitHub Copilot CLI",
        spawn_mode: SpawnMode::Prompt,
    },
    AgentPreset {
        name: "OpenCode",
        command_template: "opencode run {prompt}",
        binary: "opencode",
        description: "OpenCode coding agent",
        spawn_mode: SpawnMode::Prompt,
    },
    AgentPreset {
        name: "Gemini",
        command_template: "gemini -p {prompt} -o text",
        binary: "gemini",
        description: "Google Gemini CLI",
        spawn_mode: SpawnMode::Prompt,
    },
    AgentPreset {
        name: "Amp",
        command_template: "amp",
        binary: "amp",
        description: "Amp coding agent",
        spawn_mode: SpawnMode::Split,
    },
];

/// Resolve the absolute path of a binary via `which`.
pub fn resolve_binary(name: &str) -> Option<String> {
    Command::new("which")
        .arg(name)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            let s = String::from_utf8(o.stdout).ok()?;
            let trimmed = s.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
}

/// Open an agent in a terminal split pane (right side).
///
/// Supports Ghostty (AppleScript), tmux, WezTerm, and Zellij.
/// Sets `HEXCAP_SOCKET` in the agent's environment so it can send commands back.
/// Returns `Ok(true)` if a split was opened, `Ok(false)` if no supported
/// terminal was detected (caller should fall back to full-screen).
pub fn open_split(agent_bin: &str, socket_path: &str) -> Result<bool> {
    use std::env;

    // Wrap agent binary with HEXCAP_SOCKET env so it can send commands back.
    let wrapped = format!("HEXCAP_SOCKET={socket_path} exec {agent_bin}");

    let result = if env::var("TMUX").is_ok() {
        Command::new("tmux")
            .args(["split-window", "-h", "-l", "60%", "sh", "-c", &wrapped])
            .spawn()
    } else if env::var("WEZTERM_PANE").is_ok() || env::var("WEZTERM_EXECUTABLE").is_ok() {
        Command::new("wezterm")
            .args([
                "cli",
                "split-pane",
                "--right",
                "--percent",
                "60",
                "--",
                "sh",
                "-c",
                &wrapped,
            ])
            .spawn()
    } else if env::var("ZELLIJ").is_ok() {
        Command::new("zellij")
            .args(["action", "new-pane", "-d", "right", "--", "sh", "-c", &wrapped])
            .spawn()
    } else if crate::ui::helpers::is_ghostty() {
        // Ghostty on macOS: AppleScript to split the focused terminal.
        // Wrap in /bin/zsh -l -c so the agent gets the user's PATH.
        let script = format!(
            r#"tell application "Ghostty"
    set cfg to new surface configuration
    set command of cfg to "/bin/zsh -l -c 'export HEXCAP_SOCKET={socket_path}; exec {agent_bin}'"
    set t to focused terminal of selected tab of front window
    split t direction right with configuration cfg
end tell"#
        );
        Command::new("osascript").args(["-e", &script]).spawn()
    } else {
        return Ok(false);
    };

    match result {
        Ok(_) => Ok(true),
        Err(e) => Err(anyhow::anyhow!("Failed to open split: {e}")),
    }
}

/// Build the agent analysis prompt, referencing the pcap snapshot file.
pub fn build_prompt(pcap_path: &str, packet_count: usize) -> String {
    format!(
        "You have the hexcap skill. Use `hexcap read {pcap}`, `hexcap flows {pcap}`, \
         `hexcap stats {pcap}`, and `hexcap stream {pcap}` to analyze the capture. \
         The file contains {count} packets. Provide a summary of the traffic: \
         protocols seen, notable flows, any anomalies or interesting patterns.",
        pcap = pcap_path,
        count = packet_count,
    )
}

/// Expand a command template, replacing `{prompt}` and `{pcap}` placeholders.
pub fn expand_command(template: &str, pcap_path: &str, packet_count: usize) -> String {
    let prompt = build_prompt(pcap_path, packet_count);
    // Shell-quote the prompt (single quotes, escape inner single quotes).
    let quoted = format!("'{}'", prompt.replace('\'', "'\\''"));
    template
        .replace("{prompt}", &quoted)
        .replace("{pcap}", pcap_path)
}

// ---------------------------------------------------------------------------
// Agent commands (agent → TUI)
// ---------------------------------------------------------------------------

/// Magic prefix for command lines from agent stdout.
const COMMAND_PREFIX: &str = "@@HEXCAP:";

/// Commands that an agent can send back to the TUI.
///
/// Agents write `@@HEXCAP:{"action":"filter","value":"tcp port:443"}` to stdout.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum AgentCommand {
    /// Apply a display filter expression.
    Filter { value: String },
    /// Jump to a packet by ID (1-based).
    Goto { id: u64 },
    /// Pause capture.
    Pause,
    /// Resume capture.
    Resume,
    /// Export packets to pcap. Optional filename; auto-generates if absent.
    Export {
        #[serde(default)]
        file: Option<String>,
    },
    /// Toggle DNS resolution on/off.
    Dns,
    /// Set a status message in the footer.
    Status { message: String },
    /// Toggle bookmark on a packet by ID.
    Bookmark { id: u64 },
    /// Add annotation to a packet.
    Annotate { id: u64, text: String },
    /// Switch to flows view.
    Flows,
    /// Clear all packets.
    Clear,
    /// Switch view.
    View {
        #[serde(default = "default_view")]
        target: String,
    },
    /// Mark a packet for diff (same as pressing `x`).
    MarkDiff { id: u64 },
}

fn default_view() -> String {
    "list".into()
}

/// Try to parse a line as an agent command. Returns `Some` if the line starts
/// with `@@HEXCAP:` and the JSON payload is valid.
pub fn parse_command(line: &str) -> Option<AgentCommand> {
    let json = line.strip_prefix(COMMAND_PREFIX)?;
    serde_json::from_str(json.trim()).ok()
}

/// Shared queue of pending agent commands for the main loop.
pub type AgentCommands = Arc<Mutex<VecDeque<AgentCommand>>>;

/// Create a new shared command queue.
pub fn new_commands() -> AgentCommands {
    Arc::new(Mutex::new(VecDeque::new()))
}

// ---------------------------------------------------------------------------
// Output buffer
// ---------------------------------------------------------------------------

/// Maximum lines of agent output to keep in the ring buffer.
const AGENT_OUTPUT_MAX: usize = 500;

/// Shared ring buffer of agent stdout lines.
pub type AgentOutput = Arc<Mutex<VecDeque<String>>>;

/// Create a new shared output buffer.
pub fn new_output() -> AgentOutput {
    Arc::new(Mutex::new(VecDeque::with_capacity(AGENT_OUTPUT_MAX)))
}

// ---------------------------------------------------------------------------
// AgentPipe: spawn child, feed JSONL, collect stdout
// ---------------------------------------------------------------------------

/// A child process that receives JSONL on stdin and emits output on stdout.
///
/// Stdout lines prefixed with `@@HEXCAP:` are parsed as [`AgentCommand`]s and
/// pushed to the shared command queue. All other lines go to the display buffer.
pub struct AgentPipe {
    child: Child,
    stdin: Option<std::process::ChildStdin>,
    _output: AgentOutput,
}

impl AgentPipe {
    /// Spawn a child process from a shell command string.
    ///
    /// The child's stdin receives JSONL packets; its stdout is read line by
    /// line — command lines go to `commands`, display lines go to `output`.
    pub fn spawn(cmd: &str, output: AgentOutput, commands: &AgentCommands) -> Result<Self> {
        let mut child = Command::new("sh")
            .args(["-c", cmd])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to spawn agent: {cmd}"))?;

        let stdin = child.stdin.take();
        let stdout = child.stdout.take();

        Self::start_reader(stdout, &output, commands);

        Ok(Self {
            child,
            stdin,
            _output: output,
        })
    }

    /// Spawn an agent in prompt mode (no stdin pipe).
    ///
    /// The agent receives its context via CLI args (referencing a pcap file)
    /// and uses `hexcap` subcommands to analyze it. Stdin is closed immediately.
    pub fn spawn_prompt(cmd: &str, output: AgentOutput, commands: &AgentCommands) -> Result<Self> {
        let mut child = Command::new("sh")
            .args(["-c", cmd])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn agent: {cmd}"))?;

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        Self::start_reader(stdout, &output, commands);

        // Also read stderr into the output buffer so we see agent errors.
        if let Some(stderr) = stderr {
            let out = Arc::clone(&output);
            thread::Builder::new()
                .name("agent-stderr".into())
                .spawn(move || {
                    let reader = BufReader::new(stderr);
                    for line in reader.lines() {
                        let Ok(line) = line else { break };
                        let mut buf = out.lock().expect("agent output mutex poisoned");
                        if buf.len() >= AGENT_OUTPUT_MAX {
                            buf.pop_front();
                        }
                        buf.push_back(strip_ansi(&line));
                    }
                })
                .ok();
        }

        Ok(Self {
            child,
            stdin: None,
            _output: output,
        })
    }

    /// Start a background thread to read child stdout lines.
    fn start_reader(
        stdout: Option<std::process::ChildStdout>,
        output: &AgentOutput,
        commands: &AgentCommands,
    ) {
        if let Some(stdout) = stdout {
            let out = Arc::clone(output);
            let cmds = Arc::clone(commands);
            thread::Builder::new()
                .name("agent-stdout".into())
                .spawn(move || {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines() {
                        let Ok(line) = line else { break };
                        if let Some(cmd) = parse_command(&line) {
                            if let Ok(mut q) = cmds.lock() {
                                q.push_back(cmd);
                            }
                        } else {
                            let mut buf = out.lock().expect("agent output mutex poisoned");
                            if buf.len() >= AGENT_OUTPUT_MAX {
                                buf.pop_front();
                            }
                            buf.push_back(strip_ansi(&line));
                        }
                    }
                })
                .ok();
        }
    }

    /// Write a JSONL line (packet) to the child's stdin.
    pub fn send(&mut self, json_line: &str) {
        if let Some(ref mut stdin) = self.stdin {
            let _ = stdin.write_all(json_line.as_bytes());
            let _ = stdin.write_all(b"\n");
            let _ = stdin.flush();
        }
    }

    /// Check if the child is still running.
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for AgentPipe {
    fn drop(&mut self) {
        // Close stdin to signal EOF, then wait.
        self.stdin.take();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// SocketServer: Unix domain socket for external agents
// ---------------------------------------------------------------------------

use std::os::unix::net::UnixListener;

/// A Unix domain socket server that broadcasts JSONL to connected clients
/// and reads `@@HEXCAP:` commands from them (bidirectional).
///
/// New clients receive a replay of all previously broadcast packets on connect,
/// so they don't miss buffered data. The replay buffer is capped at
/// `max_replay` entries (oldest evicted first).
pub struct SocketServer {
    _listener: UnixListener,
    clients: Arc<Mutex<Vec<std::os::unix::net::UnixStream>>>,
    replay_buffer: Arc<Mutex<VecDeque<String>>>,
    max_replay: usize,
    path: String,
}

impl SocketServer {
    /// Create a UDS at the given path and start accepting connections.
    ///
    /// Each connected client gets a reader thread that parses incoming
    /// `@@HEXCAP:` command lines and pushes them to the shared command queue.
    pub fn bind(path: &str, commands: &AgentCommands, max_replay: usize) -> Result<Self> {
        // Remove stale socket file.
        let _ = std::fs::remove_file(path);

        let listener =
            UnixListener::bind(path).with_context(|| format!("failed to bind socket: {path}"))?;
        // Allow non-root agents to connect when hexcap runs under sudo.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777));
            // chown to the real (pre-sudo) user so agents running as that user
            // can connect without permission errors.
            chown_to_real_user(path);
        }
        listener.set_nonblocking(true)?;

        let clients: Arc<Mutex<Vec<std::os::unix::net::UnixStream>>> =
            Arc::new(Mutex::new(Vec::new()));
        let replay_buffer: Arc<Mutex<VecDeque<String>>> =
            Arc::new(Mutex::new(VecDeque::with_capacity(max_replay.min(8192))));

        // Background thread to accept new connections.
        let accept_clients = Arc::clone(&clients);
        let accept_replay = Arc::clone(&replay_buffer);
        let accept_cmds = Arc::clone(commands);
        let accept_listener = listener
            .try_clone()
            .context("failed to clone UDS listener")?;
        thread::Builder::new()
            .name("agent-socket-accept".into())
            .spawn(move || {
                loop {
                    match accept_listener.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            // Clone for broadcast list.
                            if let Ok(mut write_stream) = stream.try_clone() {
                                // Replay buffered packets to this new client.
                                let replay_ok = {
                                    let buf = accept_replay
                                        .lock()
                                        .expect("replay buffer mutex poisoned");
                                    let mut ok = true;
                                    for line in buf.iter() {
                                        let msg = format!("{line}\n");
                                        if write_stream.write_all(msg.as_bytes()).is_err() {
                                            ok = false;
                                            break;
                                        }
                                    }
                                    if ok {
                                        let _ = write_stream.flush();
                                    }
                                    ok
                                };
                                if replay_ok {
                                    let mut cl = accept_clients
                                        .lock()
                                        .expect("socket clients mutex poisoned");
                                    cl.push(write_stream);
                                }
                            }
                            // Spawn reader thread for this client.
                            let cmds = Arc::clone(&accept_cmds);
                            thread::Builder::new()
                                .name("agent-socket-reader".into())
                                .spawn(move || {
                                    let reader = BufReader::new(stream);
                                    for line in reader.lines() {
                                        let Ok(line) = line else { break };
                                        if let Some(cmd) = parse_command(&line)
                                            && let Ok(mut q) = cmds.lock()
                                        {
                                            q.push_back(cmd);
                                        }
                                    }
                                })
                                .ok();
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                        Err(_) => break,
                    }
                }
            })
            .ok();

        Ok(Self {
            _listener: listener,
            clients,
            replay_buffer,
            max_replay,
            path: path.to_string(),
        })
    }

    /// Broadcast a JSONL line to all connected clients, removing dead ones.
    /// Also appends to the replay buffer so new clients get the full history.
    pub fn broadcast(&self, json_line: &str) {
        // Append to replay buffer for future clients.
        if let Ok(mut buf) = self.replay_buffer.lock() {
            buf.push_back(json_line.to_string());
            while buf.len() > self.max_replay {
                buf.pop_front();
            }
        }
        let mut clients = self.clients.lock().expect("socket clients mutex poisoned");
        let msg = format!("{json_line}\n");
        clients.retain_mut(|stream| {
            stream.write_all(msg.as_bytes()).is_ok() && stream.flush().is_ok()
        });
    }

    /// Path to the socket file.
    #[allow(dead_code)]
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl Drop for SocketServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Change ownership of `path` to the real (pre-sudo) user.
///
/// When hexcap runs under `sudo`, files are created as root. This reads
/// `SUDO_UID` / `SUDO_GID` and calls `libc::chown` so that agents running
/// as the original user can connect to the socket.
#[cfg(unix)]
fn chown_to_real_user(path: &str) {
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    if let Some(uid) = uid {
        let gid = gid.unwrap_or(uid);
        let c_path = std::ffi::CString::new(path).unwrap_or_default();
        // SAFETY: `c_path` is a valid NUL-terminated string and `chown` is a
        // standard POSIX call that only modifies file metadata.
        unsafe {
            libc::chown(c_path.as_ptr(), uid, gid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_filter_command() {
        let line = r#"@@HEXCAP:{"action":"filter","value":"tcp port:443"}"#;
        let cmd = parse_command(line).expect("should parse");
        assert!(matches!(cmd, AgentCommand::Filter { value } if value == "tcp port:443"));
    }

    #[test]
    fn parse_goto_command() {
        let line = r#"@@HEXCAP:{"action":"goto","id":42}"#;
        let cmd = parse_command(line).expect("should parse");
        assert!(matches!(cmd, AgentCommand::Goto { id: 42 }));
    }

    #[test]
    fn parse_pause_command() {
        let line = r#"@@HEXCAP:{"action":"pause"}"#;
        let cmd = parse_command(line).expect("should parse");
        assert!(matches!(cmd, AgentCommand::Pause));
    }

    #[test]
    fn parse_status_command() {
        let line = r#"@@HEXCAP:{"action":"status","message":"hello"}"#;
        let cmd = parse_command(line).expect("should parse");
        assert!(matches!(cmd, AgentCommand::Status { message } if message == "hello"));
    }

    #[test]
    fn parse_annotate_command() {
        let line = r#"@@HEXCAP:{"action":"annotate","id":5,"text":"suspicious"}"#;
        let cmd = parse_command(line).expect("should parse");
        assert!(matches!(cmd, AgentCommand::Annotate { id: 5, text } if text == "suspicious"));
    }

    #[test]
    fn non_command_line_returns_none() {
        assert!(parse_command("just a regular line").is_none());
        assert!(parse_command("@@HEXCAP:not json").is_none());
    }

    #[test]
    fn parse_export_with_file() {
        let line = r#"@@HEXCAP:{"action":"export","file":"/tmp/out.pcap"}"#;
        let cmd = parse_command(line).expect("should parse");
        assert!(matches!(cmd, AgentCommand::Export { file: Some(f) } if f == "/tmp/out.pcap"));
    }

    #[test]
    fn parse_export_without_file() {
        let line = r#"@@HEXCAP:{"action":"export"}"#;
        let cmd = parse_command(line).expect("should parse");
        assert!(matches!(cmd, AgentCommand::Export { file: None }));
    }
}
