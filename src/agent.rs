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

use anyhow::{Context, Result};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Agent presets
// ---------------------------------------------------------------------------

/// Built-in agent presets available in the agent picker.
pub struct AgentPreset {
    pub name: &'static str,
    pub command: &'static str,
    pub description: &'static str,
}

/// The 4 supported coding agents.
pub const AGENT_PRESETS: &[AgentPreset] = &[
    AgentPreset {
        name: "Copilot",
        command: "copilot",
        description: "GitHub Copilot CLI",
    },
    AgentPreset {
        name: "OpenCode",
        command: "opencode",
        description: "OpenCode coding agent",
    },
    AgentPreset {
        name: "Gemini",
        command: "gemini",
        description: "Google Gemini CLI",
    },
    AgentPreset {
        name: "Amp",
        command: "amp",
        description: "Amp coding agent",
    },
];

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

        // Background thread to read child stdout.
        if let Some(stdout) = stdout {
            let out = Arc::clone(&output);
            let cmds = Arc::clone(commands);
            thread::Builder::new()
                .name("agent-stdout".into())
                .spawn(move || {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines() {
                        let Ok(line) = line else { break };
                        // Check for command prefix.
                        if let Some(cmd) = parse_command(&line) {
                            if let Ok(mut q) = cmds.lock() {
                                q.push_back(cmd);
                            }
                        } else {
                            let mut buf = out.lock().expect("agent output mutex poisoned");
                            if buf.len() >= AGENT_OUTPUT_MAX {
                                buf.pop_front();
                            }
                            buf.push_back(line);
                        }
                    }
                })
                .ok();
        }

        Ok(Self {
            child,
            stdin,
            _output: output,
        })
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

/// A Unix domain socket server that broadcasts JSONL to connected clients.
pub struct SocketServer {
    _listener: UnixListener,
    clients: Arc<Mutex<Vec<std::os::unix::net::UnixStream>>>,
    path: String,
}

impl SocketServer {
    /// Create a UDS at the given path and start accepting connections.
    pub fn bind(path: &str) -> Result<Self> {
        // Remove stale socket file.
        let _ = std::fs::remove_file(path);

        let listener =
            UnixListener::bind(path).with_context(|| format!("failed to bind socket: {path}"))?;
        listener.set_nonblocking(true)?;

        let clients: Arc<Mutex<Vec<std::os::unix::net::UnixStream>>> =
            Arc::new(Mutex::new(Vec::new()));

        // Background thread to accept new connections.
        let accept_clients = Arc::clone(&clients);
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
                            let mut cl = accept_clients
                                .lock()
                                .expect("socket clients mutex poisoned");
                            cl.push(stream);
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
            path: path.to_string(),
        })
    }

    /// Broadcast a JSONL line to all connected clients, removing dead ones.
    pub fn broadcast(&self, json_line: &str) {
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
