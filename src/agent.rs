//! Agent communication: pipe to child process and/or unix domain socket.
//!
//! - `AgentPipe`: spawns a child process, writes JSONL to its stdin, reads
//!   stdout lines into a ring buffer for display in the TUI split pane.
//! - `SocketServer`: creates a Unix domain socket, accepts multiple clients,
//!   broadcasts JSONL to all connected clients.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{Context, Result};

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
pub struct AgentPipe {
    child: Child,
    stdin: Option<std::process::ChildStdin>,
    _output: AgentOutput,
}

impl AgentPipe {
    /// Spawn a child process from a shell command string.
    ///
    /// The child's stdin receives JSONL packets; its stdout is read line by
    /// line into the shared output buffer.
    pub fn spawn(cmd: &str, output: AgentOutput) -> Result<Self> {
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
            thread::Builder::new()
                .name("agent-stdout".into())
                .spawn(move || {
                    let reader = BufReader::new(stdout);
                    for line in reader.lines() {
                        let Ok(line) = line else { break };
                        let mut buf = out.lock().expect("agent output mutex poisoned");
                        if buf.len() >= AGENT_OUTPUT_MAX {
                            buf.pop_front();
                        }
                        buf.push_back(line);
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
