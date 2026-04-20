use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyEventKind};
use ratatui::prelude::*;

use crate::app::{App, View};
use crate::{agent, capture, dns, geoip, keys, ui};

/// Execute a single command received from an agent via the `@@HEXCAP:` protocol.
fn execute_agent_command(app: &mut App, cmd: agent::AgentCommand) {
    use agent::AgentCommand;
    match cmd {
        AgentCommand::Filter { value } => {
            if value.is_empty() {
                app.display_filter.clear();
                app.set_status("Agent: filter cleared".into());
            } else {
                app.display_filter = value.clone();
                app.set_status(format!("Agent: filter \"{value}\""));
            }
        }
        AgentCommand::Goto { id } => {
            if let Some(idx) = app.packets.iter().position(|p| p.id == id) {
                app.selected = idx;
                app.set_status(format!("Agent: goto #{id}"));
            } else {
                app.set_status(format!("Agent: packet #{id} not found"));
            }
        }
        AgentCommand::Pause => {
            app.paused = true;
            app.set_status("Agent: paused".into());
        }
        AgentCommand::Resume => {
            app.paused = false;
            app.set_status("Agent: resumed".into());
        }
        AgentCommand::Export { file } => {
            if let Some(path) = file {
                app.export_path = Some(std::path::PathBuf::from(path));
            }
            let msg = app.export_packets();
            app.set_status(format!("Agent: {msg}"));
        }
        AgentCommand::Dns => {
            app.dns_enabled = !app.dns_enabled;
            let state = if app.dns_enabled { "on" } else { "off" };
            app.set_status(format!("Agent: DNS {state}"));
        }
        AgentCommand::Status { message } => {
            app.set_status(message);
        }
        AgentCommand::Bookmark { id } => {
            if !app.bookmarks.remove(&id) {
                app.bookmarks.insert(id);
                app.set_status(format!("Agent: bookmarked #{id}"));
            } else {
                app.set_status(format!("Agent: unbookmarked #{id}"));
            }
        }
        AgentCommand::Annotate { id, text } => {
            if text.is_empty() {
                app.annotations.remove(&id);
            } else {
                app.annotations.insert(id, text);
            }
            app.set_status(format!("Agent: annotated #{id}"));
        }
        AgentCommand::Flows => {
            app.open_flows();
            app.set_status("Agent: flows view".into());
        }
        AgentCommand::Clear => {
            app.clear();
            app.set_status("Agent: cleared".into());
        }
        AgentCommand::View { target } => {
            match target.as_str() {
                "list" => app.view = View::List,
                "detail" => app.open_detail(),
                "flows" => app.open_flows(),
                "stream" => app.open_stream(),
                other => {
                    app.set_status(format!("Agent: unknown view \"{other}\""));
                    return;
                }
            }
            app.set_status(format!("Agent: view {target}"));
        }
        AgentCommand::MarkDiff { id } => {
            if let Some(idx) = app.packets.iter().position(|p| p.id == id) {
                app.selected = idx;
                app.mark_or_diff();
                app.set_status(format!("Agent: mark diff #{id}"));
            } else {
                app.set_status(format!("Agent: packet #{id} not found"));
            }
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &Arc<Mutex<App>>,
    capture: &mut Option<capture::CaptureHandle>,
    bpf_filter: Option<&str>,
    geoip_db: Option<&Arc<geoip::GeoDb>>,
    agent_pipe: &mut Option<agent::AgentPipe>,
    socket_server: &mut Option<agent::SocketServer>,
    agent_output: &agent::AgentOutput,
    agent_commands: &agent::AgentCommands,
) -> Result<()> {
    let mut refresh_counter: u32 = 0;
    let mut dns_counter: u32 = 0;
    let mut agent_last_sent: usize = 0;
    loop {
        // Check for pending interface switch.
        let pending = {
            let mut a = app.lock().expect("app mutex poisoned");
            a.pending_interface.take()
        };
        if let Some(iface) = pending {
            if let Some(cap) = capture.as_ref() {
                cap.stop();
            }
            match capture::CaptureHandle::start(Some(&iface), bpf_filter, Arc::clone(app)) {
                Ok(new_cap) => {
                    *capture = Some(new_cap);
                    let mut a = app.lock().expect("app mutex poisoned");
                    a.set_status(format!("Switched to {iface}"));
                }
                Err(e) => {
                    let mut a = app.lock().expect("app mutex poisoned");
                    a.set_status(format!("Switch failed: {e}"));
                }
            }
        }

        // Check for pending agent picker selection -> spawn agent.
        {
            let mut a = app.lock().expect("app mutex poisoned");
            if let Some(preset_idx) = a.pending_agent_spawn.take()
                && let Some(preset) = agent::AGENT_PRESETS.get(preset_idx)
            {
                if preset.spawn_mode == agent::SpawnMode::Split {
                    // Ensure a socket exists for bidirectional communication.
                    let sock_path = if let Some(ref srv) = *socket_server {
                        srv.path().to_string()
                    } else {
                        let path = std::env::temp_dir()
                            .join(format!(
                                "hexcap_{}.sock",
                                std::process::id()
                            ))
                            .to_string_lossy()
                            .to_string();
                        match agent::SocketServer::bind(&path, agent_commands, a.max_packets) {                            Ok(srv) => {
                                *socket_server = Some(srv);
                                a.socket_path = Some(path.clone());
                                path
                            }
                            Err(e) => {
                                a.set_status(format!("Socket failed: {e}"));
                                continue;
                            }
                        }
                    };

                    // If agent is already running (socket exists), just
                    // show a status — don't spawn another split.
                    if a.agent_name.as_deref() == Some(preset.name) {
                        a.set_status(format!(
                            "{} already open (socket: {sock_path})",
                            preset.name
                        ));
                    } else if let Some(agent_bin) = agent::resolve_binary(preset.binary) {
                        match agent::open_split(&agent_bin, &sock_path) {
                            Ok(true) => {
                                a.agent_name = Some(preset.name.to_string());
                                a.set_status(format!(
                                    "Opened {} split (socket: {sock_path})",
                                    preset.name
                                ));
                            }
                            Ok(false) => {
                                a.set_status(format!(
                                    "{}: no split support (need Ghostty/tmux/WezTerm/Zellij)",
                                    preset.name
                                ));
                            }
                            Err(e) => {
                                a.set_status(format!("{} split failed: {e}", preset.name));
                            }
                        }
                    } else {
                        a.set_status(format!(
                            "{} not found — install {} first",
                            preset.binary, preset.name
                        ));
                    }
                } else {
                    // Prompt mode: snapshot packets, spawn non-interactively.
                    let pkt_count = a.packets.len();
                    let snapshot_path = std::env::temp_dir().join(format!(
                        "hexcap_agent_{}.pcap",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    ));
                    let packets_ref: Vec<&crate::packet::CapturedPacket> =
                        a.packets.iter().collect();
                    let snapshot_ok =
                        crate::export::write_pcap(&snapshot_path, &packets_ref).is_ok();

                    if snapshot_ok {
                        let pcap_str = snapshot_path.to_string_lossy();
                        let cmd = agent::expand_command(
                            preset.command_template,
                            &pcap_str,
                            pkt_count,
                        );
                        a.set_status(format!("Spawning {}...", preset.name));
                        if let Ok(mut buf) = agent_output.lock() {
                            buf.clear();
                        }
                        match agent::AgentPipe::spawn_prompt(
                            &cmd,
                            Arc::clone(agent_output),
                            agent_commands,
                        ) {
                            Ok(pipe) => {
                                *agent_pipe = Some(pipe);
                                a.show_agent_pane = true;
                                a.agent_name = Some(preset.name.to_string());
                                a.agent_scroll = 0;
                                a.set_status(format!("Agent: {}", preset.name));
                            }
                            Err(e) => {
                                a.set_status(format!("Agent failed: {e}"));
                            }
                        }
                    } else {
                        a.set_status("Failed to snapshot packets for agent".into());
                    }
                }
            }
        }

        // Check for on-demand socket creation (X key).
        {
            let mut a = app.lock().expect("app mutex poisoned");
            if a.pending_socket_create {
                a.pending_socket_create = false;
                if let Some(ref srv) = *socket_server {
                    let path = srv.path().to_string();
                    a.socket_path = Some(path.clone());
                    let msg = match crate::clipboard::copy_to_clipboard(&path) {
                        Ok(()) => format!("Socket copied: {path}"),
                        Err(_) => format!("Socket: {path}"),
                    };
                    a.set_status(msg);
                } else {
                    let path = std::env::temp_dir()
                        .join(format!("hexcap_{}.sock", std::process::id()))
                        .to_string_lossy()
                        .to_string();
                    match agent::SocketServer::bind(&path, agent_commands, a.max_packets) {
                        Ok(srv) => {
                            *socket_server = Some(srv);
                            a.socket_path = Some(path.clone());
                            let msg = match crate::clipboard::copy_to_clipboard(&path) {
                                Ok(()) => format!("Socket copied: {path}"),
                                Err(_) => format!("Socket: {path}"),
                            };
                            a.set_status(msg);
                        }
                        Err(e) => {
                            a.set_status(format!("Socket failed: {e}"));
                        }
                    }
                }
            }
        }

        // Drain and execute agent commands.
        {
            let cmds: Vec<agent::AgentCommand> = {
                let mut q = agent_commands
                    .lock()
                    .expect("agent commands mutex poisoned");
                q.drain(..).collect()
            };
            if !cmds.is_empty() {
                let mut a = app.lock().expect("app mutex poisoned");
                for cmd in cmds {
                    execute_agent_command(&mut a, cmd);
                }
            }
        }

        {
            let mut app_guard = app.lock().expect("app mutex poisoned");
            app_guard.tick_status();
            app_guard.tick_bandwidth();

            // Feed new packets to agent pipe/socket.
            let pkt_count = app_guard.packets.len();

            // Check if pipe process has died.
            if let Some(pipe) = &mut *agent_pipe
                && !pipe.is_running()
            {
                app_guard.set_status("Agent pipe exited".into());
            }
            let pipe_alive = agent_pipe.as_mut().is_some_and(agent::AgentPipe::is_running);

            if pkt_count > agent_last_sent && (pipe_alive || socket_server.is_some()) {
                for i in agent_last_sent..pkt_count {
                    if let Some(pkt) = app_guard.packets.get(i)
                        && let Ok(json) = serde_json::to_string(pkt)
                    {
                        if pipe_alive && let Some(pipe) = &mut *agent_pipe {
                            pipe.send(&json);
                        }
                        if let Some(srv) = socket_server {
                            srv.broadcast(&json);
                        }
                    }
                }
                agent_last_sent = pkt_count;
            }
            refresh_counter += 1;
            if refresh_counter >= 100 {
                refresh_counter = 0;
                app_guard.refresh_process_ports();
            }
            // Periodic DNS resolution (~every 5 seconds = 100 ticks).
            dns_counter += 1;
            if dns_counter >= 100 && app_guard.dns_enabled {
                dns_counter = 0;
                let addrs: Vec<String> = app_guard
                    .packets
                    .iter()
                    .flat_map(|p| [p.src.clone(), p.dst.clone()])
                    .collect();
                let existing_keys = app_guard.dns_cache.keys().copied().collect();
                let app_clone = Arc::clone(app);
                drop(app_guard);
                dns::resolve_batch(addrs, existing_keys, app_clone);
            } else {
                // GeoIP resolution (cheap, in-line).
                if app_guard.geoip_enabled
                    && let Some(db) = geoip_db
                {
                    let ips: Vec<std::net::IpAddr> = app_guard
                        .packets
                        .iter()
                        .flat_map(|p| {
                            [&p.src, &p.dst]
                                .into_iter()
                                .filter_map(|a| dns::extract_ip(a))
                        })
                        .collect();
                    geoip::resolve_batch(db, &ips, &mut app_guard.geoip_cache);
                }
                terminal.draw(|f| ui::render(f, &app_guard))?;
                drop(app_guard);
            }
        }

        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    let mut app_guard = app.lock().expect("app mutex poisoned");
                    if keys::handle_key(&mut app_guard, key.code) {
                        return Ok(());
                    }
                }
                Event::Mouse(mouse) => {
                    let mut app_guard = app.lock().expect("app mutex poisoned");
                    let term_height = terminal.size().map(|s| s.height).unwrap_or(24);
                    keys::handle_mouse(&mut app_guard, mouse, term_height);
                }
                _ => {}
            }
        }
    }
}
