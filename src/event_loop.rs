use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyEventKind};
use ratatui::prelude::*;

use crate::app::{App, View};
use crate::{agent, capture, dns, geoip, keys, ui};

/// Execute a single command received from an agent via the `@@HEXCAP:` protocol.
#[allow(clippy::too_many_lines)]
fn execute_agent_command(app: &mut App, cmd: agent::AgentCommand) {
    use agent::AgentCommand;
    match cmd {
        AgentCommand::Filter { value } => {
            if value.is_empty() {
                app.display_filter.clear();
                app.set_status("Agent: filter cleared".into());
            } else {
                app.display_filter.clone_from(&value);
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
            if let Some(ref path) = file {
                // Validate: reject path traversal and absolute paths outside /tmp.
                let p = std::path::Path::new(path);
                let has_traversal = p
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir));
                if has_traversal {
                    app.set_status("Agent: export rejected (path traversal)".into());
                    return;
                }
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
            if app.bookmarks.remove(&id) {
                app.set_status(format!("Agent: unbookmarked #{id}"));
            } else {
                app.bookmarks.insert(id);
                app.set_status(format!("Agent: bookmarked #{id}"));
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
        AgentCommand::Interface { name } => {
            let valid = capture::list_interfaces()
                .is_ok_and(|ifaces| ifaces.iter().any(|i| i.name == name));
            if valid {
                app.pending_interface = Some(name.clone());
                app.set_status(format!("Agent: switching to {name}"));
            } else {
                let available = capture::list_interfaces()
                    .map(|ifaces| {
                        ifaces
                            .iter()
                            .map(|i| i.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                app.set_status(format!(
                    "Agent: unknown interface '{name}' (available: {available})"
                ));
            }
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
        // These are routed through the stamped command queue, not here.
        AgentCommand::Register { .. }
        | AgentCommand::Chat { .. }
        | AgentCommand::Ask { .. }
        | AgentCommand::Reply { .. } => {}
    }
}

/// Execute a query against the current app state and return a JSON value.
fn execute_query(
    app: &App,
    kind: &agent::QueryKind,
    registry: Option<&agent::AgentRegistry>,
) -> serde_json::Value {
    use agent::QueryKind;
    match kind {
        QueryKind::Packets { filter, limit } => {
            let limit = limit.unwrap_or(100).min(10_000);
            let packets: Vec<&crate::packet::CapturedPacket> = if let Some(f) = filter {
                app.packets
                    .iter()
                    .filter(|p| crate::packet::matches_display_filter(p, f))
                    .take(limit)
                    .collect()
            } else {
                app.packets.iter().take(limit).collect()
            };
            serde_json::to_value(&packets).unwrap_or_default()
        }
        QueryKind::Flows => serde_json::to_value(&app.flows).unwrap_or_default(),
        QueryKind::Stats => {
            let total = app.packets.len();
            let mut proto_counts: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            let mut total_bytes: u64 = 0;
            for pkt in &app.packets {
                *proto_counts
                    .entry(format!("{:?}", pkt.protocol))
                    .or_default() += 1;
                total_bytes += pkt.length as u64;
            }
            serde_json::json!({
                "total_packets": total,
                "total_bytes": total_bytes,
                "protocols": proto_counts,
                "flows": app.flows.len(),
                "paused": app.paused,
            })
        }
        QueryKind::Decode { packet_id } => {
            if let Some(pkt) = app.packets.iter().find(|p| p.id == *packet_id) {
                serde_json::to_value(pkt).unwrap_or_default()
            } else {
                serde_json::json!({"error": format!("packet #{packet_id} not found")})
            }
        }
        QueryKind::Stream { flow } => {
            // Find matching flow and collect TCP payload.
            if let Some(flow_str) = flow {
                let payload: Vec<u8> = app
                    .packets
                    .iter()
                    .filter(|p| {
                        let key = crate::packet::FlowKey::new(&p.src, &p.dst);
                        key.to_string() == *flow_str
                    })
                    .flat_map(|p| {
                        // Extract TCP payload (skip headers).
                        crate::hex::hex_dump_plain(&p.data).into_bytes()
                    })
                    .collect();
                let text = String::from_utf8_lossy(&payload);
                serde_json::json!({
                    "flow": flow_str,
                    "payload_bytes": payload.len(),
                    "payload_text": text,
                })
            } else {
                serde_json::json!({"error": "flow parameter required"})
            }
        }
        QueryKind::Status => {
            serde_json::json!({
                "packets": app.packets.len(),
                "flows": app.flows.len(),
                "paused": app.paused,
                "view": format!("{:?}", app.view),
                "display_filter": app.display_filter,
                "dns_enabled": app.dns_enabled,
                "bookmarks": app.bookmarks.len(),
                "selected": app.selected,
            })
        }
        QueryKind::Interfaces => capture::list_interfaces()
            .map(|ifaces| serde_json::to_value(&ifaces).unwrap_or_default())
            .unwrap_or(serde_json::json!([])),
        QueryKind::Agents => {
            if let Some(reg) = registry {
                let reg = reg.lock().expect("registry mutex poisoned");
                let agents: Vec<&agent::AgentRegistration> = reg.values().collect();
                serde_json::to_value(&agents).unwrap_or_default()
            } else {
                serde_json::json!([])
            }
        }
    }
}

/// Execute a stamped command (one that needs `client_id` context for routing).
fn execute_stamped_command(app: &mut App, server: &agent::SocketServer, sc: agent::StampedCommand) {
    use agent::AgentCommand;
    match sc.command {
        AgentCommand::Register { name, capabilities } => {
            let reg = agent::AgentRegistration {
                name: name.clone(),
                client_id: sc.client_id,
                capabilities,
            };
            if let Ok(mut registry) = server.registry.lock() {
                registry.insert(sc.client_id, reg);
            }
            app.set_status(format!("Agent '{name}' registered"));
        }
        AgentCommand::Chat { message } => {
            // Look up sender name from registry.
            let sender = server
                .registry
                .lock()
                .ok()
                .and_then(|r| r.get(&sc.client_id).map(|a| a.name.clone()))
                .unwrap_or_else(|| format!("client:{}", sc.client_id));
            let msg = serde_json::json!({
                "type": "chat",
                "from": sender,
                "message": message,
            });
            let json = serde_json::to_string(&msg).unwrap_or_default();
            server.broadcast_except(sc.client_id, &json);
            app.set_status(format!("[{sender}] {message}"));
        }
        AgentCommand::Ask {
            to,
            request_id,
            message,
        } => {
            let sender = server
                .registry
                .lock()
                .ok()
                .and_then(|r| r.get(&sc.client_id).map(|a| a.name.clone()))
                .unwrap_or_else(|| format!("client:{}", sc.client_id));
            if let Some(target_id) = server.resolve_agent(&to) {
                let msg = serde_json::json!({
                    "type": "ask",
                    "from": sender,
                    "request_id": request_id,
                    "message": message,
                });
                let json = serde_json::to_string(&msg).unwrap_or_default();
                if !server.send_to_client(target_id, &json) {
                    app.set_status(format!("Agent: failed to reach '{to}'"));
                }
            } else {
                app.set_status(format!("Agent: unknown agent '{to}'"));
            }
        }
        AgentCommand::Reply {
            to,
            request_id,
            message,
        } => {
            let sender = server
                .registry
                .lock()
                .ok()
                .and_then(|r| r.get(&sc.client_id).map(|a| a.name.clone()))
                .unwrap_or_else(|| format!("client:{}", sc.client_id));
            if let Some(target_id) = server.resolve_agent(&to) {
                let msg = serde_json::json!({
                    "type": "reply",
                    "from": sender,
                    "request_id": request_id,
                    "message": message,
                });
                let json = serde_json::to_string(&msg).unwrap_or_default();
                if !server.send_to_client(target_id, &json) {
                    app.set_status(format!("Agent: failed to reach '{to}'"));
                }
            } else {
                app.set_status(format!("Agent: unknown agent '{to}'"));
            }
        }
        // Non-stamped commands don't end up here.
        _ => {}
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
    agent_queries: &agent::AgentQueries,
    stamped_commands: &agent::StampedCommands,
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
                        let path = agent::default_socket_path();
                        match agent::SocketServer::bind(
                            &path,
                            agent_commands,
                            agent_queries,
                            stamped_commands,
                            a.max_packets,
                        ) {
                            Ok(srv) => {
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
                        let cmd =
                            agent::expand_command(preset.command_template, &pcap_str, pkt_count);
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
                    let path = agent::default_socket_path();
                    match agent::SocketServer::bind(
                        &path,
                        agent_commands,
                        agent_queries,
                        stamped_commands,
                        a.max_packets,
                    ) {
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

        // Drain and execute agent queries.
        {
            let queries: Vec<agent::AgentQuery> = {
                let mut q = agent_queries.lock().expect("agent queries mutex poisoned");
                q.drain(..).collect()
            };
            if !queries.is_empty() {
                let a = app.lock().expect("app mutex poisoned");
                for query in queries {
                    let registry = socket_server.as_ref().map(|s| &s.registry);
                    let data = execute_query(&a, &query.kind, registry);
                    let response = agent::QueryResponse {
                        id: query.request_id,
                        response_type: "response".into(),
                        data,
                    };
                    if let Some(ref srv) = *socket_server {
                        srv.respond(query.client_id, &response);
                    }
                }
            }
        }

        // Drain and execute stamped commands (register/chat/ask/reply).
        {
            let cmds: Vec<agent::StampedCommand> = {
                let mut q = stamped_commands
                    .lock()
                    .expect("stamped commands mutex poisoned");
                q.drain(..).collect()
            };
            if !cmds.is_empty()
                && let Some(ref srv) = *socket_server
            {
                let mut app_guard = app.lock().expect("app mutex poisoned");
                for sc in cmds {
                    execute_stamped_command(&mut app_guard, srv, sc);
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
            let pipe_alive = agent_pipe
                .as_mut()
                .is_some_and(agent::AgentPipe::is_running);

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
                    let term_height = terminal.size().map_or(24, |s| s.height);
                    keys::handle_mouse(&mut app_guard, mouse, term_height);
                }
                _ => {}
            }
        }
    }
}
