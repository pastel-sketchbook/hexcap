use crossterm::event::{KeyCode, MouseEvent, MouseEventKind};

use crate::app::{App, InputMode, View};
use crate::{capture, clipboard, hex, process};

/// Handle mouse events. `term_height` is the terminal row count so we can
/// determine which pane (main vs agent) the scroll landed in.
pub fn handle_mouse(app: &mut App, event: MouseEvent, term_height: u16) {
    let split_row = if app.show_agent_pane {
        #[allow(clippy::cast_possible_truncation)]
        let row = (u32::from(term_height) * u32::from(app.agent_pane_ratio) / 100) as u16;
        row
    } else {
        term_height
    };

    // Drag on the agent pane border to resize.
    if app.show_agent_pane {
        match event.kind {
            MouseEventKind::Down(crossterm::event::MouseButton::Left) => {
                // Start drag if click is on or near the border row.
                let distance = event.row.abs_diff(split_row);
                if distance <= 1 {
                    app.agent_pane_dragging = true;
                    return;
                }
            }
            MouseEventKind::Drag(crossterm::event::MouseButton::Left)
                if app.agent_pane_dragging =>
            {
                #[allow(clippy::cast_possible_truncation)]
                let new_ratio = (u32::from(event.row) * 100 / u32::from(term_height.max(1))) as u16;
                app.agent_pane_ratio = new_ratio.clamp(20, 80);
                return;
            }
            MouseEventKind::Up(crossterm::event::MouseButton::Left) if app.agent_pane_dragging => {
                app.agent_pane_dragging = false;
                return;
            }
            _ => {}
        }
    }

    // Scrolls in the agent pane area.
    if app.show_agent_pane && event.row >= split_row {
        match event.kind {
            MouseEventKind::ScrollDown => {
                app.agent_scroll = app.agent_scroll.saturating_sub(1);
            }
            MouseEventKind::ScrollUp => {
                let total = app.agent_output.lock().map_or(0, |o| o.len());
                if app.agent_scroll < total {
                    app.agent_scroll += 1;
                }
            }
            _ => {}
        }
        return;
    }

    match event.kind {
        MouseEventKind::ScrollDown => match app.view {
            View::List => app.next(),
            View::Detail => app.scroll_down(),
            View::Flows => app.flow_next(),
            View::Stream => app.stream_scroll_down(),
        },
        MouseEventKind::ScrollUp => match app.view {
            View::List => app.previous(),
            View::Detail => app.scroll_up(),
            View::Flows => app.flow_prev(),
            View::Stream => app.stream_scroll_up(),
        },
        _ => {}
    }
}

/// Returns `true` if the app should quit.
#[allow(clippy::too_many_lines)]
pub fn handle_key(app: &mut App, code: KeyCode) -> bool {
    // Interface picker overlay — intercept keys first.
    if app.interface_picker.is_some() {
        match code {
            KeyCode::Esc => app.close_interface_picker(),
            KeyCode::Enter => app.iface_picker_select(),
            KeyCode::Down | KeyCode::Char('j') => app.iface_picker_next(),
            KeyCode::Up | KeyCode::Char('k') => app.iface_picker_prev(),
            _ => {}
        }
        return false;
    }

    // Agent picker overlay — intercept keys first.
    if app.agent_picker.is_some() {
        match code {
            KeyCode::Esc => app.close_agent_picker(),
            KeyCode::Enter => app.agent_picker_select(),
            KeyCode::Down | KeyCode::Char('j') => app.agent_picker_next(),
            KeyCode::Up | KeyCode::Char('k') => app.agent_picker_prev(),
            _ => {}
        }
        return false;
    }

    // Process picker overlay — intercept keys first.
    if app.process_picker.is_some() {
        match code {
            KeyCode::Esc => app.close_process_picker(),
            KeyCode::Enter => app.picker_select(),
            KeyCode::Down | KeyCode::Char('j') => app.picker_next(),
            KeyCode::Up | KeyCode::Char('k') => app.picker_prev(),
            KeyCode::Backspace => app.picker_pop(),
            KeyCode::Char(ch) => app.picker_push(ch),
            _ => {}
        }
        return false;
    }

    // Search input mode.
    if app.input_mode == InputMode::Search {
        match code {
            KeyCode::Esc => app.cancel_search(),
            KeyCode::Enter => app.confirm_search(),
            KeyCode::Backspace => app.search_pop(),
            KeyCode::Char(ch) => app.search_push(ch),
            _ => {}
        }
        return false;
    }

    // Go-to-packet input mode.
    if app.input_mode == InputMode::GoToPacket {
        match code {
            KeyCode::Esc => app.cancel_goto(),
            KeyCode::Enter => app.confirm_goto(),
            KeyCode::Backspace => app.goto_pop(),
            KeyCode::Char(ch) => app.goto_push(ch),
            _ => {}
        }
        return false;
    }

    // Annotation input mode.
    if app.annotating.is_some() {
        match code {
            KeyCode::Esc => app.cancel_annotate(),
            KeyCode::Enter => app.confirm_annotate(),
            KeyCode::Backspace => app.annotate_pop(),
            KeyCode::Char(ch) => app.annotate_push(ch),
            _ => {}
        }
        return false;
    }

    // Display filter input mode.
    if app.display_filter_editing {
        match code {
            KeyCode::Esc => app.cancel_display_filter(),
            KeyCode::Enter => app.confirm_display_filter(),
            KeyCode::Backspace => app.display_filter_pop(),
            KeyCode::Char(ch) => app.display_filter_push(ch),
            _ => {}
        }
        return false;
    }

    // Help overlay — Esc or ? closes it.
    if app.show_help {
        match code {
            KeyCode::Esc | KeyCode::Char('?' | 'q') => app.show_help = false,
            _ => {}
        }
        return false;
    }

    // Stats summary overlay.
    if app.show_stats_summary {
        match code {
            KeyCode::Esc | KeyCode::Char('I' | 'q') => app.show_stats_summary = false,
            _ => {}
        }
        return false;
    }

    // Expert info overlay.
    if app.show_expert {
        match code {
            KeyCode::Esc | KeyCode::Char('E' | 'q') => app.show_expert = false,
            _ => {}
        }
        return false;
    }

    // Protocol hierarchy overlay.
    if app.show_proto_hierarchy {
        match code {
            KeyCode::Esc | KeyCode::Char('H' | 'q') => app.show_proto_hierarchy = false,
            _ => {}
        }
        return false;
    }

    // Flow graph overlay.
    if app.show_flow_graph {
        match code {
            KeyCode::Esc | KeyCode::Char('G' | 'q') => app.show_flow_graph = false,
            KeyCode::Char('j') | KeyCode::Down => {
                let count = app.flow_graph_packet_indices().len();
                if count > 0 && app.flow_graph_selected < count - 1 {
                    app.flow_graph_selected += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                app.flow_graph_selected = app.flow_graph_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                let indices = app.flow_graph_packet_indices();
                if let Some(&pkt_idx) = indices.get(app.flow_graph_selected) {
                    app.show_flow_graph = false;
                    app.paused = true;
                    app.selected = pkt_idx;
                    app.view = View::Detail;
                    app.hex_scroll = 0;
                }
            }
            _ => {}
        }
        return false;
    }

    // Diff overlay.
    if app.diff_pair.is_some() {
        match code {
            KeyCode::Esc | KeyCode::Char('x' | 'q') => app.diff_pair = None,
            _ => {}
        }
        return false;
    }

    match app.view {
        View::List => handle_list_key(app, code),
        View::Detail => {
            handle_detail_key(app, code);
            false
        }
        View::Flows => {
            handle_flows_key(app, code);
            false
        }
        View::Stream => {
            handle_stream_key(app, code);
            false
        }
    }
}

/// Returns `true` if the app should quit.
fn handle_list_key(app: &mut App, code: KeyCode) -> bool {
    match code {
        KeyCode::Char('q') => return true,
        KeyCode::Char('j') | KeyCode::Down => app.next(),
        KeyCode::Char('k') | KeyCode::Up => app.previous(),
        KeyCode::Char('G') | KeyCode::End => app.last(),
        KeyCode::Char('g') | KeyCode::Home => app.first(),
        KeyCode::PageDown | KeyCode::Char('d') => app.page_down(),
        KeyCode::PageUp | KeyCode::Char('u') => app.page_up(),
        KeyCode::Enter => app.open_detail(),
        KeyCode::Char(' ') => app.toggle_pause(),
        KeyCode::Char('c') => app.clear(),
        KeyCode::Char('t') => app.next_theme(),
        KeyCode::Char('/') => app.start_search(),
        KeyCode::Char('f') => app.next_proto_filter(),
        KeyCode::Char('F') => app.cycle_follow_speed(),
        KeyCode::Char('p') => {
            if let Ok(procs) = process::list_network_processes() {
                app.open_process_picker(procs);
            }
        }
        KeyCode::Char('P') => app.clear_process_filter(),
        KeyCode::Char('w') => {
            let msg = app.export_packets();
            app.set_status(msg);
        }
        KeyCode::Char('n') => app.open_flows(),
        KeyCode::Char('N') => app.clear_flow_filter(),
        KeyCode::Char('i') => {
            if let Ok(ifaces) = capture::list_interfaces() {
                app.open_interface_picker(ifaces);
            }
        }
        KeyCode::Char('m') => app.toggle_bookmark(),
        KeyCode::Char('\'') => app.jump_next_bookmark(),
        KeyCode::Char('"') => app.jump_prev_bookmark(),
        KeyCode::Char('D') => {
            app.dns_enabled = !app.dns_enabled;
            let state = if app.dns_enabled { "on" } else { "off" };
            app.set_status(format!("DNS resolution {state}"));
        }
        KeyCode::Tab => app.next_resize_column(),
        KeyCode::Char('>') => app.widen_column(),
        KeyCode::Char('<') => app.narrow_column(),
        KeyCode::Char('?') => app.show_help = true,
        KeyCode::Char('I') => app.show_stats_summary = true,
        KeyCode::Char('E') => app.show_expert = true,
        KeyCode::Char('H') => app.show_proto_hierarchy = true,
        KeyCode::Char('x') => app.mark_or_diff(),
        KeyCode::Char('a') => app.start_annotate(),
        KeyCode::Char('\\') => app.start_display_filter(),
        KeyCode::Char('T') => app.cycle_time_format(),
        KeyCode::Char('R') => app.toggle_time_reference(),
        KeyCode::Char(':') => app.start_goto(),
        KeyCode::Char('X') => {
            if let Some(ref path) = app.socket_path {
                let msg = match clipboard::copy_to_clipboard(path) {
                    Ok(()) => format!("Socket copied: {path}"),
                    Err(_) => format!("Socket: {path}"),
                };
                app.set_status(msg);
            } else {
                app.pending_socket_create = true;
            }
        }
        KeyCode::Char('A') => {
            if app.agent_name.is_some() {
                app.show_agent_pane = !app.show_agent_pane;
            } else {
                app.open_agent_picker();
            }
        }
        KeyCode::Char('J') if app.show_agent_pane => {
            app.agent_scroll = app.agent_scroll.saturating_sub(1);
        }
        KeyCode::Char('K') if app.show_agent_pane => {
            let total = app.agent_output.lock().map_or(0, |o| o.len());
            if app.agent_scroll < total {
                app.agent_scroll += 1;
            }
        }
        _ => {}
    }
    false
}

fn handle_flows_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.close_flows(),
        KeyCode::Char('j') | KeyCode::Down => app.flow_next(),
        KeyCode::Char('k') | KeyCode::Up => app.flow_prev(),
        KeyCode::Enter => app.flow_select(),
        KeyCode::Char('G') => {
            app.flow_graph_selected = 0;
            app.show_flow_graph = true;
        }
        KeyCode::Char('t') => app.next_theme(),
        _ => {}
    }
}

fn handle_detail_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.close_detail(),
        KeyCode::Char('j') | KeyCode::Down => app.scroll_down(),
        KeyCode::Char('k') | KeyCode::Up => app.scroll_up(),
        KeyCode::Char('t') => app.next_theme(),
        KeyCode::Char('w') => {
            let msg = app.export_packets();
            app.set_status(msg);
        }
        KeyCode::Char('y') => {
            let msg = if let Some(pkt) = app.selected_packet() {
                let dump = hex::hex_dump_plain(&pkt.data);
                match clipboard::copy_to_clipboard(&dump) {
                    Ok(()) => "Hex dump copied".into(),
                    Err(e) => format!("Copy failed: {e}"),
                }
            } else {
                "No packet selected".into()
            };
            app.set_status(msg);
        }
        KeyCode::Char('Y') => {
            let msg = if let Some(pkt) = app.selected_packet() {
                let s = hex::hex_string(&pkt.data);
                match clipboard::copy_to_clipboard(&s) {
                    Ok(()) => "Raw hex copied".into(),
                    Err(e) => format!("Copy failed: {e}"),
                }
            } else {
                "No packet selected".into()
            };
            app.set_status(msg);
        }
        KeyCode::Char('S') => app.open_stream(),
        _ => {}
    }
}

fn handle_stream_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.close_stream(),
        KeyCode::Char('j') | KeyCode::Down => app.stream_scroll_down(),
        KeyCode::Char('k') | KeyCode::Up => app.stream_scroll_up(),
        KeyCode::Char('t') => app.next_theme(),
        KeyCode::Char('y') => {
            let msg = if app.stream_data.is_empty() {
                "No stream data".into()
            } else {
                let dump = hex::hex_dump_plain(&app.stream_data);
                match clipboard::copy_to_clipboard(&dump) {
                    Ok(()) => "Stream hex dump copied".into(),
                    Err(e) => format!("Copy failed: {e}"),
                }
            };
            app.set_status(msg);
        }
        _ => {}
    }
}
