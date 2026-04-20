mod app;
mod capture;
mod clipboard;
mod config;
mod dns;
mod export;
mod geoip;
mod headless;
mod hex;
mod packet;
mod process;
mod theme;
mod ui;

use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::*;

use app::{App, InputMode, View};
use capture::CaptureHandle;

/// hexcap — TUI packet capture with libpcap + hexyl-style hex dump
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Network interface to capture on (e.g. en0, eth0)
    #[arg(short, long)]
    interface: Option<String>,

    /// BPF filter expression (e.g. "tcp port 80")
    #[arg(short, long)]
    filter: Option<String>,

    /// Maximum number of packets to keep in the ring buffer
    #[arg(long, default_value_t = 10_000)]
    max_packets: usize,

    /// Filter packets by process name or PID
    #[arg(short, long)]
    process: Option<String>,

    /// Write captured packets to a pcap file on exit or when pressing 'w'
    #[arg(short, long)]
    write: Option<String>,

    /// Read packets from a pcap file instead of live capture
    #[arg(short, long)]
    read: Option<String>,

    /// Path to `GeoLite2-City.mmdb` or `GeoLite2-Country.mmdb` for `GeoIP` lookups
    #[arg(long)]
    geoip: Option<String>,

    /// Output JSON instead of TUI (JSONL for live capture, JSON array for --read)
    #[arg(long)]
    json: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Read and decode a pcap file to JSON
    Read {
        /// Path to the pcap file
        file: String,
        /// Display filter expression (e.g. "tcp port:443 !arp")
        #[arg(short, long)]
        filter: Option<String>,
        /// Maximum number of packets to output (0 = all)
        #[arg(short = 'n', long, default_value_t = 0)]
        limit: usize,
    },
    /// Capture packets headless and output as JSONL
    Capture {
        /// Network interface (comma-separated for multiple)
        #[arg(short, long)]
        interface: Option<String>,
        /// BPF filter expression
        #[arg(short, long)]
        filter: Option<String>,
        /// Number of packets to capture (0 = unlimited)
        #[arg(short = 'c', long, default_value_t = 100)]
        count: usize,
        /// Display filter expression
        #[arg(short, long)]
        display_filter: Option<String>,
    },
    /// Extract connection flows from a pcap file
    Flows {
        /// Path to the pcap file
        file: String,
    },
    /// Show capture statistics from a pcap file
    Stats {
        /// Path to the pcap file
        file: String,
    },
    /// Follow a TCP stream from a pcap file
    Stream {
        /// Path to the pcap file
        file: String,
        /// Flow to follow (e.g. "10.0.0.1:443-10.0.0.2:52100")
        #[arg(long)]
        flow: Option<String>,
    },
    /// Decode a single packet from a pcap file
    Decode {
        /// Path to the pcap file
        file: String,
        /// Packet ID (1-based)
        #[arg(long)]
        id: u64,
    },
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(io::stderr)
        .init();

    // ── Subcommand dispatch (headless, JSON output) ────────────────────
    if let Some(cmd) = cli.command {
        return match cmd {
            Command::Read {
                file,
                filter,
                limit,
            } => headless::cmd_read(&file, filter.as_deref(), limit),
            Command::Capture {
                interface,
                filter,
                count,
                display_filter,
            } => headless::cmd_capture(
                interface.as_deref(),
                filter.as_deref(),
                count,
                display_filter.as_deref(),
            ),
            Command::Flows { file } => headless::cmd_flows(&file),
            Command::Stats { file } => headless::cmd_stats(&file),
            Command::Stream { file, flow } => headless::cmd_stream(&file, flow.as_deref()),
            Command::Decode { file, id } => headless::cmd_decode(&file, id),
        };
    }

    // ── --json flag on root CLI ────────────────────────────────────────
    if cli.json {
        return if let Some(ref path) = cli.read {
            headless::cmd_json_read(path)
        } else {
            headless::cmd_json_live(
                cli.interface.as_deref(),
                cli.filter.as_deref(),
                cli.max_packets,
            )
        };
    }

    // ── TUI mode (default) ────────────────────────────────────────────

    // Resolve --process flag to a port-based filter.
    let process_filter = if let Some(ref query) = cli.process {
        let info = process::resolve_process(query)?;
        tracing::info!(
            pid = info.pid,
            name = %info.name,
            ports = ?info.ports,
            "filtering by process"
        );
        Some(app::ProcessFilter {
            name: info.name,
            pid: info.pid,
            ports: info.ports,
        })
    } else {
        None
    };

    let app = Arc::new(Mutex::new(App::new(
        cli.max_packets,
        process_filter,
        cli.write.map(std::path::PathBuf::from),
    )));

    // Load GeoIP database if provided, or auto-detect common filenames.
    let geoip_path = cli.geoip.clone().or_else(|| {
        let candidates = [
            "country.mmdb",
            "GeoLite2-Country.mmdb",
            "GeoLite2-City.mmdb",
        ];
        candidates
            .iter()
            .find(|p| std::path::Path::new(p).exists())
            .map(|p| p.to_string())
    });
    let geoip_db = if let Some(ref path) = geoip_path {
        match geoip::GeoDb::open(std::path::Path::new(path)) {
            Ok(db) => {
                if let Ok(mut a) = app.lock() {
                    a.geoip_enabled = true;
                    a.set_status("GeoIP database loaded".into());
                }
                Some(Arc::new(db))
            }
            Err(e) => {
                tracing::warn!("Failed to load GeoIP database: {e}");
                None
            }
        }
    } else {
        None
    };

    // Either read from pcap file or start live capture.
    // Mutex poisoning policy: if any thread panics while holding the App
    // mutex, recovery is not possible — the TUI state is inconsistent.
    // All `.expect("app mutex poisoned")` calls intentionally propagate the panic.
    let (mut capture, capture_group) = if let Some(ref path) = cli.read {
        let raw_packets = export::read_pcap(std::path::Path::new(path))?;
        let mut a = app.lock().expect("app mutex poisoned");
        for (i, (timestamp, data)) in raw_packets.into_iter().enumerate() {
            let mut pkt = packet::parse_packet((i + 1) as u64, &data);
            pkt.timestamp = timestamp;
            a.push_packet(pkt);
        }
        a.paused = true; // No live capture, start paused.
        a.interface_name.clone_from(path);
        // Load bookmarks sidecar if present.
        let pcap_path = std::path::Path::new(path);
        let bm_path = export::bookmark_path(pcap_path);
        if bm_path.exists() {
            match export::load_bookmarks(&bm_path) {
                Ok(bm) => {
                    let count = bm.len();
                    a.bookmarks = bm;
                    if count > 0 {
                        a.set_status(format!("Loaded {count} bookmarks"));
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to load bookmarks: {e}");
                }
            }
        }
        // Load annotations sidecar if present.
        let ann_path = export::annotation_path(pcap_path);
        if ann_path.exists() {
            match export::load_annotations(&ann_path) {
                Ok(ann) => {
                    let count = ann.len();
                    a.annotations = ann;
                    if count > 0 {
                        let prev = a.status_message.as_ref().map(|(m, _)| m.clone());
                        let msg = if let Some(prev_msg) = prev {
                            format!("{prev_msg}, {count} annotations")
                        } else {
                            format!("Loaded {count} annotations")
                        };
                        a.set_status(msg);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to load annotations: {e}");
                }
            }
        }
        drop(a);
        (None, None)
    } else if let Some(ref iface) = cli.interface {
        if iface.contains(',') {
            // Multi-interface capture.
            let names: Vec<String> = iface.split(',').map(|s| s.trim().to_string()).collect();
            let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let group = capture::CaptureGroup::start(
                &names,
                cli.filter.as_deref(),
                Arc::clone(&app),
                counter,
            )?;
            (None, Some(group))
        } else {
            let h = CaptureHandle::start(
                Some(iface.as_str()),
                cli.filter.as_deref(),
                Arc::clone(&app),
            )?;
            (Some(h), None)
        }
    } else {
        let h = CaptureHandle::start(None, cli.filter.as_deref(), Arc::clone(&app))?;
        (Some(h), None)
    };

    let bpf_filter = cli.filter.clone();

    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(
        &mut terminal,
        &app,
        &mut capture,
        bpf_filter.as_deref(),
        geoip_db.as_ref(),
    );

    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;
    drop(capture);
    drop(capture_group);

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &Arc<Mutex<App>>,
    capture: &mut Option<CaptureHandle>,
    bpf_filter: Option<&str>,
    geoip_db: Option<&Arc<geoip::GeoDb>>,
) -> Result<()> {
    let mut refresh_counter: u32 = 0;
    let mut dns_counter: u32 = 0;
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
            match CaptureHandle::start(Some(&iface), bpf_filter, Arc::clone(app)) {
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

        {
            let mut app_guard = app.lock().expect("app mutex poisoned");
            app_guard.tick_status();
            app_guard.tick_bandwidth();
            refresh_counter += 1;
            if refresh_counter >= 100 {
                refresh_counter = 0;
                app_guard.refresh_process_ports();
            }
            // Periodic DNS resolution (~every 5 seconds = 100 ticks).
            dns_counter += 1;
            if dns_counter >= 100 && app_guard.dns_enabled {
                dns_counter = 0;
                // Collect unique addresses for resolution.
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

        // Re-draw if we dropped the guard early for DNS.
        // (The DNS branch skipped the draw, so draw now.)

        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }
                    let mut app_guard = app.lock().expect("app mutex poisoned");
                    if handle_key(&mut app_guard, key.code) {
                        return Ok(());
                    }
                }
                Event::Mouse(mouse) => {
                    let mut app_guard = app.lock().expect("app mutex poisoned");
                    handle_mouse(&mut app_guard, mouse.kind);
                }
                _ => {}
            }
        }
    }
}

/// Handle mouse events.
fn handle_mouse(app: &mut App, kind: MouseEventKind) {
    match kind {
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
fn handle_key(app: &mut App, code: KeyCode) -> bool {
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
        KeyCode::Char('x') => app.mark_or_diff(),
        KeyCode::Char('a') => app.start_annotate(),
        KeyCode::Char('\\') => app.start_display_filter(),
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
