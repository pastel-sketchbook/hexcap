mod app;
mod capture;
mod clipboard;
mod config;
mod export;
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
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{ExecutableCommand, execute};
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(io::stderr)
        .init();

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
    let capture = CaptureHandle::start(
        cli.interface.as_deref(),
        cli.filter.as_deref(),
        Arc::clone(&app),
    )?;

    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let result = run_loop(&mut terminal, &app);

    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    drop(capture);

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &Arc<Mutex<App>>,
) -> Result<()> {
    let mut refresh_counter: u32 = 0;
    loop {
        {
            let mut app = app.lock().expect("app mutex poisoned");
            app.tick_status();
            refresh_counter += 1;
            if refresh_counter >= 100 {
                refresh_counter = 0;
                app.refresh_process_ports();
            }
            terminal.draw(|f| ui::render(f, &app))?;
        }

        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            let mut app = app.lock().expect("app mutex poisoned");
            if handle_key(&mut app, key.code) {
                return Ok(());
            }
        }
    }
}

/// Returns `true` if the app should quit.
fn handle_key(app: &mut App, code: KeyCode) -> bool {
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
        KeyCode::Enter => app.open_detail(),
        KeyCode::Char(' ') => app.toggle_pause(),
        KeyCode::Char('c') => app.clear(),
        KeyCode::Char('t') => app.next_theme(),
        KeyCode::Char('/') => app.start_search(),
        KeyCode::Char('f') => app.next_proto_filter(),
        KeyCode::Char('F') => app.toggle_follow(),
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
        _ => {}
    }
}
