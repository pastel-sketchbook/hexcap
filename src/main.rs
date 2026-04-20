mod app;
mod capture;
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
            // Mutex poisoning means the capture thread panicked — unrecoverable.
            let mut app = app.lock().expect("app mutex poisoned");

            // Clear expired status messages.
            app.tick_status();

            // Refresh process ports every ~5s (100 × 50ms).
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

            // Mutex poisoning means the capture thread panicked — unrecoverable.
            let mut app = app.lock().expect("app mutex poisoned");

            // Process picker overlay — intercept keys first.
            if app.process_picker.is_some() {
                match key.code {
                    KeyCode::Esc => app.close_process_picker(),
                    KeyCode::Enter => app.picker_select(),
                    KeyCode::Down | KeyCode::Char('j') => app.picker_next(),
                    KeyCode::Up | KeyCode::Char('k') => app.picker_prev(),
                    KeyCode::Backspace => app.picker_pop(),
                    KeyCode::Char(ch) => app.picker_push(ch),
                    _ => {}
                }
                continue;
            }

            // Search input mode — intercept keys first.
            if app.input_mode == InputMode::Search {
                match key.code {
                    KeyCode::Esc => app.cancel_search(),
                    KeyCode::Enter => app.confirm_search(),
                    KeyCode::Backspace => app.search_pop(),
                    KeyCode::Char(ch) => app.search_push(ch),
                    _ => {}
                }
                continue;
            }

            match app.view {
                View::List => match key.code {
                    KeyCode::Char('q') => return Ok(()),
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
                    _ => {}
                },
                View::Detail => match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => app.close_detail(),
                    KeyCode::Char('j') | KeyCode::Down => app.scroll_down(),
                    KeyCode::Char('k') | KeyCode::Up => app.scroll_up(),
                    KeyCode::Char('t') => app.next_theme(),
                    KeyCode::Char('w') => {
                        let msg = app.export_packets();
                        app.set_status(msg);
                    }
                    _ => {}
                },
            }
        }
    }
}
