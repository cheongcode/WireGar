mod app;
mod views;
mod ui;

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use app::{App, Tab};
use wirehunt_core::models::Report;

#[derive(Parser)]
#[command(
    name = "wirehunt-tui",
    about = "WireHunt TUI - interactive network forensic analysis",
    version,
)]
struct Cli {
    /// Path to a case directory (containing report.json) or a report.json file directly
    pub path: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let report_path = if cli.path.is_dir() {
        cli.path.join("report.json")
    } else {
        cli.path
    };

    let report_data = std::fs::read_to_string(&report_path)
        .with_context(|| format!("cannot read {}", report_path.display()))?;
    let report: Report = serde_json::from_str(&report_data)
        .with_context(|| "failed to parse report.json")?;

    let mut app = App::new(report);

    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    // Main loop
    let result = run_loop(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    while app.running {
        terminal.draw(|frame| {
            ui::render(frame, app);
        })?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    app.running = false;
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') => {
                        if app.stream_detail_index.is_some() || app.show_help {
                            app.escape();
                        } else {
                            app.running = false;
                        }
                    }
                    KeyCode::Char('?') => app.show_help = !app.show_help,
                    KeyCode::Tab => app.next_tab(),
                    KeyCode::BackTab => app.prev_tab(),
                    KeyCode::Char('1') => app.set_tab(Tab::Dashboard),
                    KeyCode::Char('2') => app.set_tab(Tab::Flows),
                    KeyCode::Char('3') => app.set_tab(Tab::Streams),
                    KeyCode::Char('4') => app.set_tab(Tab::Artifacts),
                    KeyCode::Char('5') => app.set_tab(Tab::Credentials),
                    KeyCode::Char('6') => app.set_tab(Tab::DnsLog),
                    KeyCode::Char('7') => app.set_tab(Tab::HttpLog),
                    KeyCode::Char('j') | KeyCode::Down => app.scroll_down(),
                    KeyCode::Char('k') | KeyCode::Up => app.scroll_up(),
                    KeyCode::Char('d') | KeyCode::PageDown => app.page_down(),
                    KeyCode::Char('u') | KeyCode::PageUp => app.page_up(),
                    KeyCode::Char('g') => app.go_top(),
                    KeyCode::Char('G') => app.go_bottom(),
                    KeyCode::Enter => app.enter(),
                    KeyCode::Esc => app.escape(),
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
