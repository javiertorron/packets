pub mod app;
pub mod capture;
pub mod detector;
pub mod pedagogy;
pub mod parse;
pub mod profiler;
pub mod ui;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{error::Error, io, sync::mpsc, thread, time::Duration};

use app::App;

fn main() -> Result<(), Box<dyn Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create channel for packet capture
    let (tx, rx) = mpsc::channel();

    // Start capture thread
    thread::spawn(move || {
        if let Err(e) = capture::start_capture(tx) {
            eprintln!("Capture error: {}", e);
        }
    });

    // Create app state
    let mut app = App::new();

    // Run main loop
    let res = run_app(&mut terminal, &mut app, rx);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    rx: mpsc::Receiver<capture::PacketInfo>,
) -> io::Result<()> {
    loop {
        // Handle new packets from the channel
        while let Ok(packet) = rx.try_recv() {
            app.add_packet(packet);
        }

        // Draw UI
        terminal.draw(|f| ui::draw(f, app))?;

        // Handle input events (non-blocking with timeout)
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Up => app.previous_alert(),
                    KeyCode::Down => app.next_alert(),
                    KeyCode::Enter => app.toggle_pedagogy(),
                    KeyCode::Tab => app.next_tab(),
                    _ => {}
                }
            }
        }
    }
}
