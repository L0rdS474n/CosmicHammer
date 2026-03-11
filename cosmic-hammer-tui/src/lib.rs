#![forbid(unsafe_code)]

pub mod app;
pub mod input;
pub mod layout;
pub mod theme;
pub mod widgets;

use std::io;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use cosmic_hammer_core::{fmt_duration, CosmicError, FlipEvent};
use crossterm::event::{self, Event};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use crate::app::App;
use crate::layout::build_layout;
use crate::widgets::{flip_log, header, heatmap, region_map, stats};

/// Messages sent from the scanner to the TUI via an mpsc channel.
#[derive(Debug)]
pub enum TuiMessage {
    /// A bit-flip was detected.
    FlipDetected(FlipEvent),
    /// A scan cycle completed.
    ScanComplete,
    /// The scanner is shutting down; the TUI should exit.
    Shutdown,
}

/// Default region size in MB used for display purposes.
/// This matches the default 512 MB arena / 5 regions.
const DEFAULT_REGION_SIZE_MB: u64 = 102;

/// Runs the fullscreen TUI dashboard.
///
/// The TUI receives events from the scanner through an `mpsc::Receiver<TuiMessage>`.
/// It initializes the terminal in raw mode with an alternate screen, runs the
/// event loop, and restores the terminal on exit.
pub fn run_tui(rx: Receiver<TuiMessage>) -> Result<(), CosmicError> {
    // Initialize terminal
    enable_raw_mode().map_err(CosmicError::Io)?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).map_err(CosmicError::Io)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(CosmicError::Io)?;

    let mut app = App::new();

    let result = run_event_loop(&mut terminal, &mut app, &rx);

    // Restore terminal regardless of result
    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    result
}

/// The main event loop: polls crossterm events and TUI messages, renders frames.
fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    rx: &Receiver<TuiMessage>,
) -> Result<(), CosmicError> {
    let poll_timeout = Duration::from_millis(250);

    while app.is_running() {
        // Draw the current frame
        terminal
            .draw(|frame| {
                let layout = build_layout(frame.area());

                let uptime_secs = app.uptime().as_secs() as i64;
                let uptime_str = fmt_duration(uptime_secs);

                header::render_header(
                    frame,
                    layout.header,
                    &uptime_str,
                    app.scan_count,
                    app.flip_count(),
                );

                region_map::render_region_map(
                    frame,
                    layout.left_top,
                    &app.region_stats,
                    DEFAULT_REGION_SIZE_MB,
                );

                heatmap::render_heatmap(frame, layout.left_bottom, &app.events);

                flip_log::render_flip_log(
                    frame,
                    layout.right_top,
                    &app.events,
                    app.selected_event,
                    app.scroll_offset,
                );

                stats::render_stats(frame, layout.right_bottom, &app.stats);

                // Footer
                render_footer(frame, layout.footer, app);
            })
            .map_err(CosmicError::Io)?;

        // Poll for crossterm keyboard events
        if event::poll(poll_timeout).map_err(CosmicError::Io)? {
            if let Event::Key(key) = event::read().map_err(CosmicError::Io)? {
                app.on_key(key);
            }
        }

        // Drain all pending TUI messages from the channel
        while let Ok(msg) = rx.try_recv() {
            match msg {
                TuiMessage::FlipDetected(flip_event) => {
                    app.add_event(flip_event);
                }
                TuiMessage::ScanComplete => {
                    app.increment_scans();
                }
                TuiMessage::Shutdown => {
                    app.running = false;
                }
            }
        }
    }

    Ok(())
}

/// Renders the footer bar with key hints and panel focus indicator.
fn render_footer(frame: &mut ratatui::Frame, area: ratatui::layout::Rect, app: &App) {
    use ratatui::style::{Color, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Paragraph};

    let focus_name = match app.focus {
        app::FocusPanel::FlipLog => "Flip Log",
        app::FocusPanel::RegionMap => "Region Map",
    };

    let line = Line::from(vec![
        Span::styled(
            format!(" [Tab] {focus_name} "),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw("| "),
        Span::styled("[Up/Down] scroll ", Style::default().fg(Color::White)),
        Span::raw("| "),
        Span::styled("[q] quit ", Style::default().fg(Color::DarkGray)),
    ]);

    let footer = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(footer, area);
}

/// Prints a flip event in headless mode (no TUI), matching the C console output format.
///
/// Format: `[FLIP] offset=0x... bit=N dir=0>1 class=CLASS_NAME region=REGION_NAME`
pub fn print_headless_flip(event: &FlipEvent) {
    eprintln!(
        "[FLIP] offset=0x{:012x} bit={} dir={} class={} region={} dram_row={}",
        event.offset,
        event.bit_position,
        event.direction,
        event.flip_class.name(),
        event.region.name(),
        event.dram_row,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic_hammer_core::{FlipClass, FlipDirection, RegionType};

    fn make_test_event() -> FlipEvent {
        FlipEvent {
            timestamp: 52320, // 14:32:00
            offset: 0x01a3f000,
            bit_position: 52,
            expected: 0x00007FFF12345678,
            observed: 0x00007FFF12345679,
            direction: FlipDirection::ZeroToOne,
            n_bits: 1,
            region: RegionType::PteSim,
            flip_class: FlipClass::PteNxClear,
            dram_row: 512,
        }
    }

    #[test]
    fn given_tui_message_flip_detected_when_matched_then_contains_event() {
        let event = make_test_event();
        let msg = TuiMessage::FlipDetected(event);
        match msg {
            TuiMessage::FlipDetected(e) => {
                assert_eq!(e.flip_class, FlipClass::PteNxClear);
            }
            _ => panic!("expected FlipDetected"),
        }
    }

    #[test]
    fn given_tui_message_scan_complete_when_matched_then_variant_correct() {
        let msg = TuiMessage::ScanComplete;
        assert!(matches!(msg, TuiMessage::ScanComplete));
    }

    #[test]
    fn given_tui_message_shutdown_when_matched_then_variant_correct() {
        let msg = TuiMessage::Shutdown;
        assert!(matches!(msg, TuiMessage::Shutdown));
    }

    #[test]
    fn given_flip_event_when_print_headless_then_no_panic() {
        // This test verifies that print_headless_flip does not panic.
        // Output goes to stderr so we cannot easily capture it in a unit test,
        // but we verify no runtime error occurs.
        let event = make_test_event();
        print_headless_flip(&event);
    }
}
