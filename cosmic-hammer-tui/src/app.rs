use cosmic_hammer_core::RegionType;
use cosmic_hammer_core::{FlipClass, FlipEvent, MAX_FLIPS};
use crossterm::event::KeyEvent;
use std::time::{Duration, Instant};

use crate::input::{self, Action};

/// Which panel currently has focus for scrolling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPanel {
    FlipLog,
    RegionMap,
}

impl FocusPanel {
    pub fn next(self) -> Self {
        match self {
            Self::FlipLog => Self::RegionMap,
            Self::RegionMap => Self::FlipLog,
        }
    }
}

/// Core application state for the TUI dashboard.
pub struct App {
    pub events: Vec<FlipEvent>,
    pub scan_count: u64,
    pub start_time: Instant,
    pub selected_event: usize,
    pub scroll_offset: usize,
    pub running: bool,
    pub stats: [u64; FlipClass::COUNT],
    pub region_stats: [u64; RegionType::COUNT],
    pub focus: FocusPanel,
}

impl App {
    /// Creates a new App with default initial state.
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            scan_count: 0,
            start_time: Instant::now(),
            selected_event: 0,
            scroll_offset: 0,
            running: true,
            stats: [0; FlipClass::COUNT],
            region_stats: [0; RegionType::COUNT],
            focus: FocusPanel::FlipLog,
        }
    }

    /// Adds a flip event and updates the stats arrays.
    /// Events are capped at MAX_FLIPS; oldest events are dropped.
    pub fn add_event(&mut self, event: FlipEvent) {
        self.stats[event.flip_class as usize] += 1;
        self.region_stats[event.region as usize] += 1;

        self.events.insert(0, event); // newest first

        if self.events.len() > MAX_FLIPS {
            self.events.truncate(MAX_FLIPS);
        }
    }

    /// Increments the scan cycle counter.
    pub fn increment_scans(&mut self) {
        self.scan_count = self.scan_count.saturating_add(1);
    }

    /// Returns the elapsed time since the app started.
    pub fn uptime(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Handles a keyboard event by mapping it to an action.
    pub fn on_key(&mut self, key: KeyEvent) {
        if let Some(action) = input::map_key(key) {
            match action {
                Action::Quit => {
                    self.running = false;
                }
                Action::ScrollUp => {
                    if self.selected_event > 0 {
                        self.selected_event -= 1;
                    }
                    self.adjust_scroll();
                }
                Action::ScrollDown => {
                    if !self.events.is_empty() && self.selected_event < self.events.len() - 1 {
                        self.selected_event += 1;
                    }
                    self.adjust_scroll();
                }
                Action::NextPanel => {
                    self.focus = self.focus.next();
                }
            }
        }
    }

    /// Returns whether the application is still running.
    pub fn is_running(&self) -> bool {
        self.running
    }

    /// Returns the total number of detected flip events.
    pub fn flip_count(&self) -> usize {
        self.events.len()
    }

    /// Adjusts scroll_offset to keep selected_event visible.
    fn adjust_scroll(&mut self) {
        // We keep a simple invariant: scroll_offset <= selected_event
        if self.selected_event < self.scroll_offset {
            self.scroll_offset = self.selected_event;
        }
        // We don't know visible height here, so just ensure offset doesn't exceed selected
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic_hammer_core::{FlipClass, FlipDirection, FlipEvent, RegionType};
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn make_key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn make_event(class: FlipClass, region: RegionType) -> FlipEvent {
        FlipEvent {
            timestamp: 1_700_000_000,
            offset: 4096,
            bit_position: 7,
            expected: 0x00007FFF12345678,
            observed: 0x00007FFF12345679,
            direction: FlipDirection::ZeroToOne,
            n_bits: 1,
            region,
            flip_class: class,
            dram_row: 512,
        }
    }

    #[test]
    fn given_new_app_when_created_then_running() {
        let app = App::new();
        assert!(app.is_running());
        assert_eq!(app.scan_count, 0);
        assert_eq!(app.events.len(), 0);
        assert_eq!(app.selected_event, 0);
    }

    #[test]
    fn given_app_when_add_event_then_event_stored_and_stats_updated() {
        let mut app = App::new();
        app.add_event(make_event(FlipClass::PtrHijack, RegionType::Pointer));

        assert_eq!(app.events.len(), 1);
        assert_eq!(app.stats[FlipClass::PtrHijack as usize], 1);
        assert_eq!(app.region_stats[RegionType::Pointer as usize], 1);
    }

    #[test]
    fn given_app_when_add_multiple_events_then_newest_first() {
        let mut app = App::new();
        let mut e1 = make_event(FlipClass::Benign, RegionType::Data);
        e1.timestamp = 100;
        let mut e2 = make_event(FlipClass::DataCorrupt, RegionType::Data);
        e2.timestamp = 200;

        app.add_event(e1);
        app.add_event(e2);

        assert_eq!(app.events[0].timestamp, 200); // newest first
        assert_eq!(app.events[1].timestamp, 100);
    }

    #[test]
    fn given_app_when_increment_scans_then_count_increases() {
        let mut app = App::new();
        app.increment_scans();
        app.increment_scans();
        assert_eq!(app.scan_count, 2);
    }

    #[test]
    fn given_app_when_q_pressed_then_not_running() {
        let mut app = App::new();
        app.on_key(make_key(KeyCode::Char('q')));
        assert!(!app.is_running());
    }

    #[test]
    fn given_app_with_events_when_down_pressed_then_selected_increments() {
        let mut app = App::new();
        app.add_event(make_event(FlipClass::Benign, RegionType::Data));
        app.add_event(make_event(FlipClass::Benign, RegionType::Data));

        app.on_key(make_key(KeyCode::Down));
        assert_eq!(app.selected_event, 1);
    }

    #[test]
    fn given_app_at_first_event_when_up_pressed_then_stays_at_zero() {
        let mut app = App::new();
        app.add_event(make_event(FlipClass::Benign, RegionType::Data));

        app.on_key(make_key(KeyCode::Up));
        assert_eq!(app.selected_event, 0);
    }

    #[test]
    fn given_app_when_tab_pressed_then_focus_changes() {
        let mut app = App::new();
        assert_eq!(app.focus, FocusPanel::FlipLog);

        app.on_key(make_key(KeyCode::Tab));
        assert_eq!(app.focus, FocusPanel::RegionMap);

        app.on_key(make_key(KeyCode::Tab));
        assert_eq!(app.focus, FocusPanel::FlipLog);
    }

    #[test]
    fn given_app_when_uptime_called_then_returns_duration() {
        let app = App::new();
        let uptime = app.uptime();
        // Just verify it is non-negative (it always is for Duration)
        assert!(uptime.as_secs() < 10); // test runs fast
    }

    #[test]
    fn given_app_at_last_event_when_down_pressed_then_stays_at_last() {
        let mut app = App::new();
        app.add_event(make_event(FlipClass::Benign, RegionType::Data));
        // Only one event at index 0; pressing down should stay at 0
        app.on_key(make_key(KeyCode::Down));
        assert_eq!(app.selected_event, 0);
    }

    #[test]
    fn given_empty_app_when_down_pressed_then_no_panic() {
        let mut app = App::new();
        app.on_key(make_key(KeyCode::Down)); // should not panic
        assert_eq!(app.selected_event, 0);
    }
}
