use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Actions that can be triggered by keyboard input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Quit,
    ScrollUp,
    ScrollDown,
    NextPanel,
}

/// Maps a crossterm KeyEvent to an optional Action.
pub fn map_key(key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => Some(Action::Quit),
        KeyCode::Esc => Some(Action::Quit),
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Some(Action::Quit),
        KeyCode::Up | KeyCode::Char('k') => Some(Action::ScrollUp),
        KeyCode::Down | KeyCode::Char('j') => Some(Action::ScrollDown),
        KeyCode::Tab => Some(Action::NextPanel),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};

    fn make_key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    #[test]
    fn given_q_when_map_key_then_quit() {
        assert_eq!(
            map_key(make_key(KeyCode::Char('q'), KeyModifiers::NONE)),
            Some(Action::Quit)
        );
    }

    #[test]
    fn given_esc_when_map_key_then_quit() {
        assert_eq!(
            map_key(make_key(KeyCode::Esc, KeyModifiers::NONE)),
            Some(Action::Quit)
        );
    }

    #[test]
    fn given_ctrl_c_when_map_key_then_quit() {
        assert_eq!(
            map_key(make_key(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(Action::Quit)
        );
    }

    #[test]
    fn given_up_when_map_key_then_scroll_up() {
        assert_eq!(
            map_key(make_key(KeyCode::Up, KeyModifiers::NONE)),
            Some(Action::ScrollUp)
        );
    }

    #[test]
    fn given_down_when_map_key_then_scroll_down() {
        assert_eq!(
            map_key(make_key(KeyCode::Down, KeyModifiers::NONE)),
            Some(Action::ScrollDown)
        );
    }

    #[test]
    fn given_tab_when_map_key_then_next_panel() {
        assert_eq!(
            map_key(make_key(KeyCode::Tab, KeyModifiers::NONE)),
            Some(Action::NextPanel)
        );
    }

    #[test]
    fn given_unknown_key_when_map_key_then_none() {
        assert_eq!(map_key(make_key(KeyCode::F(1), KeyModifiers::NONE)), None);
    }
}
