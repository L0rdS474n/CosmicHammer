use cosmic_hammer_core::FlipClass;
use ratatui::style::Color;

/// Returns the severity color for a given flip classification.
pub fn severity_color(class: FlipClass) -> Color {
    match class {
        FlipClass::Benign => Color::Green,
        FlipClass::DataCorrupt => Color::Yellow,
        FlipClass::PtrHijack | FlipClass::CodePage => Color::Red,
        FlipClass::PrivEsc => Color::Red,
        FlipClass::PtePresentClear => Color::Yellow,
        FlipClass::PteWriteSet | FlipClass::PteNxClear => Color::LightRed,
        FlipClass::PtePhysCorrupt | FlipClass::PteSupervisorEsc => Color::Red,
    }
}

/// Returns a color for a region based on how many flips have been detected in it.
pub fn region_flip_color(flip_count: u64) -> Color {
    match flip_count {
        0 => Color::Green,
        1..=5 => Color::Yellow,
        _ => Color::Red,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_benign_when_severity_color_then_green() {
        assert_eq!(severity_color(FlipClass::Benign), Color::Green);
    }

    #[test]
    fn given_data_corrupt_when_severity_color_then_yellow() {
        assert_eq!(severity_color(FlipClass::DataCorrupt), Color::Yellow);
    }

    #[test]
    fn given_ptr_hijack_when_severity_color_then_red() {
        assert_eq!(severity_color(FlipClass::PtrHijack), Color::Red);
    }

    #[test]
    fn given_pte_nx_clear_when_severity_color_then_light_red() {
        assert_eq!(severity_color(FlipClass::PteNxClear), Color::LightRed);
    }

    #[test]
    fn given_zero_flips_when_region_flip_color_then_green() {
        assert_eq!(region_flip_color(0), Color::Green);
    }

    #[test]
    fn given_three_flips_when_region_flip_color_then_yellow() {
        assert_eq!(region_flip_color(3), Color::Yellow);
    }

    #[test]
    fn given_ten_flips_when_region_flip_color_then_red() {
        assert_eq!(region_flip_color(10), Color::Red);
    }
}
