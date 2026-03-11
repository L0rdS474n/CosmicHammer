#![forbid(unsafe_code)]

pub mod classify;
pub mod config;
pub mod duration;
pub mod error;
pub mod flip;
pub mod region;
pub mod report;

pub use classify::classify_flip;
pub use config::ArenaConfig;
pub use duration::{fmt_duration, parse_report_window};
pub use error::CosmicError;
pub use flip::{FlipClass, FlipDirection, FlipEvent};
pub use region::RegionType;
pub use report::ReportWindow;

/// Sentinel fill patterns matching the original C implementation.
pub const FILL_POINTER: u64 = 0x00007FFF12345678;
pub const FILL_RETADDR: u64 = 0x00007FFF87654321;
pub const FILL_PERMISSION: u64 = 0x0000000000000004;
pub const FILL_DATA_A: u64 = 0xAAAAAAAAAAAAAAAA;
pub const FILL_DATA_B: u64 = 0x5555555555555555;

pub const VERSION: &str = "1.0.0";
pub const MAX_FLIPS: usize = 8192;
pub const DEFAULT_REPORT_SECS: i64 = 72 * 3600; // 72 hours
pub const DEFAULT_REPORT_URL: &str = "http://cosmos.fuzzsociety.org:5000/report";

#[cfg(test)]
mod tests {
    use super::*;

    // T1: Given the DEFAULT_REPORT_URL constant, when inspected, then its value
    // matches the expected hard-coded URL string exactly.
    #[test]
    fn given_default_report_url_constant_when_inspected_then_value_matches_expected() {
        assert_eq!(DEFAULT_REPORT_URL, "http://cosmos.fuzzsociety.org:5000/report");
    }

    // T2: Given DEFAULT_REPORT_URL, when inspected, then it starts with the "http://"
    // scheme prefix (confirming it is not HTTPS and is not empty).
    #[test]
    fn given_default_report_url_when_inspected_then_starts_with_http() {
        assert!(
            DEFAULT_REPORT_URL.starts_with("http://"),
            "DEFAULT_REPORT_URL must start with 'http://', got: {}",
            DEFAULT_REPORT_URL
        );
    }
}
