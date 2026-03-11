use chrono::{DateTime, TimeZone, Utc};
use cosmic_hammer_core::flip::FlipClass;
use cosmic_hammer_core::region::RegionType;
use cosmic_hammer_core::report::ReportWindow;

use crate::schema::{FlipTotals, PlatformInfo, ReportJson};

/// Build a [`ReportJson`] from a [`ReportWindow`] and supplementary metadata.
///
/// # Arguments
///
/// * `window` - accumulated flip statistics
/// * `window_secs` - configured report window in seconds (used for `window_hours`)
/// * `altitude` - altitude in metres; `None` produces JSON `null`
/// * `arch` - CPU architecture string (e.g. `"x86_64"`)
/// * `os` - OS identification string (e.g. `"Linux 6.1.0"`)
/// * `ram_mb` - total RAM in megabytes
/// * `ecc` - whether ECC memory was detected
pub fn build_report_json(
    window: &ReportWindow,
    window_secs: i64,
    altitude: Option<i64>,
    arch: &str,
    os: &str,
    ram_mb: u64,
    ecc: bool,
) -> ReportJson {
    let window_hours = window_secs as f64 / 3600.0;

    let window_start = format_timestamp(window.window_start);
    let window_end = format_timestamp(window.window_end);

    let platform = PlatformInfo {
        arch: arch.to_string(),
        os: os.to_string(),
        ram_mb,
        ecc,
        altitude_m: altitude,
    };

    let flip_totals = FlipTotals {
        total_bits_observed: window.total_bits,
        zero_to_one: window.zero_to_one,
        one_to_zero: window.one_to_zero,
    };

    // Build by_class map — iterate all FlipClass variants by index.
    let mut by_class = serde_json::Map::new();
    for i in 0..FlipClass::COUNT {
        if let Some(fc) = FlipClass::from_index(i) {
            by_class.insert(
                fc.name().to_string(),
                serde_json::Value::Number(serde_json::Number::from(window.by_class[i])),
            );
        }
    }

    // Build by_region map — iterate all RegionType variants by index.
    let mut by_region = serde_json::Map::new();
    for i in 0..RegionType::COUNT {
        if let Some(rt) = RegionType::from_index(i) {
            by_region.insert(
                rt.name().to_string(),
                serde_json::Value::Number(serde_json::Number::from(window.by_region[i])),
            );
        }
    }

    ReportJson {
        schema_version: "1.1".to_string(),
        window_hours,
        window_start,
        window_end,
        platform,
        flip_totals,
        by_class,
        by_region,
        dram_rows_affected: window.dram_rows_seen,
        multi_bit_events: window.multi_bit_events,
        scan_cycles: window.scan_cycles,
    }
}

/// Format a Unix timestamp as ISO 8601 UTC string (`YYYY-MM-DDTHH:MM:SSZ`).
fn format_timestamp(epoch: i64) -> String {
    let dt: DateTime<Utc> = Utc
        .timestamp_opt(epoch, 0)
        .single()
        .unwrap_or_else(|| Utc.timestamp_opt(0, 0).single().unwrap());
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic_hammer_core::flip::FlipClass;
    use cosmic_hammer_core::region::RegionType;

    /// Given a default ReportWindow, build_report_json populates all required fields.
    #[test]
    fn given_default_window_when_build_then_schema_version_is_1_1() {
        let w = ReportWindow::new(1_700_000_000);
        let report = build_report_json(&w, 72 * 3600, None, "x86_64", "Linux 6.1.0", 16384, false);
        assert_eq!(report.schema_version, "1.1");
    }

    /// Given window_secs = 72*3600, window_hours = 72.0.
    #[test]
    fn given_72h_window_when_build_then_window_hours_72() {
        let w = ReportWindow::new(0);
        let report = build_report_json(&w, 72 * 3600, None, "x86_64", "Linux", 8192, false);
        assert!((report.window_hours - 72.0).abs() < 0.0001);
    }

    /// Given altitude = None, platform.altitude_m is None.
    #[test]
    fn given_no_altitude_when_build_then_altitude_none() {
        let w = ReportWindow::new(0);
        let report = build_report_json(&w, 3600, None, "x86_64", "Linux", 8192, false);
        assert!(report.platform.altitude_m.is_none());
    }

    /// Given altitude = Some(1500), platform.altitude_m is Some(1500).
    #[test]
    fn given_altitude_when_build_then_altitude_present() {
        let w = ReportWindow::new(0);
        let report = build_report_json(&w, 3600, Some(1500), "x86_64", "Linux", 8192, false);
        assert_eq!(report.platform.altitude_m, Some(1500));
    }

    /// Given some flips recorded, by_class and by_region maps contain expected keys.
    #[test]
    fn given_flips_when_build_then_by_class_has_all_keys() {
        let mut w = ReportWindow::new(0);
        w.record_flip(FlipClass::PtrHijack, RegionType::Pointer, 1, 1);
        let report = build_report_json(&w, 3600, None, "x86_64", "Linux", 8192, false);
        assert!(report.by_class.contains_key("PTR_HIJACK"));
        assert!(report.by_class.contains_key("BENIGN"));
        assert!(report.by_region.contains_key("POINTER"));
        assert!(report.by_region.contains_key("DATA"));
        assert_eq!(report.by_class.len(), FlipClass::COUNT);
        assert_eq!(report.by_region.len(), RegionType::COUNT);
    }

    /// Serialized JSON null for altitude when None.
    #[test]
    fn given_no_altitude_when_serialized_then_altitude_is_null() {
        let w = ReportWindow::new(0);
        let report = build_report_json(&w, 3600, None, "x86_64", "Linux", 8192, false);
        let json_str = serde_json::to_string(&report).unwrap();
        assert!(json_str.contains("\"altitude_m\":null"));
    }
}
