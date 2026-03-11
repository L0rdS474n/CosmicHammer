use serde::{Deserialize, Serialize};

/// Platform information embedded in the report JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub arch: String,
    pub os: String,
    pub ram_mb: u64,
    pub ecc: bool,
    pub altitude_m: Option<i64>,
}

/// Flip count totals embedded in the report JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlipTotals {
    pub total_bits_observed: u64,
    pub zero_to_one: u64,
    pub one_to_zero: u64,
}

/// Top-level report JSON structure.
///
/// Field names match the C source `build_report_json()` exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportJson {
    pub schema_version: String,
    pub window_hours: f64,
    pub window_start: String,
    pub window_end: String,
    pub platform: PlatformInfo,
    pub flip_totals: FlipTotals,
    pub by_class: serde_json::Map<String, serde_json::Value>,
    pub by_region: serde_json::Map<String, serde_json::Value>,
    pub dram_rows_affected: u64,
    pub multi_bit_events: u64,
    pub scan_cycles: u64,
}
