use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use cosmic_hammer_core::error::CosmicError;

use crate::schema::ReportJson;

/// Write a [`ReportJson`] to a file named `cr_report_{unix_timestamp}.json`.
///
/// Returns the filename on success.
pub fn dump_report_to_file(report: &ReportJson) -> Result<String, CosmicError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let filename = format!("cr_report_{}.json", timestamp);

    let json =
        serde_json::to_string_pretty(report).map_err(|e| CosmicError::Json(e.to_string()))?;

    fs::write(&filename, &json)?;

    println!("[*] Report saved -> {}", filename);
    Ok(filename)
}
