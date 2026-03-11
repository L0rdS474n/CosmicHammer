use cosmic_hammer_core::error::CosmicError;

use crate::schema::ReportJson;

/// POST a [`ReportJson`] to the given URL.
///
/// This is a stub implementation. When `reqwest` and `tokio` are added as
/// dependencies, this function will perform a real HTTP POST with:
/// - Content-Type: application/json
/// - User-Agent: CosmicRowhammer/1.0.0
/// - 10-second timeout
/// - Redirect following enabled
///
/// For now it prints a message and returns Ok.
pub async fn post_report(report: &ReportJson, url: &str) -> Result<(), CosmicError> {
    // Validate that we have a valid report and URL before the stub message.
    let _json = serde_json::to_string(report).map_err(|e| CosmicError::Json(e.to_string()))?;

    if url.is_empty() {
        return Err(CosmicError::Report("Empty report URL".to_string()));
    }

    println!(
        "[!] Built without reqwest -- remote reporting disabled.\n    \
         Would POST report (schema_version={}) to {}",
        report.schema_version, url
    );

    Ok(())
}
