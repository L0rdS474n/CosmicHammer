#![forbid(unsafe_code)]

pub mod file;
pub mod http;
pub mod json;
pub mod schema;

pub use file::dump_report_to_file;
pub use http::post_report;
pub use json::build_report_json;
pub use schema::{FlipTotals, PlatformInfo, ReportJson};
