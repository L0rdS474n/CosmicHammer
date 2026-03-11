use crate::check::{CheckResult, CheckStatus};

// ANSI color codes
const RED: &str = "\x1b[1;31m";
const YEL: &str = "\x1b[1;33m";
const GRN: &str = "\x1b[1;32m";
const CYN: &str = "\x1b[1;36m";
const RST: &str = "\x1b[0m";

/// Print results for a single checker section, with ANSI-colored status tags.
pub fn print_section(section_name: &str, results: &[CheckResult]) {
    println!();
    println!(
        "-- {} -----------------------------------------------",
        section_name
    );
    for result in results {
        let (color, tag) = match result.status {
            CheckStatus::Pass => (GRN, "PASS"),
            CheckStatus::Warn => (YEL, "WARN"),
            CheckStatus::Fail => (RED, "FAIL"),
            CheckStatus::Info => (CYN, "INFO"),
        };
        println!("  [{}{}{}] {}", color, tag, RST, result.message);
        if let Some(detail) = &result.detail {
            for line in detail.lines() {
                println!("         {}", line);
            }
        }
    }
}

/// Print a summary of all results with counts and return the appropriate exit code.
///
/// Returns:
/// - 0 if no FAIL and no WARN (system ready)
/// - 1 if WARNs but no FAILs (system ready with caveats)
/// - 2 if any FAILs (system not ready)
pub fn print_summary(all_results: &[CheckResult]) -> i32 {
    let mut pass_count = 0u32;
    let mut warn_count = 0u32;
    let mut fail_count = 0u32;

    for r in all_results {
        match r.status {
            CheckStatus::Pass => pass_count += 1,
            CheckStatus::Warn => warn_count += 1,
            CheckStatus::Fail => fail_count += 1,
            CheckStatus::Info => {}
        }
    }

    println!();
    println!("===================================================");
    println!(
        "  PASS: {}   WARN: {}   FAIL: {}",
        pass_count, warn_count, fail_count
    );
    println!("===================================================");

    if fail_count > 0 {
        println!(
            "  {}System not ready -- fix FAIL items before running.{}",
            RED, RST
        );
        2
    } else if warn_count > 0 {
        println!(
            "  {}System ready with caveats -- review WARNs above.{}",
            YEL, RST
        );
        1
    } else {
        println!(
            "  {}System ready -- good to run CosmicRowhammer.{}",
            GRN, RST
        );
        0
    }
}

/// Print the banner header.
pub fn print_banner() {
    println!("+=================================================+");
    println!("|   CosmicRowhammer  --  System Pre-flight Check   |");
    println!("+=================================================+");
}
