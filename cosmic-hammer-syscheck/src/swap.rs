use crate::check::{CheckResult, SystemChecker};

/// Checks swap configuration.
pub struct SwapChecker;

impl SystemChecker for SwapChecker {
    fn name(&self) -> &str {
        "Swap"
    }

    fn run(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();

        #[cfg(target_os = "linux")]
        {
            match std::fs::read_to_string("/proc/meminfo") {
                Ok(meminfo) => {
                    let swap_total_kb = extract_meminfo_kb(&meminfo, "SwapTotal").unwrap_or(0);
                    if swap_total_kb == 0 {
                        results.push(CheckResult::pass(
                            "No swap configured -- pages cannot be silently evicted",
                        ));
                    } else {
                        let swap_free_kb = extract_meminfo_kb(&meminfo, "SwapFree").unwrap_or(0);
                        results.push(CheckResult::warn(format!(
                            "Swap present: total={} MB  free={} MB",
                            swap_total_kb / 1024,
                            swap_free_kb / 1024
                        )));
                        results.push(CheckResult::warn(
                            "  If mlock fails, arena pages may swap -> zero on readback -> false positives",
                        ));
                    }
                }
                Err(_) => {
                    results.push(CheckResult::info("Could not read /proc/meminfo"));
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            results.push(CheckResult::info("Not available on this platform"));
        }

        results
    }
}

/// Extract a kB value from /proc/meminfo for the given field name.
#[cfg(target_os = "linux")]
fn extract_meminfo_kb(meminfo: &str, field: &str) -> Option<u64> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            if let Some(rest) = rest.strip_prefix(':') {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if let Some(val_str) = parts.first() {
                    return val_str.parse::<u64>().ok();
                }
            }
        }
    }
    None
}
