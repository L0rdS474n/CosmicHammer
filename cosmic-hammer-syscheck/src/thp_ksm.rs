use crate::check::{CheckResult, SystemChecker};

/// Checks Transparent Huge Pages (THP) and Kernel Same-page Merging (KSM) status.
pub struct ThpKsmChecker;

impl SystemChecker for ThpKsmChecker {
    fn name(&self) -> &str {
        "THP / KSM (false-positive sources)"
    }

    fn run(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();

        #[cfg(target_os = "linux")]
        {
            // THP check
            let thp_path = "/sys/kernel/mm/transparent_hugepage/enabled";
            match std::fs::read_to_string(thp_path) {
                Ok(content) => {
                    // Extract the active policy from brackets: e.g. "always [madvise] never"
                    let active = content
                        .split('[')
                        .nth(1)
                        .and_then(|s| s.split(']').next())
                        .map(|s| s.trim().to_string());

                    match active.as_deref() {
                        Some("never") => {
                            results.push(CheckResult::pass("THP = never (optimal)"));
                        }
                        Some("madvise") => {
                            results.push(CheckResult::pass(
                                "THP = madvise (good -- MADV_NOHUGEPAGE will suppress for arena)",
                            ));
                        }
                        Some(policy) => {
                            results.push(CheckResult::warn(format!(
                                "THP = {} (always) -- khugepaged may cause transient false flips",
                                policy
                            )));
                            results.push(CheckResult::warn(
                                "  Fix: echo madvise > /sys/kernel/mm/transparent_hugepage/enabled",
                            ));
                        }
                        None => {
                            results
                                .push(CheckResult::info("Could not parse THP policy from sysfs"));
                        }
                    }
                }
                Err(_) => {
                    results.push(CheckResult::info(
                        "THP sysfs not available (container or kernel without THP)",
                    ));
                }
            }

            // KSM check
            let ksm_path = "/sys/kernel/mm/ksm/run";
            match std::fs::read_to_string(ksm_path) {
                Ok(content) => {
                    let value = content.trim();
                    if value == "0" {
                        results.push(CheckResult::pass("KSM = off (optimal)"));
                    } else {
                        results.push(CheckResult::warn(format!(
                            "KSM = {} (active) -- large uniform sentinel regions are prime merge targets",
                            value
                        )));
                        results.push(CheckResult::warn("  Fix: echo 0 > /sys/kernel/mm/ksm/run"));
                    }
                }
                Err(_) => {
                    results.push(CheckResult::info("KSM sysfs not available"));
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
