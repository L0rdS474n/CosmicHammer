use crate::check::{CheckResult, SystemChecker};

/// Checks available memory and cgroup limits.
pub struct MemoryChecker;

impl SystemChecker for MemoryChecker {
    fn name(&self) -> &str {
        "Memory"
    }

    fn run(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();
        let arena_kb: u64 = 512 * 1024; // 512 MB in kB

        #[cfg(target_os = "linux")]
        {
            match std::fs::read_to_string("/proc/meminfo") {
                Ok(meminfo) => {
                    if let Some(mem_avail_kb) = extract_meminfo_kb(&meminfo, "MemAvailable") {
                        results.push(CheckResult::info(format!(
                            "MemAvailable: {} MB",
                            mem_avail_kb / 1024
                        )));

                        let headroom_kb = 256 * 1024; // 256 MB headroom
                        if mem_avail_kb >= arena_kb + headroom_kb {
                            results.push(CheckResult::pass(
                                "Sufficient free memory for 512 MB arena + 256 MB headroom",
                            ));
                        } else if mem_avail_kb >= arena_kb {
                            results.push(CheckResult::warn(format!(
                                "Tight: only {} MB headroom above arena -- risk of reclaim under pressure",
                                mem_avail_kb / 1024 - 512
                            )));
                        } else {
                            results.push(CheckResult::fail(format!(
                                "Insufficient free memory: {} MB available, need 512 MB",
                                mem_avail_kb / 1024
                            )));
                        }
                    }
                }
                Err(_) => {
                    results.push(CheckResult::info("Could not read /proc/meminfo"));
                }
            }

            // Check cgroup memory limits
            let cgroup_paths = [
                "/sys/fs/cgroup/memory/memory.limit_in_bytes",
                "/sys/fs/cgroup/memory.max",
            ];

            for cg_path in &cgroup_paths {
                if let Ok(content) = std::fs::read_to_string(cg_path) {
                    let value = content.trim();
                    if value == "max" {
                        results.push(CheckResult::pass(format!(
                            "cgroup memory limit: unlimited ({})",
                            cg_path
                        )));
                        break;
                    }

                    if let Ok(limit_bytes) = value.parse::<u64>() {
                        // 8 TiB is effectively unlimited
                        if limit_bytes > 8 * 1024 * 1024 * 1024 * 1024 {
                            results.push(CheckResult::pass(format!(
                                "cgroup memory limit: unlimited ({})",
                                cg_path
                            )));
                        } else {
                            let cg_mb = limit_bytes / 1024 / 1024;
                            if cg_mb >= 768 {
                                results.push(CheckResult::pass(format!(
                                    "cgroup memory limit: {} MB (>= 768 MB recommended)",
                                    cg_mb
                                )));
                            } else {
                                results.push(
                                    CheckResult::fail(format!(
                                        "cgroup memory limit: {} MB -- too low for 512 MB arena + OS overhead",
                                        cg_mb
                                    ))
                                    .with_detail(
                                        "Fix: docker run --memory 768m (or higher)".to_string(),
                                    ),
                                );
                            }
                        }
                    }
                    break;
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = arena_kb;
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
            // Format: "FieldName:    12345 kB"
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
