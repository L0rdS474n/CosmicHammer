use crate::check::{CheckResult, SystemChecker};

/// Checks NUMA topology: node count and per-node memory.
pub struct NumaChecker;

impl SystemChecker for NumaChecker {
    fn name(&self) -> &str {
        "NUMA Topology"
    }

    fn run(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();

        #[cfg(target_os = "linux")]
        {
            let mut node_count = 0u32;
            let mut node_info: Vec<(String, Option<String>)> = Vec::new();

            // Scan /sys/devices/system/node/node*
            if let Ok(entries) = std::fs::read_dir("/sys/devices/system/node") {
                let mut node_dirs: Vec<_> = entries
                    .filter_map(|e| e.ok())
                    .filter(|e| {
                        e.file_name()
                            .to_str()
                            .map(|n| n.starts_with("node"))
                            .unwrap_or(false)
                    })
                    .collect();
                node_dirs.sort_by_key(|e| e.file_name());

                for entry in &node_dirs {
                    node_count += 1;
                    let name = entry.file_name().to_string_lossy().to_string();
                    let meminfo_path = entry.path().join("meminfo");
                    let mem_free = if let Ok(content) = std::fs::read_to_string(&meminfo_path) {
                        extract_meminfo_field(&content, "MemFree")
                    } else {
                        None
                    };
                    node_info.push((name, mem_free));
                }
            }

            results.push(CheckResult::info(format!("NUMA nodes: {}", node_count)));

            if node_count <= 1 {
                results.push(CheckResult::pass(
                    "Single NUMA node -- arena will be local, consistent access latency",
                ));
            } else {
                results.push(CheckResult::warn(format!(
                    "Multi-NUMA system ({} nodes)",
                    node_count
                )));
                results.push(CheckResult::warn(
                    "  Remote NUMA accesses have higher latency and different retention characteristics",
                ));
                results.push(CheckResult::warn(
                    "  Consider: numactl --membind=0 ./cosmic_rowhammer",
                ));
                for (name, free) in &node_info {
                    results.push(CheckResult::info(format!(
                        "  {} MemFree: {} kB",
                        name,
                        free.as_deref().unwrap_or("?")
                    )));
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

/// Extract a value from NUMA node meminfo (format: "Node N FieldName:    VALUE kB")
#[cfg(target_os = "linux")]
fn extract_meminfo_field(content: &str, field: &str) -> Option<String> {
    for line in content.lines() {
        if line.contains(field) {
            // The value is typically the second-to-last token (before "kB")
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Find the numeric value: it's the token right before "kB"
            if parts.len() >= 2 {
                // Return the numeric part
                if let Some(pos) = parts.iter().position(|&p| p == "kB") {
                    if pos > 0 {
                        return Some(parts[pos - 1].to_string());
                    }
                }
                // Fallback: return last numeric-looking token
                for part in parts.iter().rev() {
                    if part.chars().all(|c| c.is_ascii_digit()) && !part.is_empty() {
                        return Some(part.to_string());
                    }
                }
            }
        }
    }
    None
}
