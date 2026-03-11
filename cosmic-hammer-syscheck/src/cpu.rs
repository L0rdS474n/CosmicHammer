use crate::check::{CheckResult, SystemChecker};

/// Reads CPU identity information: vendor, model, family, stepping, microcode,
/// and physical/virtual address widths.
pub struct CpuChecker;

impl SystemChecker for CpuChecker {
    fn name(&self) -> &str {
        "CPU Identity"
    }

    fn run(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();

        #[cfg(target_os = "linux")]
        {
            match std::fs::read_to_string("/proc/cpuinfo") {
                Ok(cpuinfo) => {
                    let vendor = extract_cpuinfo_field(&cpuinfo, "vendor_id");
                    let model = extract_cpuinfo_field(&cpuinfo, "model name");
                    let family = extract_cpuinfo_field(&cpuinfo, "cpu family");
                    let stepping = extract_cpuinfo_field(&cpuinfo, "stepping");
                    let microcode = extract_cpuinfo_field(&cpuinfo, "microcode");

                    results.push(CheckResult::info(format!(
                        "Vendor: {}",
                        vendor.as_deref().unwrap_or("unknown")
                    )));
                    results.push(CheckResult::info(format!(
                        "Model: {}",
                        model.as_deref().unwrap_or("unknown")
                    )));
                    results.push(CheckResult::info(format!(
                        "Family: {}  Stepping: {}",
                        family.as_deref().unwrap_or("?"),
                        stepping.as_deref().unwrap_or("?")
                    )));
                    results.push(CheckResult::info(format!(
                        "Microcode: {}",
                        microcode.as_deref().unwrap_or("unavailable")
                    )));

                    // Physical/virtual address widths
                    let addr_sizes = extract_cpuinfo_field(&cpuinfo, "address sizes");
                    if let Some(addr) = addr_sizes {
                        // Format: "39 bits physical, 48 bits virtual"
                        let parts: Vec<&str> = addr.split(',').collect();
                        let phys_bits = parts
                            .first()
                            .and_then(|s| s.trim().split_whitespace().next())
                            .and_then(|s| s.parse::<u32>().ok());
                        let virt_bits = parts
                            .get(1)
                            .and_then(|s| s.trim().split_whitespace().next())
                            .and_then(|s| s.parse::<u32>().ok());

                        if let Some(phys) = phys_bits {
                            if phys >= 39 {
                                results.push(CheckResult::pass(format!(
                                    "Physical addr width: {} bits (pte_for_index PFN fits in bits [31:12] -- fully safe)",
                                    phys
                                )));
                            } else if phys >= 36 {
                                results.push(CheckResult::warn(format!(
                                    "Physical addr width: {} bits (< 39 -- unusual, but pte_for_index 20-bit PFN still safe)",
                                    phys
                                )));
                            } else {
                                results.push(CheckResult::fail(format!(
                                    "Physical addr width: {} bits (< 36 -- PFN field may collide with PTE control bits)",
                                    phys
                                )));
                            }
                        }

                        if let Some(virt) = virt_bits {
                            results.push(CheckResult::info(format!(
                                "Virtual addr width: {} bits",
                                virt
                            )));
                        }
                    }
                }
                Err(_) => {
                    results.push(CheckResult::info("Could not read /proc/cpuinfo"));
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            results.push(CheckResult::info(
                "CPU identity checks not available on this platform",
            ));
        }

        results
    }
}

/// Extract the first occurrence of a field from /proc/cpuinfo.
#[cfg(target_os = "linux")]
fn extract_cpuinfo_field(cpuinfo: &str, field: &str) -> Option<String> {
    for line in cpuinfo.lines() {
        // Lines are "field\t: value" or "field : value"
        if let Some((key, value)) = line.split_once(':') {
            if key.trim() == field {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}
