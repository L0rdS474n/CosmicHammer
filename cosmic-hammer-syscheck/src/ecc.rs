use crate::check::{CheckResult, SystemChecker};

/// Checks ECC/EDAC status via sysfs and dmidecode fallback.
pub struct EccChecker;

impl SystemChecker for EccChecker {
    fn name(&self) -> &str {
        "ECC / EDAC"
    }

    fn run(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();

        #[cfg(target_os = "linux")]
        {
            use std::path::Path;

            let edac_path = Path::new("/sys/devices/system/edac/mc/mc0");
            if edac_path.is_dir() {
                let ce = read_sysfs_value("/sys/devices/system/edac/mc/mc0/ce_count");
                let ue = read_sysfs_value("/sys/devices/system/edac/mc/mc0/ue_count");
                let mc_name = read_sysfs_string("/sys/devices/system/edac/mc/mc0/mc_name");

                results.push(CheckResult::warn(format!(
                    "ECC DIMM detected -- EDAC driver loaded (mc: {})",
                    mc_name.as_deref().unwrap_or("?")
                )));
                results.push(CheckResult::info(format!(
                    "  ce_count (corrected errors) = {}",
                    ce.as_deref().unwrap_or("?")
                )));
                results.push(CheckResult::info(format!(
                    "  ue_count (uncorrected errors) = {}",
                    ue.as_deref().unwrap_or("?")
                )));
                results.push(CheckResult::warn(
                    "  Single-bit SEUs will be silently corrected -- flip rate will be UNDER-counted",
                ));
                results.push(CheckResult::warn(
                    "  Only multi-bit (UE) events will be visible to CosmicRowhammer",
                ));
            } else {
                let in_docker = Path::new("/.dockerenv").exists();
                if in_docker {
                    results.push(CheckResult::info(
                        "EDAC sysfs not visible inside container (host kernel sysfs not mounted)",
                    ));
                } else {
                    results.push(CheckResult::info("EDAC sysfs absent -- ECC status unknown"));
                    results.push(CheckResult::info(
                        "  Try: modprobe edac_core && modprobe <platform>_edac",
                    ));
                }

                // Try dmidecode fallback
                if let Ok(output) = std::process::Command::new("dmidecode")
                    .args(["-t", "17"])
                    .output()
                {
                    if output.status.success() {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        for line in stdout.lines() {
                            if line.contains("Error Correction") {
                                if let Some((_, value)) = line.split_once(':') {
                                    let ecc_type = value.trim();
                                    results.push(CheckResult::info(format!(
                                        "  dmidecode reports ECC type: {}",
                                        ecc_type
                                    )));
                                    if ecc_type.contains("None") || ecc_type.contains("Unknown") {
                                        results.push(CheckResult::pass(
                                            "No ECC detected via dmidecode -- all SEUs visible",
                                        ));
                                    } else {
                                        results.push(CheckResult::warn(format!(
                                            "ECC active ({}) -- single-bit flips will be corrected silently",
                                            ecc_type
                                        )));
                                    }
                                    break;
                                }
                            }
                        }
                    }
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

#[cfg(target_os = "linux")]
fn read_sysfs_value(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(target_os = "linux")]
fn read_sysfs_string(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}
