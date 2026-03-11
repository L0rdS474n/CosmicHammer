use crate::check::{CheckResult, SystemChecker};

/// Checks MCA bank error logs via mcelog.
pub struct McaChecker;

impl SystemChecker for McaChecker {
    fn name(&self) -> &str {
        "MCA Bank Error Logs"
    }

    fn run(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();

        #[cfg(target_os = "linux")]
        {
            use std::path::Path;

            // Try mcelog --client first
            let has_mcelog = std::process::Command::new("which")
                .arg("mcelog")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

            let has_dev_mcelog = Path::new("/dev/mcelog").exists();

            if has_mcelog && has_dev_mcelog {
                match std::process::Command::new("mcelog")
                    .arg("--client")
                    .output()
                {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let trimmed = stdout.trim();
                        if trimmed.is_empty() {
                            results
                                .push(CheckResult::pass("mcelog: no recent machine check errors"));
                        } else {
                            results.push(
                                CheckResult::warn("mcelog reports recent machine check errors")
                                    .with_detail(
                                        trimmed.lines().take(5).collect::<Vec<_>>().join("\n"),
                                    ),
                            );
                        }
                    }
                    Err(_) => {
                        results.push(CheckResult::info("mcelog --client failed"));
                    }
                }
            } else if Path::new("/var/log/mcelog").exists() {
                match std::fs::read_to_string("/var/log/mcelog") {
                    Ok(content) => {
                        let line_count = content.lines().count();
                        if line_count > 0 {
                            results.push(CheckResult::warn(format!(
                                "/var/log/mcelog has {} lines -- hardware errors logged, review before running",
                                line_count
                            )));
                        } else {
                            results.push(CheckResult::pass(
                                "/var/log/mcelog empty -- no prior hardware errors",
                            ));
                        }
                    }
                    Err(_) => {
                        results.push(CheckResult::info("Could not read /var/log/mcelog"));
                    }
                }
            } else {
                results.push(CheckResult::info(
                    "mcelog not available -- install for hardware error history",
                ));
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            results.push(CheckResult::info("Not available on this platform"));
        }

        results
    }
}
