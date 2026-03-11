use crate::check::{CheckResult, SystemChecker};

/// Checks root/admin privileges, CAP_IPC_LOCK, and RLIMIT_MEMLOCK.
pub struct PrivilegesChecker;

impl SystemChecker for PrivilegesChecker {
    fn name(&self) -> &str {
        "Privileges"
    }

    fn run(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();

        #[cfg(unix)]
        {
            // Check root (euid == 0)
            let euid = unsafe { libc::geteuid() };
            if euid == 0 {
                results.push(CheckResult::pass("Running as root"));
            } else {
                results.push(CheckResult::fail(
                    "Not root -- mlock, MSR reads, and EDAC access will fail",
                ));
            }

            // Check CAP_IPC_LOCK (Linux only: read /proc/self/status CapEff)
            #[cfg(target_os = "linux")]
            {
                if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
                    for line in status.lines() {
                        if let Some(hex_str) = line.strip_prefix("CapEff:\t") {
                            let hex_str = hex_str.trim();
                            if let Ok(cap_eff) = u64::from_str_radix(hex_str, 16) {
                                // IPC_LOCK is bit 14
                                if (cap_eff >> 14) & 1 == 1 {
                                    results.push(CheckResult::pass("CAP_IPC_LOCK effective"));
                                } else {
                                    results.push(CheckResult::warn(
                                        "CAP_IPC_LOCK not set -- add --cap-add IPC_LOCK to docker run",
                                    ));
                                }
                            }
                            break;
                        }
                    }
                }
            }

            // Check RLIMIT_MEMLOCK >= 512MB
            let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
            let ret = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rlim) };
            if ret == 0 {
                let arena_bytes: u64 = 512 * 1024 * 1024;
                if rlim.rlim_cur == libc::RLIM_INFINITY as u64 {
                    results.push(CheckResult::pass("RLIMIT_MEMLOCK = unlimited"));
                } else if rlim.rlim_cur >= arena_bytes {
                    results.push(CheckResult::pass(format!(
                        "RLIMIT_MEMLOCK = {} kB (>= 512 MB arena)",
                        rlim.rlim_cur / 1024
                    )));
                } else {
                    results.push(
                        CheckResult::fail(format!(
                            "RLIMIT_MEMLOCK = {} kB -- arena needs 524288 kB (512 MB)",
                            rlim.rlim_cur / 1024
                        ))
                        .with_detail(
                            "Fix: docker run --ulimit memlock=-1  or  ulimit -l unlimited"
                                .to_string(),
                        ),
                    );
                }
            }
        }

        #[cfg(windows)]
        {
            // On Windows, check if running as admin.
            // A simple heuristic: try to read a protected registry key or check
            // environment. For now, report Info since we cannot easily detect
            // admin status without additional dependencies.
            results.push(CheckResult::info(
                "Admin privilege check not available on this platform",
            ));
        }

        #[cfg(not(any(unix, windows)))]
        {
            results.push(CheckResult::info(
                "Privilege checks not available on this platform",
            ));
        }

        results
    }
}
