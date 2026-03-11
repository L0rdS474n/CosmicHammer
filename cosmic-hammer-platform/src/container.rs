/// Detects whether the process is running inside a container.
///
/// On Linux, checks for /.dockerenv and inspects /proc/1/cgroup for
/// docker, lxc, containerd, or kubepods markers.
/// On other platforms, always returns false.
pub fn detect_container() -> bool {
    #[cfg(target_os = "linux")]
    {
        detect_container_linux()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Returns the cgroup memory limit in bytes, or None if unlimited or unavailable.
///
/// On Linux, reads cgroup v1 (`/sys/fs/cgroup/memory/memory.limit_in_bytes`)
/// or cgroup v2 (`/sys/fs/cgroup/memory.max`).
/// On other platforms, always returns None.
pub fn cgroup_mem_limit() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        cgroup_mem_limit_linux()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Checks whether Kernel Same-page Merging (KSM) is active.
///
/// On Linux, reads `/sys/kernel/mm/ksm/run`.
/// On other platforms, always returns false.
pub fn ksm_active() -> bool {
    #[cfg(target_os = "linux")]
    {
        ksm_active_linux()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Returns the current Transparent Huge Pages (THP) policy.
///
/// On Linux, reads `/sys/kernel/mm/transparent_hugepage/enabled` and
/// extracts the `[bracketed]` active policy.
/// On other platforms, returns `"unknown"`.
pub fn thp_policy() -> String {
    #[cfg(target_os = "linux")]
    {
        thp_policy_linux()
    }
    #[cfg(not(target_os = "linux"))]
    {
        "unknown".to_string()
    }
}

// ---------------------------------------------------------------------------
// Linux implementations
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn detect_container_linux() -> bool {
    use std::fs;
    use std::path::Path;

    // Most reliable: Docker always creates /.dockerenv
    if Path::new("/.dockerenv").exists() {
        return true;
    }

    // cgroup v1: docker sets a non-trivial cgroup path
    if let Ok(contents) = fs::read_to_string("/proc/1/cgroup") {
        let markers = ["docker", "lxc", "containerd", "kubepods"];
        for line in contents.lines() {
            for marker in &markers {
                if line.contains(marker) {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(target_os = "linux")]
fn cgroup_mem_limit_linux() -> Option<u64> {
    use std::fs;

    let paths = [
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
        "/sys/fs/cgroup/memory.max",
    ];

    for path in &paths {
        if let Ok(contents) = fs::read_to_string(path) {
            let trimmed = contents.trim();
            // cgroup v2 uses "max" for unlimited
            if trimmed == "max" {
                return None;
            }
            if let Ok(val) = trimmed.parse::<u64>() {
                // Kernel uses a value near u64::MAX for "unlimited"
                // (9223372036854771712 or similar). Treat anything above
                // 8 TiB as unlimited.
                const EIGHT_TIB: u64 = 8 * 1024 * 1024 * 1024 * 1024;
                if val > EIGHT_TIB {
                    return None;
                }
                return Some(val);
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
fn ksm_active_linux() -> bool {
    use std::fs;

    if let Ok(contents) = fs::read_to_string("/sys/kernel/mm/ksm/run") {
        if let Ok(val) = contents.trim().parse::<i32>() {
            return val != 0;
        }
    }
    false
}

#[cfg(target_os = "linux")]
fn thp_policy_linux() -> String {
    use std::fs;

    if let Ok(contents) = fs::read_to_string("/sys/kernel/mm/transparent_hugepage/enabled") {
        // File contains e.g. "always [madvise] never" - extract the bracketed one
        if let Some(start) = contents.find('[') {
            if let Some(end) = contents[start..].find(']') {
                return contents[start + 1..start + end].to_string();
            }
        }
        // Fallback: return the raw content trimmed
        return contents.trim().to_string();
    }

    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Container detection -- non-Linux platforms
    // -----------------------------------------------------------------------

    /// On non-Linux (or CI without container markers), detect_container should
    /// return a bool without panicking.
    #[test]
    fn detect_container_returns_bool() {
        let _result = detect_container();
    }

    /// cgroup_mem_limit returns None on non-Linux or when files are absent.
    #[test]
    fn cgroup_mem_limit_returns_option() {
        let _result = cgroup_mem_limit();
    }

    /// ksm_active returns a bool without panicking.
    #[test]
    fn ksm_active_returns_bool() {
        let _result = ksm_active();
    }

    /// thp_policy returns a non-empty string.
    #[test]
    fn thp_policy_returns_string() {
        let result = thp_policy();
        assert!(!result.is_empty());
    }

    // -----------------------------------------------------------------------
    // THP parsing logic
    // -----------------------------------------------------------------------

    #[test]
    fn thp_policy_parse_bracketed_value() {
        // Simulate the parsing logic used in thp_policy_linux
        let contents = "always [madvise] never";
        if let Some(start) = contents.find('[') {
            if let Some(end) = contents[start..].find(']') {
                let policy = &contents[start + 1..start + end];
                assert_eq!(policy, "madvise");
                return;
            }
        }
        panic!("failed to parse bracketed value");
    }

    #[test]
    fn thp_policy_parse_always_active() {
        let contents = "[always] madvise never";
        if let Some(start) = contents.find('[') {
            if let Some(end) = contents[start..].find(']') {
                let policy = &contents[start + 1..start + end];
                assert_eq!(policy, "always");
                return;
            }
        }
        panic!("failed to parse bracketed value");
    }

    #[test]
    fn thp_policy_parse_never_active() {
        let contents = "always madvise [never]";
        if let Some(start) = contents.find('[') {
            if let Some(end) = contents[start..].find(']') {
                let policy = &contents[start + 1..start + end];
                assert_eq!(policy, "never");
                return;
            }
        }
        panic!("failed to parse bracketed value");
    }

    // -----------------------------------------------------------------------
    // Cgroup limit parsing logic
    // -----------------------------------------------------------------------

    #[test]
    fn cgroup_limit_near_max_treated_as_unlimited() {
        // Kernel uses 9223372036854771712 (near u64::MAX) for "unlimited"
        let val: u64 = 9_223_372_036_854_771_712;
        const EIGHT_TIB: u64 = 8 * 1024 * 1024 * 1024 * 1024;
        assert!(
            val > EIGHT_TIB,
            "near-max value should exceed 8 TiB threshold"
        );
    }

    #[test]
    fn cgroup_limit_small_value_is_limit() {
        let val: u64 = 768 * 1024 * 1024; // 768 MB
        const EIGHT_TIB: u64 = 8 * 1024 * 1024 * 1024 * 1024;
        assert!(val <= EIGHT_TIB, "768 MB should be under 8 TiB threshold");
    }
}
