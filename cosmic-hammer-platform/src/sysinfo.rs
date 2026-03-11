/// Returns the total physical RAM in megabytes.
pub fn get_total_ram_mb() -> u64 {
    #[cfg(target_os = "linux")]
    {
        get_total_ram_mb_linux()
    }
    #[cfg(target_os = "macos")]
    {
        get_total_ram_mb_macos()
    }
    #[cfg(target_os = "windows")]
    {
        get_total_ram_mb_windows()
    }
    #[cfg(target_os = "freebsd")]
    {
        get_total_ram_mb_freebsd()
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd"
    )))]
    {
        0
    }
}

/// Returns the CPU architecture string (e.g., "x86_64", "aarch64").
pub fn get_arch() -> String {
    std::env::consts::ARCH.to_string()
}

/// Returns a human-readable OS identification string.
pub fn get_os_info() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    format!("{os} ({arch})")
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn get_total_ram_mb_linux() -> u64 {
    // SAFETY: sysinfo is a standard POSIX call that populates a struct.
    // We zero-initialize the struct first.
    unsafe {
        let mut info: libc::sysinfo = std::mem::zeroed();
        if libc::sysinfo(&mut info) == 0 {
            let total_bytes = info.totalram as u64 * info.mem_unit as u64;
            total_bytes / (1024 * 1024)
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// macOS
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn get_total_ram_mb_macos() -> u64 {
    use std::mem;

    // SAFETY: sysctlbyname with "hw.memsize" returns the physical memory
    // size as a u64. We pass a properly sized buffer.
    unsafe {
        let mut memsize: u64 = 0;
        let mut size = mem::size_of::<u64>();
        let name = b"hw.memsize\0";
        let ret = libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            &mut memsize as *mut u64 as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        );
        if ret == 0 {
            memsize / (1024 * 1024)
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn get_total_ram_mb_windows() -> u64 {
    use windows_sys::Win32::System::SystemInformation::GlobalMemoryStatusEx;

    #[repr(C)]
    struct MemoryStatusEx {
        dw_length: u32,
        dw_memory_load: u32,
        ull_total_phys: u64,
        ull_avail_phys: u64,
        ull_total_page_file: u64,
        ull_avail_page_file: u64,
        ull_total_virtual: u64,
        ull_avail_virtual: u64,
        ull_avail_extended_virtual: u64,
    }

    // SAFETY: GlobalMemoryStatusEx populates the MEMORYSTATUSEX struct.
    // We set dwLength to the struct size as required by the API.
    unsafe {
        let mut status: MemoryStatusEx = std::mem::zeroed();
        status.dw_length = std::mem::size_of::<MemoryStatusEx>() as u32;
        let ret = GlobalMemoryStatusEx(&mut status as *mut MemoryStatusEx as *mut _);
        if ret != 0 {
            status.ull_total_phys / (1024 * 1024)
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// FreeBSD
// ---------------------------------------------------------------------------

#[cfg(target_os = "freebsd")]
fn get_total_ram_mb_freebsd() -> u64 {
    use std::mem;

    // SAFETY: sysctlbyname with "hw.physmem" returns the physical memory
    // size. We pass a properly sized buffer.
    unsafe {
        let mut physmem: u64 = 0;
        let mut size = mem::size_of::<u64>();
        let name = b"hw.physmem\0";
        let ret = libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            &mut physmem as *mut u64 as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        );
        if ret == 0 {
            physmem / (1024 * 1024)
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_arch_returns_non_empty() {
        let arch = get_arch();
        assert!(!arch.is_empty());
    }

    #[test]
    fn get_os_info_returns_non_empty() {
        let info = get_os_info();
        assert!(!info.is_empty());
        // Should contain the arch
        assert!(info.contains(&get_arch()));
    }

    #[test]
    fn get_total_ram_mb_returns_positive_on_known_platforms() {
        let ram = get_total_ram_mb();
        // On real machines this should be > 0; allow 0 only on unsupported platforms
        if cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
            target_os = "freebsd"
        )) {
            assert!(ram > 0, "expected positive RAM on a supported platform");
        }
    }
}
