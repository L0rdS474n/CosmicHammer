use cosmic_hammer_core::CosmicError;

use crate::traits::{LockStatus, PinnedArena};

use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualFree, VirtualLock, VirtualUnlock, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_READWRITE,
};
use windows_sys::Win32::System::SystemInformation::GetSystemInfo;

/// Windows arena backed by VirtualAlloc with MEM_COMMIT | MEM_RESERVE.
pub struct WindowsArena {
    ptr: *mut u8,
    size: usize,
    lock_status: LockStatus,
}

// SAFETY: The arena owns its memory exclusively. The raw pointer is not
// shared across threads without synchronization, and PinnedArena requires
// &mut self for mutable access.
unsafe impl Send for WindowsArena {}

/// Attempts to grow the process working set to accommodate locking `size` bytes.
fn ensure_working_set(size: usize) {
    use windows_sys::Win32::System::Memory::{
        GetProcessWorkingSetSizeEx, SetProcessWorkingSetSizeEx,
    };

    // SAFETY: GetCurrentProcess returns a pseudo-handle that does not need closing.
    let process = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() };

    let mut min_ws: usize = 0;
    let mut max_ws: usize = 0;
    let mut flags: u32 = 0;

    // SAFETY: Passing valid mutable pointers for min/max working set sizes and flags.
    let ok = unsafe { GetProcessWorkingSetSizeEx(process, &mut min_ws, &mut max_ws, &mut flags) };
    if ok == 0 {
        tracing::warn!("GetProcessWorkingSetSizeEx failed - cannot adjust working set");
        return;
    }

    let needed_min = min_ws.saturating_add(size);
    let needed_max = max_ws.saturating_add(size);

    // SAFETY: Setting working set sizes to accommodate the arena allocation.
    // flags = 0 uses default behavior. This is advisory and failure is non-fatal.
    let ok = unsafe { SetProcessWorkingSetSizeEx(process, needed_min, needed_max, 0) };
    if ok == 0 {
        tracing::warn!("SetProcessWorkingSetSizeEx failed - VirtualLock may fail for large arenas");
    }
}

impl WindowsArena {
    /// Allocates a new arena of the given size using VirtualAlloc.
    ///
    /// Adjusts the process working set and attempts VirtualLock.
    pub fn new(size: usize) -> Result<Self, CosmicError> {
        if size == 0 {
            return Err(CosmicError::ArenaAlloc(
                "arena size must be greater than zero".to_string(),
            ));
        }

        // SAFETY: VirtualAlloc with NULL lpAddress allocates a new region.
        // MEM_COMMIT | MEM_RESERVE allocates and commits pages.
        // PAGE_READWRITE grants read/write access. The returned pointer is
        // checked for null.
        let ptr = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };

        if ptr.is_null() {
            return Err(CosmicError::ArenaAlloc(format!(
                "VirtualAlloc failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let ptr = ptr as *mut u8;

        // Grow working set before locking
        ensure_working_set(size);

        // SAFETY: ptr is a valid VirtualAlloc'd region of `size` bytes.
        // VirtualLock failure is non-fatal; we record the status.
        let lock_status = unsafe {
            if VirtualLock(ptr as *const std::ffi::c_void, size) == 0 {
                tracing::warn!(
                    "VirtualLock failed ({}) - pages may be paged out under memory pressure. \
                     Run as Administrator or increase working set limits.",
                    std::io::Error::last_os_error()
                );
                LockStatus::BestEffort
            } else {
                tracing::info!("Arena locked - pages pinned in RAM");
                LockStatus::Locked
            }
        };

        Ok(Self {
            ptr,
            size,
            lock_status,
        })
    }
}

impl PinnedArena for WindowsArena {
    fn as_ptr(&self) -> *const u8 {
        self.ptr
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    fn len(&self) -> usize {
        self.size
    }

    fn lock_status(&self) -> LockStatus {
        self.lock_status
    }
}

impl Drop for WindowsArena {
    fn drop(&mut self) {
        // SAFETY: self.ptr was obtained from a successful VirtualAlloc call
        // with self.size bytes. We unlock first (ignoring errors) then free
        // with MEM_RELEASE (which requires dwSize = 0 per Windows API docs).
        unsafe {
            let _ = VirtualUnlock(self.ptr as *const std::ffi::c_void, self.size);
            let ret = VirtualFree(self.ptr as *mut std::ffi::c_void, 0, MEM_RELEASE);
            if ret == 0 {
                tracing::error!("VirtualFree failed: {}", std::io::Error::last_os_error());
            }
        }
    }
}

/// Returns the system page size on Windows.
pub fn page_size() -> usize {
    let mut info = unsafe { std::mem::zeroed() };
    // SAFETY: GetSystemInfo populates the SYSTEM_INFO struct.
    // It always succeeds and does not return an error code.
    unsafe { GetSystemInfo(&mut info) };
    info.dwPageSize as usize
}
