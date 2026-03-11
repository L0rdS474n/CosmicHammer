use std::ptr;

use cosmic_hammer_core::CosmicError;

use crate::traits::{LockStatus, PinnedArena};

/// FreeBSD arena backed by mmap with MAP_PRIVATE | MAP_ANONYMOUS | MAP_PREFAULT_READ.
pub struct FreebsdArena {
    ptr: *mut u8,
    size: usize,
    lock_status: LockStatus,
}

// SAFETY: The arena owns its memory exclusively. The raw pointer is not
// shared across threads without synchronization, and PinnedArena requires
// &mut self for mutable access.
unsafe impl Send for FreebsdArena {}

/// FreeBSD-specific MAP_PREFAULT_READ flag.
/// This requests the kernel to prefault all pages as readable.
const MAP_PREFAULT_READ: libc::c_int = 0x00040000;

/// FreeBSD-specific MADV_NOCORE flag.
/// Excludes the region from core dumps.
const MADV_NOCORE: libc::c_int = 8;

impl FreebsdArena {
    /// Allocates a new arena of the given size using mmap.
    ///
    /// Uses MAP_PREFAULT_READ for prefaulting, MADV_NOCORE for dump exclusion,
    /// and attempts mlock.
    pub fn new(size: usize) -> Result<Self, CosmicError> {
        if size == 0 {
            return Err(CosmicError::ArenaAlloc(
                "arena size must be greater than zero".to_string(),
            ));
        }

        // SAFETY: Calling mmap with MAP_PRIVATE | MAP_ANONYMOUS | MAP_PREFAULT_READ
        // to allocate a private anonymous memory region with prefaulted pages.
        // The returned pointer is checked against MAP_FAILED.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | MAP_PREFAULT_READ,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            return Err(CosmicError::ArenaAlloc(format!(
                "mmap failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let ptr = ptr as *mut u8;

        // -- Exclude from core dumps via MADV_NOCORE --
        // SAFETY: ptr is a valid mmap'd region of `size` bytes.
        // MADV_NOCORE is advisory; failure is silently ignored.
        unsafe {
            let _ = libc::madvise(ptr as *mut libc::c_void, size, MADV_NOCORE);
        }

        // -- Lock pages --
        // SAFETY: ptr is a valid mmap'd region of `size` bytes.
        // mlock failure is non-fatal; we record the status.
        let lock_status = unsafe {
            if libc::mlock(ptr as *const libc::c_void, size) != 0 {
                tracing::warn!(
                    "mlock failed ({}) - pages may be swapped under memory pressure",
                    std::io::Error::last_os_error()
                );
                LockStatus::BestEffort
            } else {
                tracing::info!("Arena mlocked - pages pinned in RAM");
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

impl PinnedArena for FreebsdArena {
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

impl Drop for FreebsdArena {
    fn drop(&mut self) {
        // SAFETY: self.ptr was obtained from a successful mmap call with
        // self.size bytes. We unlock first (ignoring errors) then unmap.
        unsafe {
            let _ = libc::munlock(self.ptr as *const libc::c_void, self.size);
            let ret = libc::munmap(self.ptr as *mut libc::c_void, self.size);
            if ret != 0 {
                tracing::error!("munmap failed: {}", std::io::Error::last_os_error());
            }
        }
    }
}
