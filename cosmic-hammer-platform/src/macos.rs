use std::ptr;

use cosmic_hammer_core::CosmicError;

use crate::traits::{LockStatus, PinnedArena};

/// macOS arena backed by mmap with MAP_PRIVATE | MAP_ANONYMOUS + manual prefault.
pub struct MacosArena {
    ptr: *mut u8,
    size: usize,
    lock_status: LockStatus,
}

// SAFETY: The arena owns its memory exclusively. The raw pointer is not
// shared across threads without synchronization, and PinnedArena requires
// &mut self for mutable access.
unsafe impl Send for MacosArena {}

impl MacosArena {
    /// Allocates a new arena of the given size using mmap.
    ///
    /// Uses MADV_WILLNEED for prefaulting and attempts mlock.
    /// THP and KSM are not applicable on macOS.
    pub fn new(size: usize) -> Result<Self, CosmicError> {
        if size == 0 {
            return Err(CosmicError::ArenaAlloc(
                "arena size must be greater than zero".to_string(),
            ));
        }

        // SAFETY: Calling mmap with MAP_PRIVATE | MAP_ANONYMOUS to allocate a
        // private anonymous memory region. macOS does not support MAP_POPULATE,
        // so we prefault via madvise(MADV_WILLNEED) afterwards. The returned
        // pointer is checked against MAP_FAILED.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
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

        // -- Prefault pages via MADV_WILLNEED --
        // SAFETY: ptr is a valid mmap'd region of `size` bytes.
        // MADV_WILLNEED advises the kernel to page in the region.
        unsafe {
            if libc::madvise(ptr as *mut libc::c_void, size, libc::MADV_WILLNEED) != 0 {
                tracing::warn!(
                    "MADV_WILLNEED failed ({}) - prefaulting may be incomplete",
                    std::io::Error::last_os_error()
                );
            }
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

impl PinnedArena for MacosArena {
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

impl Drop for MacosArena {
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
