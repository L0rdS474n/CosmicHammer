use std::ptr;

use cosmic_hammer_core::CosmicError;

use crate::traits::{LockStatus, PinnedArena};

/// Linux arena backed by mmap with MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE.
pub struct LinuxArena {
    ptr: *mut u8,
    size: usize,
    lock_status: LockStatus,
}

// SAFETY: The arena owns its memory exclusively. The raw pointer is not
// shared across threads without synchronization, and PinnedArena requires
// &mut self for mutable access.
unsafe impl Send for LinuxArena {}

impl LinuxArena {
    /// Allocates a new arena of the given size using mmap.
    ///
    /// Applies memory advisories (NOHUGEPAGE, UNMERGEABLE, DONTDUMP) and
    /// attempts to mlock the region.
    pub fn new(size: usize) -> Result<Self, CosmicError> {
        if size == 0 {
            return Err(CosmicError::ArenaAlloc(
                "arena size must be greater than zero".to_string(),
            ));
        }

        // SAFETY: Calling mmap with MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE
        // to allocate a private anonymous memory region. No file descriptor is
        // used (fd = -1, offset = 0). The returned pointer is checked against
        // MAP_FAILED before use.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
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

        // -- Disable THP: prevents khugepaged false-positive flips --
        // SAFETY: ptr is a valid mmap'd region of `size` bytes.
        // MADV_NOHUGEPAGE is advisory; failure is non-fatal.
        unsafe {
            if libc::madvise(ptr as *mut libc::c_void, size, libc::MADV_NOHUGEPAGE) != 0 {
                tracing::warn!(
                    "MADV_NOHUGEPAGE unavailable ({}) - THP may cause false positives",
                    std::io::Error::last_os_error()
                );
            }
        }

        // -- Disable KSM merging: prevents CoW-restore false-positive flips --
        // SAFETY: ptr is a valid mmap'd region of `size` bytes.
        // MADV_UNMERGEABLE is advisory; failure is non-fatal.
        unsafe {
            if libc::madvise(ptr as *mut libc::c_void, size, libc::MADV_UNMERGEABLE) != 0 {
                tracing::warn!(
                    "MADV_UNMERGEABLE failed ({}) - add --cap-add SYS_ADMIN if KSM is active",
                    std::io::Error::last_os_error()
                );
            }
        }

        // -- Omit from core dumps --
        // SAFETY: ptr is a valid mmap'd region of `size` bytes.
        // MADV_DONTDUMP is advisory; failure is silently ignored.
        unsafe {
            let _ = libc::madvise(ptr as *mut libc::c_void, size, libc::MADV_DONTDUMP);
        }

        // -- Lock pages: requires CAP_IPC_LOCK or root --
        // SAFETY: ptr is a valid mmap'd region of `size` bytes.
        // mlock failure is non-fatal; we record the status.
        let lock_status = unsafe {
            if libc::mlock(ptr as *const libc::c_void, size) != 0 {
                tracing::warn!(
                    "mlock failed ({}) - without locked pages, the kernel may swap/reclaim \
                     arena pages between spray and scan, causing false positives. \
                     Ensure: docker run --cap-add IPC_LOCK, run as root, cgroup limit >= 768 MB",
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

impl PinnedArena for LinuxArena {
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

impl Drop for LinuxArena {
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
