/// Status of memory locking for the arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockStatus {
    /// All pages are locked in physical RAM.
    Locked,
    /// Lock was attempted but failed; pages may be swapped.
    BestEffort,
    /// No locking was attempted.
    Unlocked,
}

/// Advisory hints for memory management.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAdvisory {
    /// Disable transparent huge pages (Linux).
    NoHugePage,
    /// Disable KSM merging (Linux).
    NoMerge,
    /// Exclude from core dumps.
    NoDump,
    /// Hint that memory will be needed soon.
    WillNeed,
}

/// A contiguous, page-aligned memory region pinned in physical RAM.
///
/// Implementations must ensure that the backing memory is freed
/// (and unlocked, if applicable) when the arena is dropped.
///
/// # Safety
///
/// The raw pointers returned by `as_ptr` and `as_mut_ptr` are valid
/// for the lifetime of this arena and point to `len()` bytes of
/// readable/writable memory.
pub trait PinnedArena: Send {
    /// Returns a const pointer to the start of the arena.
    fn as_ptr(&self) -> *const u8;

    /// Returns a mutable pointer to the start of the arena.
    fn as_mut_ptr(&mut self) -> *mut u8;

    /// Returns the total size of the arena in bytes.
    fn len(&self) -> usize;

    /// Returns whether the arena memory is empty (zero length).
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the lock status of the arena pages.
    fn lock_status(&self) -> LockStatus;
}
