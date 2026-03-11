//! Parallel scanning support.
//!
//! Provides `scan_parallel()` which splits the arena into chunks and scans
//! each chunk. Currently uses `std::thread::scope` for parallelism; rayon
//! integration can be added later without changing the public API.

use cosmic_hammer_core::FlipEvent;

use crate::arena::Arena;
use crate::fill::expected_at;

/// Wrapper around a raw pointer to make it `Send` for scoped threads.
///
/// # Safety
///
/// The caller must guarantee that concurrent accesses via this pointer
/// are to disjoint regions (no data races).
#[derive(Clone, Copy)]
struct SendPtr(*mut u8);

impl SendPtr {
    fn as_mut_ptr(self) -> *mut u8 {
        self.0
    }
}

// SAFETY: SendPtr is only used within `scan_parallel`, where each thread
// is given an exclusive, non-overlapping word range of the underlying
// allocation. The scoped-thread lifetime guarantee ensures the pointer
// remains valid for the duration of each thread.
unsafe impl Send for SendPtr {}

/// Scan the arena in parallel using the specified number of threads.
///
/// The arena is divided into `thread_count` chunks (by word range).
/// Each chunk is scanned independently and the results are merged.
///
/// # Arguments
///
/// * `arena` - The arena to scan. Must be filled before calling.
/// * `thread_count` - Number of threads to use. Values below 1 are treated as 1.
///
/// # Returns
///
/// A merged `Vec<FlipEvent>` from all threads, ordered by byte offset.
pub fn scan_parallel(arena: &mut Arena, thread_count: usize) -> Vec<FlipEvent> {
    let thread_count = thread_count.max(1);

    // For thread_count == 1, just do a normal scan.
    if thread_count == 1 {
        return arena.scan();
    }

    let config = arena.config().clone();
    let total_scannable = config.region_count * config.region_size;
    let words_total = total_scannable / core::mem::size_of::<u64>();

    // Split into chunks of roughly equal word count.
    let words_per_chunk = words_total.div_ceil(thread_count);

    let base = SendPtr(unsafe { arena.base_mut_ptr() });
    let pte_model = arena.pte_model();

    // Collect chunk ranges as (word_start, word_end).
    let mut chunks = Vec::with_capacity(thread_count);
    let mut start = 0usize;
    while start < words_total {
        let end = (start + words_per_chunk).min(words_total);
        chunks.push((start, end));
        start = end;
    }

    let mut all_flips: Vec<FlipEvent> = Vec::new();

    // Use scoped threads so we can borrow config and pte_model.
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(chunks.len());

        for (word_start, word_end) in &chunks {
            let word_start = *word_start;
            let word_end = *word_end;
            let config_ref = &config;
            let pte_ref = pte_model;
            let send_base = base;

            handles.push(s.spawn(move || {
                let mut found = Vec::new();
                let words = send_base.as_mut_ptr() as *mut u64;

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                for i in word_start..word_end {
                    let byte_off = i * core::mem::size_of::<u64>();
                    let expected = expected_at(byte_off, config_ref, pte_ref);

                    // SAFETY: words.add(i) is within the arena and within this
                    // thread's exclusive, non-overlapping chunk.
                    let observed = unsafe { std::ptr::read_volatile(words.add(i)) };

                    if observed == expected {
                        continue;
                    }

                    let diff = expected ^ observed;
                    let bit_pos = diff.trailing_zeros() as u8;
                    let direction = if (observed >> bit_pos) & 1 == 1 {
                        cosmic_hammer_core::FlipDirection::ZeroToOne
                    } else {
                        cosmic_hammer_core::FlipDirection::OneToZero
                    };
                    let n_bits = diff.count_ones();
                    let rtype = crate::scan::region_for_offset(byte_off, config_ref);
                    let dram_row = (byte_off / 8192) as u32;

                    let flip_class = if rtype == cosmic_hammer_core::RegionType::PteSim {
                        pte_ref.classify_flip(expected, observed)
                    } else {
                        cosmic_hammer_core::classify_flip(
                            rtype,
                            expected,
                            observed,
                            direction.as_int(),
                            n_bits,
                        )
                    };

                    found.push(cosmic_hammer_core::FlipEvent {
                        timestamp: now,
                        offset: byte_off,
                        bit_position: bit_pos,
                        expected,
                        observed,
                        direction,
                        n_bits,
                        region: rtype,
                        flip_class,
                        dram_row,
                    });

                    // Restore sentinel so the word is not re-reported.
                    // SAFETY: same pointer validity as the read above.
                    unsafe {
                        std::ptr::write_volatile(words.add(i), expected);
                    }
                }

                found
            }));
        }

        for h in handles {
            let mut chunk_flips = h.join().expect("scan thread panicked");
            all_flips.append(&mut chunk_flips);
        }
    });

    // Sort by offset for deterministic output.
    all_flips.sort_by_key(|ev| ev.offset);
    all_flips
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic_hammer_core::{ArenaConfig, RegionType, FILL_POINTER};
    use cosmic_hammer_platform::{LockStatus, PinnedArena};
    use cosmic_hammer_pte::x86_64::X86_64Pte;

    struct MockArena {
        buf: Vec<u8>,
    }

    impl MockArena {
        fn new(size: usize) -> Self {
            Self {
                buf: vec![0u8; size],
            }
        }
    }

    impl PinnedArena for MockArena {
        fn as_ptr(&self) -> *const u8 {
            self.buf.as_ptr()
        }
        fn as_mut_ptr(&mut self) -> *mut u8 {
            self.buf.as_mut_ptr()
        }
        fn len(&self) -> usize {
            self.buf.len()
        }
        fn lock_status(&self) -> LockStatus {
            LockStatus::Unlocked
        }
    }

    fn make_test_arena() -> Arena {
        let config = ArenaConfig::new(1);
        let mock = MockArena::new(config.total_size);
        Arena::new(Box::new(mock), config, Box::new(X86_64Pte))
    }

    /// Given a clean arena, parallel scan with 2 threads finds no flips.
    #[test]
    fn given_clean_arena_when_parallel_scan_then_no_flips() {
        let mut arena = make_test_arena();
        arena.fill();
        let flips = scan_parallel(&mut arena, 2);
        assert!(flips.is_empty());
    }

    /// Given one injected flip, parallel scan with 4 threads detects it.
    #[test]
    fn given_one_flip_when_parallel_scan_then_detected() {
        let mut arena = make_test_arena();
        arena.fill();

        // Inject flip at word 0 of region 0
        let base = unsafe { arena.base_mut_ptr() };
        let target = base as *mut u64;
        unsafe {
            std::ptr::write_volatile(target, FILL_POINTER ^ 1u64);
        }

        let flips = scan_parallel(&mut arena, 4);
        assert_eq!(flips.len(), 1);
        assert_eq!(flips[0].offset, 0);
        assert_eq!(flips[0].region, RegionType::Pointer);
    }

    /// thread_count=1 falls back to single-threaded scan.
    #[test]
    fn given_thread_count_1_when_parallel_scan_then_works() {
        let mut arena = make_test_arena();
        arena.fill();
        let flips = scan_parallel(&mut arena, 1);
        assert!(flips.is_empty());
    }
}
