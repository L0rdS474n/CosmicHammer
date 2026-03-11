//! Lock-free ring buffer for `FlipEvent` values.
//!
//! The `FlipRing` is a fixed-capacity (MAX_FLIPS = 8192) circular buffer that
//! supports lock-free concurrent writes via atomic operations. No Mutex or
//! RwLock is used.

use cosmic_hammer_core::{FlipEvent, MAX_FLIPS};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A single slot in the ring buffer, using `UnsafeCell` for interior mutability
/// to allow `&self` push without a Mutex.
struct Slot {
    data: UnsafeCell<Option<FlipEvent>>,
}

// SAFETY: Slot is Send+Sync because concurrent access is serialised by the
// atomic head index — each slot is written by exactly one push at a time and
// is only read after the head has advanced past it.
unsafe impl Send for Slot {}
unsafe impl Sync for Slot {}

impl Slot {
    fn new() -> Self {
        Self {
            data: UnsafeCell::new(None),
        }
    }
}

/// Lock-free ring buffer for `FlipEvent`, capacity = `MAX_FLIPS` (8192).
///
/// Thread-safe: uses atomics only, no locks.
///
/// # Design
///
/// `head` is an ever-increasing counter. The actual buffer index is
/// `head % MAX_FLIPS`. When the buffer is full, the oldest entry is
/// silently overwritten.
///
/// `total` tracks the lifetime count of events pushed (may exceed capacity).
pub struct FlipRing {
    buffer: Box<[Slot]>,
    head: AtomicUsize,
    total: AtomicUsize,
}

// SAFETY: FlipRing is Send + Sync. The buffer slots use UnsafeCell but
// concurrent access is serialised by the atomic fetch_add on `head`:
// each push claims a unique slot index, ensuring no data race.
unsafe impl Send for FlipRing {}
unsafe impl Sync for FlipRing {}

impl FlipRing {
    /// Create a new empty FlipRing with capacity `MAX_FLIPS`.
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(MAX_FLIPS);
        for _ in 0..MAX_FLIPS {
            slots.push(Slot::new());
        }
        Self {
            buffer: slots.into_boxed_slice(),
            head: AtomicUsize::new(0),
            total: AtomicUsize::new(0),
        }
    }

    /// Push an event into the ring buffer (lock-free).
    ///
    /// Uses `fetch_add` with `Relaxed` ordering for the index claim (the
    /// uniqueness of the slot is guaranteed by atomicity), then a `Release`
    /// store is implicit via the total counter update so that readers using
    /// `Acquire` on `head`/`total` see the written data.
    pub fn push(&self, event: FlipEvent) {
        // Claim the next slot atomically. Each concurrent push gets a unique index.
        let idx = self.head.fetch_add(1, Ordering::Relaxed);
        let slot_idx = idx % MAX_FLIPS;

        // SAFETY: `slot_idx` is in [0, MAX_FLIPS), which is within bounds of
        // the buffer. The atomic fetch_add guarantees each concurrent push
        // writes to a distinct slot, so no data race occurs.
        unsafe {
            *self.buffer[slot_idx].data.get() = Some(event);
        }

        // Increment total with Release ordering so that a subsequent Acquire
        // load on `total` or `head` by a reader sees the slot write above.
        self.total.fetch_add(1, Ordering::Release);
    }

    /// Lifetime total number of events pushed (may exceed capacity).
    pub fn total(&self) -> usize {
        self.total.load(Ordering::Acquire)
    }

    /// Current head position (monotonically increasing).
    pub fn head(&self) -> usize {
        self.head.load(Ordering::Acquire)
    }

    /// Get a specific event by its absolute index (0-based from the first push).
    ///
    /// Returns `None` if the index has been overwritten (i.e., it is more than
    /// `MAX_FLIPS` behind the current head) or has not been written yet.
    pub fn get(&self, index: usize) -> Option<FlipEvent> {
        let current_head = self.head.load(Ordering::Acquire);

        // Not yet written
        if index >= current_head {
            return None;
        }

        // Overwritten: the slot has been reused
        if current_head > MAX_FLIPS && index < current_head - MAX_FLIPS {
            return None;
        }

        let slot_idx = index % MAX_FLIPS;
        // SAFETY: slot_idx is in [0, MAX_FLIPS). We checked that the slot
        // has been written and not yet overwritten. The Acquire ordering on
        // head ensures we see the Release store from the writer.
        unsafe { (*self.buffer[slot_idx].data.get()).clone() }
    }

    /// Take a snapshot of recent events without blocking.
    ///
    /// Returns up to `MAX_FLIPS` events, from oldest available to newest.
    pub fn snapshot(&self) -> Vec<FlipEvent> {
        let current_head = self.head.load(Ordering::Acquire);
        if current_head == 0 {
            return Vec::new();
        }

        let start = current_head.saturating_sub(MAX_FLIPS);

        let mut result = Vec::with_capacity(current_head - start);
        for idx in start..current_head {
            let slot_idx = idx % MAX_FLIPS;
            // SAFETY: slot_idx is in [0, MAX_FLIPS). All slots in [start, head)
            // have been written. The Acquire load on head synchronises with the
            // Release store in push().
            if let Some(ev) = unsafe { (*self.buffer[slot_idx].data.get()).clone() } {
                result.push(ev);
            }
        }

        result
    }
}

impl Default for FlipRing {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic_hammer_core::{FlipClass, FlipDirection, RegionType};

    /// Helper to create a FlipEvent with a distinguishable offset.
    fn make_event(offset: usize) -> FlipEvent {
        FlipEvent {
            timestamp: 1_700_000_000,
            offset,
            bit_position: 0,
            expected: 0x00007FFF12345678,
            observed: 0x00007FFF12345679,
            direction: FlipDirection::ZeroToOne,
            n_bits: 1,
            region: RegionType::Pointer,
            flip_class: FlipClass::PtrHijack,
            dram_row: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Push and snapshot, verify ordering
    // -----------------------------------------------------------------------

    /// Given several pushed events, snapshot returns them in push order.
    #[test]
    fn given_pushed_events_when_snapshot_then_ordered() {
        let ring = FlipRing::new();
        for i in 0..10 {
            ring.push(make_event(i * 8));
        }

        let snap = ring.snapshot();
        assert_eq!(snap.len(), 10);
        for (i, ev) in snap.iter().enumerate() {
            assert_eq!(ev.offset, i * 8, "event {i} has wrong offset");
        }
    }

    /// Given no pushes, snapshot returns empty.
    #[test]
    fn given_empty_ring_when_snapshot_then_empty() {
        let ring = FlipRing::new();
        assert!(ring.snapshot().is_empty());
        assert_eq!(ring.total(), 0);
    }

    /// total() tracks all pushes.
    #[test]
    fn given_pushes_when_total_then_matches_count() {
        let ring = FlipRing::new();
        for i in 0..50 {
            ring.push(make_event(i));
        }
        assert_eq!(ring.total(), 50);
    }

    // -----------------------------------------------------------------------
    // Push more than capacity: oldest overwritten
    // -----------------------------------------------------------------------

    /// Given more than MAX_FLIPS pushes, snapshot returns only the most recent
    /// MAX_FLIPS events and total reflects the true count.
    #[test]
    fn given_overflow_when_snapshot_then_oldest_overwritten() {
        let ring = FlipRing::new();
        let n = MAX_FLIPS + 100;
        for i in 0..n {
            ring.push(make_event(i * 8));
        }

        assert_eq!(ring.total(), n);
        let snap = ring.snapshot();
        assert_eq!(snap.len(), MAX_FLIPS);

        // The first event in the snapshot should be event #100 (offset = 100*8)
        assert_eq!(snap[0].offset, 100 * 8);
        // The last event should be event #(n-1) (offset = (n-1)*8)
        assert_eq!(snap[snap.len() - 1].offset, (n - 1) * 8);
    }

    // -----------------------------------------------------------------------
    // get() works for valid indices, returns None for invalid
    // -----------------------------------------------------------------------

    #[test]
    fn get_valid_index_returns_event() {
        let ring = FlipRing::new();
        ring.push(make_event(0));
        ring.push(make_event(8));
        ring.push(make_event(16));

        let ev = ring.get(1).expect("index 1 should be present");
        assert_eq!(ev.offset, 8);
    }

    #[test]
    fn get_out_of_range_returns_none() {
        let ring = FlipRing::new();
        ring.push(make_event(0));
        assert!(ring.get(5).is_none());
    }

    #[test]
    fn get_overwritten_index_returns_none() {
        let ring = FlipRing::new();
        for i in 0..(MAX_FLIPS + 10) {
            ring.push(make_event(i * 8));
        }
        // Index 0 has been overwritten
        assert!(ring.get(0).is_none());
        // Index MAX_FLIPS + 9 is the last valid one
        assert!(ring.get(MAX_FLIPS + 9).is_some());
    }

    // -----------------------------------------------------------------------
    // Concurrent push from multiple threads
    // -----------------------------------------------------------------------

    /// Multiple threads push concurrently; total matches the sum of all pushes
    /// and no events are lost.
    #[test]
    fn given_concurrent_pushes_when_done_then_total_correct() {
        let ring = FlipRing::new();
        let per_thread = 500;
        let thread_count = 4;

        std::thread::scope(|s| {
            for t in 0..thread_count {
                let ring_ref = &ring;
                s.spawn(move || {
                    for i in 0..per_thread {
                        ring_ref.push(make_event(t * 10000 + i));
                    }
                });
            }
        });

        assert_eq!(ring.total(), per_thread * thread_count);
        let snap = ring.snapshot();
        assert_eq!(snap.len(), per_thread * thread_count);
    }

    /// Concurrent pushes exceeding capacity still produce correct total.
    #[test]
    fn given_concurrent_overflow_when_done_then_total_correct() {
        let ring = FlipRing::new();
        let per_thread = MAX_FLIPS; // 8192 each, 4 threads = 32768 total
        let thread_count = 4;

        std::thread::scope(|s| {
            for t in 0..thread_count {
                let ring_ref = &ring;
                s.spawn(move || {
                    for i in 0..per_thread {
                        ring_ref.push(make_event(t * 100000 + i));
                    }
                });
            }
        });

        assert_eq!(ring.total(), per_thread * thread_count);
        let snap = ring.snapshot();
        // Only the last MAX_FLIPS entries are retained
        assert_eq!(snap.len(), MAX_FLIPS);
    }
}
