//! Arena management: owns the pinned memory, fills sentinels, and scans for flips.

use cosmic_hammer_core::{ArenaConfig, FlipEvent, RegionType};
use cosmic_hammer_platform::PinnedArena;
use cosmic_hammer_pte::PteModel;

use crate::fill::{expected_at, fill_arena};
use crate::scan::{region_for_offset, scan_arena, spray_pass};

/// Owns a pinned memory arena, its configuration, and the PTE model.
///
/// Provides high-level fill/scan/spray operations over the raw memory.
pub struct Arena {
    inner: Box<dyn PinnedArena>,
    config: ArenaConfig,
    pte_model: Box<dyn PteModel>,
}

impl Arena {
    /// Create a new Arena wrapping the given pinned memory, config, and PTE model.
    pub fn new(
        inner: Box<dyn PinnedArena>,
        config: ArenaConfig,
        pte_model: Box<dyn PteModel>,
    ) -> Self {
        Self {
            inner,
            config,
            pte_model,
        }
    }

    /// Fill all regions with their sentinel patterns using volatile writes.
    pub fn fill(&mut self) {
        let base = self.inner.as_mut_ptr();
        // SAFETY: `base` is a valid mutable pointer to `inner.len()` bytes of
        // pinned memory. The Box<dyn PinnedArena> guarantees the allocation is
        // valid for the lifetime of `self`. We have `&mut self` so no concurrent
        // access is possible.
        unsafe {
            fill_arena(base, &self.config, self.pte_model.as_ref());
        }
    }

    /// Return the expected sentinel value for a given byte offset.
    pub fn expected_at(&self, byte_offset: usize) -> u64 {
        expected_at(byte_offset, &self.config, self.pte_model.as_ref())
    }

    /// Scan all words for bit flips, returning detected events.
    ///
    /// Each mismatch is recorded as a `FlipEvent` and the sentinel is restored
    /// via volatile write so the word is not re-reported on the next scan.
    pub fn scan(&mut self) -> Vec<FlipEvent> {
        let base = self.inner.as_mut_ptr();
        // SAFETY: same pointer validity as fill(). The arena is exclusively
        // borrowed via `&mut self`.
        unsafe { scan_arena(base, &self.config, self.pte_model.as_ref()) }
    }

    /// Spray pass: touch one word per 4KB page to keep pages resident.
    pub fn spray_pass(&self) {
        let base = self.inner.as_ptr();
        let total = self.inner.len();
        // SAFETY: `base` is valid for `total` bytes of readable memory.
        // spray_pass only performs volatile reads with no writes.
        unsafe {
            spray_pass(base, total);
        }
    }

    /// Determine which region type a byte offset falls into.
    pub fn region_for_offset(&self, byte_offset: usize) -> RegionType {
        region_for_offset(byte_offset, &self.config)
    }

    /// Total size of the arena in bytes.
    pub fn size(&self) -> usize {
        self.inner.len()
    }

    /// Borrow the arena config.
    pub fn config(&self) -> &ArenaConfig {
        &self.config
    }

    /// Borrow the PTE model.
    pub fn pte_model(&self) -> &dyn PteModel {
        self.pte_model.as_ref()
    }

    /// Returns the lock status of the underlying pinned memory.
    pub fn lock_status(&self) -> cosmic_hammer_platform::LockStatus {
        self.inner.lock_status()
    }

    /// Returns a const pointer to the start of the arena.
    pub fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }

    /// Borrow the inner PinnedArena's mutable pointer (for parallel scan).
    ///
    /// # Safety
    ///
    /// The caller must ensure no concurrent mutable access to the same region.
    pub unsafe fn base_mut_ptr(&mut self) -> *mut u8 {
        self.inner.as_mut_ptr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic_hammer_core::{
        FlipDirection, RegionType, FILL_DATA_A, FILL_DATA_B, FILL_PERMISSION, FILL_POINTER,
        FILL_RETADDR,
    };
    use cosmic_hammer_platform::LockStatus;
    use cosmic_hammer_pte::x86_64::X86_64Pte;

    /// A mock PinnedArena backed by a plain Vec<u8>, for testing without
    /// root/mlock. The memory is heap-allocated and page alignment is not
    /// guaranteed, but that is acceptable for unit tests.
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

    /// Helper: create a small test arena (1 MB) with MockArena.
    fn make_test_arena() -> Arena {
        let config = ArenaConfig::new(1);
        let mock = MockArena::new(config.total_size);
        let pte = X86_64Pte;
        Arena::new(Box::new(mock), config, Box::new(pte))
    }

    // -----------------------------------------------------------------------
    // Fill + Scan roundtrip: no flips after clean fill
    // -----------------------------------------------------------------------

    /// Given a freshly filled arena, when scanned, then no flips are detected.
    #[test]
    fn given_filled_arena_when_scanned_then_no_flips() {
        let mut arena = make_test_arena();
        arena.fill();
        let flips = arena.scan();
        assert!(
            flips.is_empty(),
            "expected zero flips after clean fill, got {}",
            flips.len()
        );
    }

    // -----------------------------------------------------------------------
    // Manual flip injection: detect exactly one FlipEvent
    // -----------------------------------------------------------------------

    /// Given a filled arena with one word mutated, when scanned, then exactly
    /// one FlipEvent is returned with correct fields.
    #[test]
    fn given_one_mutated_word_when_scanned_then_one_flip_detected() {
        let mut arena = make_test_arena();
        arena.fill();

        // Mutate word 0 of region 0 (Pointer): flip bit 0
        let base = unsafe { arena.base_mut_ptr() };
        let target = base as *mut u64;
        let original = FILL_POINTER;
        let corrupted = original ^ 1u64; // flip bit 0
                                         // SAFETY: target points to valid arena memory
        unsafe {
            std::ptr::write_volatile(target, corrupted);
        }

        let flips = arena.scan();
        assert_eq!(flips.len(), 1, "expected exactly 1 flip");

        let ev = &flips[0];
        assert_eq!(ev.offset, 0);
        assert_eq!(ev.bit_position, 0);
        assert_eq!(ev.expected, original);
        assert_eq!(ev.observed, corrupted);
        assert_eq!(ev.n_bits, 1);
        assert_eq!(ev.region, RegionType::Pointer);
        assert_eq!(ev.dram_row, 0);
        // bit 0 of FILL_POINTER (0x...5678) is 0, corrupted sets it to 1
        // so direction should be ZeroToOne -> but wait, let's check:
        // original = 0x00007FFF12345678, bit 0 = 0
        // corrupted = original ^ 1 = 0x00007FFF12345679, bit 0 = 1
        // observed bit 0 = 1, so direction = ZeroToOne
        assert_eq!(ev.direction, FlipDirection::ZeroToOne);
    }

    /// Given a mutated word in the Data region (region 3), the scan detects it
    /// and restores the sentinel.
    #[test]
    fn given_flip_in_data_region_when_scanned_then_detected_and_restored() {
        let mut arena = make_test_arena();
        arena.fill();

        // Mutate word 0 of region 3 (Data, even index => DATA_A)
        let region_size = arena.config().region_size;
        let byte_off = 3 * region_size;
        let base = unsafe { arena.base_mut_ptr() };
        let target = unsafe { (base.add(byte_off)) as *mut u64 };
        let corrupted = FILL_DATA_A ^ (1u64 << 33);
        unsafe {
            std::ptr::write_volatile(target, corrupted);
        }

        let flips = arena.scan();
        assert_eq!(flips.len(), 1);
        assert_eq!(flips[0].offset, byte_off);
        assert_eq!(flips[0].expected, FILL_DATA_A);
        assert_eq!(flips[0].observed, corrupted);
        assert_eq!(flips[0].region, RegionType::Data);
        assert_eq!(flips[0].bit_position, 33);

        // After scan, sentinel should be restored — second scan finds nothing
        let flips2 = arena.scan();
        assert!(
            flips2.is_empty(),
            "expected zero flips after restore, got {}",
            flips2.len()
        );
    }

    /// Given a flip in the PteSim region, the PTE classifier is used.
    #[test]
    fn given_flip_in_pte_region_when_scanned_then_pte_classified() {
        let mut arena = make_test_arena();
        arena.fill();

        let region_size = arena.config().region_size;
        let byte_off = 4 * region_size; // start of PteSim region
        let expected_pte = arena.pte_model().pte_for_index(0);
        // Flip bit 63 (NX bit) from 1 to 0
        let corrupted = expected_pte ^ (1u64 << 63);

        let base = unsafe { arena.base_mut_ptr() };
        let target = unsafe { (base.add(byte_off)) as *mut u64 };
        unsafe {
            std::ptr::write_volatile(target, corrupted);
        }

        let flips = arena.scan();
        assert_eq!(flips.len(), 1);
        assert_eq!(flips[0].region, RegionType::PteSim);
        assert_eq!(
            flips[0].flip_class,
            cosmic_hammer_core::FlipClass::PteNxClear
        );
    }

    // -----------------------------------------------------------------------
    // expected_at: test all 5 region types
    // -----------------------------------------------------------------------

    #[test]
    fn expected_at_all_five_regions() {
        let arena = make_test_arena();
        let rs = arena.config().region_size;

        // Region 0 — Pointer
        assert_eq!(arena.expected_at(0), FILL_POINTER);
        assert_eq!(arena.expected_at(8), FILL_POINTER);

        // Region 1 — RetAddr
        assert_eq!(arena.expected_at(rs), FILL_RETADDR);

        // Region 2 — Permission
        assert_eq!(arena.expected_at(2 * rs), FILL_PERMISSION);

        // Region 3 — Data (alternating)
        assert_eq!(arena.expected_at(3 * rs), FILL_DATA_A); // word 0, even
        assert_eq!(arena.expected_at(3 * rs + 8), FILL_DATA_B); // word 1, odd

        // Region 4 — PteSim
        let pte_val = arena.pte_model().pte_for_index(0);
        assert_eq!(arena.expected_at(4 * rs), pte_val);
    }

    // -----------------------------------------------------------------------
    // region_for_offset
    // -----------------------------------------------------------------------

    #[test]
    fn region_for_offset_all_regions() {
        let arena = make_test_arena();
        let rs = arena.config().region_size;
        assert_eq!(arena.region_for_offset(0), RegionType::Pointer);
        assert_eq!(arena.region_for_offset(rs), RegionType::RetAddr);
        assert_eq!(arena.region_for_offset(2 * rs), RegionType::Permission);
        assert_eq!(arena.region_for_offset(3 * rs), RegionType::Data);
        assert_eq!(arena.region_for_offset(4 * rs), RegionType::PteSim);
    }

    // -----------------------------------------------------------------------
    // Spray pass: does not crash and does not corrupt data
    // -----------------------------------------------------------------------

    #[test]
    fn spray_pass_does_not_corrupt_filled_arena() {
        let mut arena = make_test_arena();
        arena.fill();
        arena.spray_pass();
        let flips = arena.scan();
        assert!(
            flips.is_empty(),
            "spray_pass must not corrupt sentinels, got {} flips",
            flips.len()
        );
    }

    // -----------------------------------------------------------------------
    // size()
    // -----------------------------------------------------------------------

    #[test]
    fn size_matches_config_total() {
        let arena = make_test_arena();
        assert_eq!(arena.size(), ArenaConfig::new(1).total_size);
    }
}
