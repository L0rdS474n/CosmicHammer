//! Fill logic for the memory arena.
//!
//! Writes sentinel patterns to all five typed regions, matching the C
//! `fill_arena()` function exactly.

use cosmic_hammer_core::{
    ArenaConfig, FILL_DATA_A, FILL_DATA_B, FILL_PERMISSION, FILL_POINTER, FILL_RETADDR,
};
use cosmic_hammer_pte::PteModel;
use std::sync::atomic::{fence, Ordering};

/// Fill all regions of the arena with their expected sentinel patterns.
///
/// # Safety
///
/// `base` must point to a valid, writeable allocation of at least
/// `config.region_count * config.region_size` bytes. The caller must ensure
/// exclusive access during the fill (no concurrent reads/writes).
pub unsafe fn fill_arena(base: *mut u8, config: &ArenaConfig, pte_model: &dyn PteModel) {
    let region_size = config.region_size;
    let words_per_region = region_size / core::mem::size_of::<u64>();

    // Region 0 — Pointer: every u64 = FILL_POINTER
    {
        let r = base as *mut u64;
        for i in 0..words_per_region {
            // SAFETY: pointer is within the arena allocation, which is valid
            // for writes for the lifetime of PinnedArena. Index is bounded by
            // words_per_region which is derived from region_size.
            std::ptr::write_volatile(r.add(i), FILL_POINTER);
        }
    }

    // Region 1 — RetAddr: every u64 = FILL_RETADDR
    {
        let r = base.add(region_size) as *mut u64;
        for i in 0..words_per_region {
            // SAFETY: same as above — within region 1 bounds.
            std::ptr::write_volatile(r.add(i), FILL_RETADDR);
        }
    }

    // Region 2 — Permission: every u64 = FILL_PERMISSION
    {
        let r = base.add(2 * region_size) as *mut u64;
        for i in 0..words_per_region {
            // SAFETY: same as above — within region 2 bounds.
            std::ptr::write_volatile(r.add(i), FILL_PERMISSION);
        }
    }

    // Region 3 — Data: alternating FILL_DATA_A (even) / FILL_DATA_B (odd)
    {
        let r = base.add(3 * region_size) as *mut u64;
        for i in 0..words_per_region {
            let val = if i & 1 == 0 { FILL_DATA_A } else { FILL_DATA_B };
            // SAFETY: same as above — within region 3 bounds.
            std::ptr::write_volatile(r.add(i), val);
        }
    }

    // Region 4 — PteSim: pte_model.pte_for_index(word_idx) for each word
    {
        let r = base.add(4 * region_size) as *mut u64;
        for i in 0..words_per_region {
            // SAFETY: same as above — within region 4 bounds.
            std::ptr::write_volatile(r.add(i), pte_model.pte_for_index(i));
        }
    }

    // Full memory fence matching C's __sync_synchronize()
    fence(Ordering::SeqCst);
}

/// Return the expected sentinel value for a given byte offset within the arena.
///
/// Matches the C `expected_at()` function exactly:
/// - region index = byte_offset / region_size
/// - word index within region = (byte_offset - region_index * region_size) / 8
pub fn expected_at(byte_offset: usize, config: &ArenaConfig, pte_model: &dyn PteModel) -> u64 {
    let region_idx = byte_offset / config.region_size;
    let word_idx = (byte_offset - region_idx * config.region_size) / core::mem::size_of::<u64>();

    match region_idx {
        0 => FILL_POINTER,
        1 => FILL_RETADDR,
        2 => FILL_PERMISSION,
        3 => {
            if word_idx & 1 == 0 {
                FILL_DATA_A
            } else {
                FILL_DATA_B
            }
        }
        4 => pte_model.pte_for_index(word_idx),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmic_hammer_pte::x86_64::X86_64Pte;

    #[test]
    fn expected_at_pointer_region() {
        let config = ArenaConfig::new(512);
        let pte = X86_64Pte;
        // First word of region 0
        assert_eq!(expected_at(0, &config, &pte), FILL_POINTER);
        // Another word in region 0
        assert_eq!(expected_at(64, &config, &pte), FILL_POINTER);
    }

    #[test]
    fn expected_at_retaddr_region() {
        let config = ArenaConfig::new(512);
        let pte = X86_64Pte;
        let offset = config.region_size; // start of region 1
        assert_eq!(expected_at(offset, &config, &pte), FILL_RETADDR);
    }

    #[test]
    fn expected_at_permission_region() {
        let config = ArenaConfig::new(512);
        let pte = X86_64Pte;
        let offset = 2 * config.region_size;
        assert_eq!(expected_at(offset, &config, &pte), FILL_PERMISSION);
    }

    #[test]
    fn expected_at_data_region_alternating() {
        let config = ArenaConfig::new(512);
        let pte = X86_64Pte;
        let base = 3 * config.region_size;
        // word 0 (even) => DATA_A
        assert_eq!(expected_at(base, &config, &pte), FILL_DATA_A);
        // word 1 (odd) => DATA_B
        assert_eq!(expected_at(base + 8, &config, &pte), FILL_DATA_B);
        // word 2 (even) => DATA_A
        assert_eq!(expected_at(base + 16, &config, &pte), FILL_DATA_A);
    }

    #[test]
    fn expected_at_pte_sim_region() {
        let config = ArenaConfig::new(512);
        let pte = X86_64Pte;
        let base = 4 * config.region_size;
        // word 0
        assert_eq!(expected_at(base, &config, &pte), pte.pte_for_index(0));
        // word 1
        assert_eq!(expected_at(base + 8, &config, &pte), pte.pte_for_index(1));
        // word 100
        assert_eq!(
            expected_at(base + 100 * 8, &config, &pte),
            pte.pte_for_index(100)
        );
    }
}
