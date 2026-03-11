//! Scan logic for the memory arena.
//!
//! Reads every u64 word via volatile loads, compares against expected sentinels,
//! and collects detected bit flips as `FlipEvent` values. Matches the C
//! `scan_arena()` function.

use cosmic_hammer_core::{classify_flip, ArenaConfig, FlipDirection, FlipEvent, RegionType};
use cosmic_hammer_pte::PteModel;
use std::sync::atomic::{fence, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::fill::expected_at;

/// Determine which `RegionType` a byte offset falls into.
pub fn region_for_offset(byte_offset: usize, config: &ArenaConfig) -> RegionType {
    let region_idx = byte_offset / config.region_size;
    RegionType::from_index(region_idx).unwrap_or(RegionType::Data)
}

/// Scan the entire arena for bit flips. Returns all detected `FlipEvent` values.
///
/// For each u64 word, a volatile read is performed and compared against the
/// expected sentinel. On mismatch a `FlipEvent` is built, then the sentinel is
/// restored via volatile write so the word is not re-reported on the next scan.
///
/// # Safety
///
/// `base` must point to a valid allocation of at least
/// `config.region_count * config.region_size` bytes. The pointer must remain
/// valid for the duration of the scan.
pub unsafe fn scan_arena(
    base: *mut u8,
    config: &ArenaConfig,
    pte_model: &dyn PteModel,
) -> Vec<FlipEvent> {
    let total_words = (config.region_count * config.region_size) / core::mem::size_of::<u64>();
    let words = base as *mut u64;
    let mut found = Vec::new();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for i in 0..total_words {
        let byte_off = i * core::mem::size_of::<u64>();
        let expected = expected_at(byte_off, config, pte_model);

        // SAFETY: `words.add(i)` is within the arena allocation. The volatile
        // read forces an actual load from memory, preventing the compiler from
        // hoisting or CSE-ing the read.
        let observed = std::ptr::read_volatile(words.add(i));

        if observed == expected {
            continue;
        }

        // -- Flip detected --
        let diff = expected ^ observed;
        let bit_pos = diff.trailing_zeros() as u8;
        let direction = if (observed >> bit_pos) & 1 == 1 {
            FlipDirection::ZeroToOne
        } else {
            FlipDirection::OneToZero
        };
        let n_bits = diff.count_ones();
        let rtype = region_for_offset(byte_off, config);
        let dram_row = (byte_off / 8192) as u32;

        let flip_class = if rtype == RegionType::PteSim {
            pte_model.classify_flip(expected, observed)
        } else {
            classify_flip(rtype, expected, observed, direction.as_int(), n_bits)
        };

        let ev = FlipEvent {
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
        };

        found.push(ev);

        // Restore sentinel so the word is not re-reported on next scan.
        // SAFETY: same pointer validity as the read above.
        std::ptr::write_volatile(words.add(i), expected);
    }

    found
}

/// Spray pass: volatile read one word per 4KB page to keep pages resident.
///
/// Matches the C `spray_pass()` function — touches exactly one word per
/// 4KB page, then issues a full memory fence.
///
/// # Safety
///
/// `base` must point to a valid allocation of at least `total_size` bytes.
pub unsafe fn spray_pass(base: *const u8, total_size: usize) {
    let words = base as *const u64;
    let stride = 4096 / core::mem::size_of::<u64>(); // 512 words
    let total_words = total_size / core::mem::size_of::<u64>();

    let mut i = 0;
    while i < total_words {
        // SAFETY: `words.add(i)` is within the arena. The volatile read
        // forces a real load, faulting the page back in if reclaimed.
        let _ = std::ptr::read_volatile(words.add(i));
        i += stride;
    }

    fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_for_offset_all_five_regions() {
        let config = ArenaConfig::new(512);
        assert_eq!(region_for_offset(0, &config), RegionType::Pointer);
        assert_eq!(
            region_for_offset(config.region_size, &config),
            RegionType::RetAddr
        );
        assert_eq!(
            region_for_offset(2 * config.region_size, &config),
            RegionType::Permission
        );
        assert_eq!(
            region_for_offset(3 * config.region_size, &config),
            RegionType::Data
        );
        assert_eq!(
            region_for_offset(4 * config.region_size, &config),
            RegionType::PteSim
        );
    }
}
