// Tests for the x86-64 PTE model.
//
// All test vectors are derived from the C source (cosmic_rowhammer.c) and the
// Intel SDM Vol.3A §4.5 specification.  Tests are written BEFORE implementation
// (TDD / test-first); they are expected to panic with "not yet implemented"
// until the production code is filled in.
//
// Bit layout reminder:
//   P   = bit  0
//   RW  = bit  1
//   US  = bit  2
//   NX  = bit 63
//   PA  = bits [51:12]  (mask 0x000F_FFFF_FFFF_F000)
//
// Sentinel for a "normal user RW page, NX set":
//   P=1 | RW=1 | US=1 | NX=1 = 0x8000_0000_0000_0007
//   plus the PA field: (i & 0xFFFFF) << 12

use cosmic_hammer_core::FlipClass;
use cosmic_hammer_pte::x86_64::X86_64Pte;
use cosmic_hammer_pte::PteModel;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn model() -> X86_64Pte {
    X86_64Pte
}

// ---------------------------------------------------------------------------
// pte_for_index — address generation and wrapping
// ---------------------------------------------------------------------------

/// Given index 0, the PA field is zero and the sentinel ctrl bits are set.
///
/// Expected: 0x8000_0000_0000_0007
#[test]
fn given_index_zero_when_pte_for_index_then_ctrl_bits_set_pa_zero() {
    // EXPECTED TO FAIL (unimplemented) until production code exists.
    let pte = model().pte_for_index(0);
    assert_eq!(pte, 0x8000_0000_0000_0007, "index 0: P|RW|US|NX set, PA=0");
}

/// Given index 1, the PA field encodes page frame 1 (bits[12] set).
///
/// Expected: 0x8000_0000_0000_1007
#[test]
fn given_index_one_when_pte_for_index_then_pa_encodes_frame_one() {
    let pte = model().pte_for_index(1);
    assert_eq!(pte, 0x8000_0000_0000_1007, "index 1: PA = 0x1000");
}

/// Given index 0xFFFFF (maximum of 20-bit index), PA occupies bits[31:12].
///
/// Expected: 0x8000_0000_FFFF_F007
/// Note: (0xFFFFF << 12) = 0x0000_0000_FFFF_F000
#[test]
fn given_max_20bit_index_when_pte_for_index_then_pa_at_bits_31_12() {
    let pte = model().pte_for_index(0xFFFFF);
    assert_eq!(
        pte, 0x8000_0000_FFFF_F007,
        "index 0xFFFFF: PA at bits[31:12]"
    );
}

/// Given index 0x100000 (one past the 20-bit mask), the index wraps — same
/// output as index 0.
///
/// Expected: 0x8000_0000_0000_0007  (wraps to i & 0xFFFFF == 0)
#[test]
fn given_index_over_20bit_max_when_pte_for_index_then_wraps_to_zero() {
    let pte = model().pte_for_index(0x100000);
    assert_eq!(
        pte, 0x8000_0000_0000_0007,
        "index 0x100000 wraps to same as index 0"
    );
}

/// Given any index, the P, RW, US flags (bits 0–2) are always set.
#[test]
fn given_any_index_when_pte_for_index_then_p_rw_us_bits_set() {
    for i in [0usize, 1, 42, 0xFFFFF, 0x100000] {
        let pte = model().pte_for_index(i);
        assert_eq!(pte & 0x7, 0x7, "index {i:#x}: P|RW|US must be 1");
    }
}

/// Given any index, the NX bit (bit 63) is always set.
#[test]
fn given_any_index_when_pte_for_index_then_nx_bit_set() {
    for i in [0usize, 1, 0xABCDE] {
        let pte = model().pte_for_index(i);
        assert_ne!(pte & (1u64 << 63), 0, "index {i:#x}: NX (bit 63) must be 1");
    }
}

// ---------------------------------------------------------------------------
// classify_flip — NX bit (highest priority)
// ---------------------------------------------------------------------------

/// Given expected PTE with NX=1 and observed PTE with NX=0,
/// when classify_flip is called, then result is PteNxClear.
///
/// NX clear (1→0) is the highest-severity classification.
#[test]
fn given_nx_cleared_when_classify_flip_then_pte_nx_clear() {
    let expected = model().pte_for_index(0); // NX=1
    let observed = expected ^ (1u64 << 63); // clear NX
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::PteNxClear,
        "NX 1→0 must be PteNxClear"
    );
}

/// Given expected PTE with NX=0 and observed PTE with NX=1 (0→1 flip),
/// when classify_flip is called, then result is NOT PteNxClear.
///
/// NX set (0→1) makes the page non-executable — that's less severe and
/// must NOT be classified as PteNxClear.
#[test]
fn given_nx_set_zero_to_one_when_classify_flip_then_not_pte_nx_clear() {
    // Build a PTE where NX=0 (executable page) then flip NX to 1.
    let expected = model().pte_for_index(0) & !(1u64 << 63); // NX=0
    let observed = expected | (1u64 << 63); // set NX (0→1)
    let class = model().classify_flip(expected, observed);
    assert_ne!(
        class,
        FlipClass::PteNxClear,
        "NX 0→1 must NOT be PteNxClear (NX becoming set is not the dangerous direction)"
    );
}

/// Given NX cleared AND PA also corrupted in the same PTE,
/// when classify_flip is called, then NX-clear takes priority.
#[test]
fn given_nx_cleared_and_pa_corrupt_when_classify_flip_then_nx_takes_priority() {
    let expected = model().pte_for_index(1);
    // Flip both NX and a PA bit simultaneously.
    let observed = expected ^ (1u64 << 63) ^ (1u64 << 20);
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::PteNxClear,
        "NX-clear must take priority over PA corruption"
    );
}

// ---------------------------------------------------------------------------
// classify_flip — Physical Address corruption
// ---------------------------------------------------------------------------

/// Given a PA bit flipped (bit 20, inside the PA mask [51:12]),
/// when classify_flip is called, then result is PtePhysCorrupt.
#[test]
fn given_pa_bit_flipped_when_classify_flip_then_pte_phys_corrupt() {
    let expected = model().pte_for_index(0);
    let observed = expected ^ (1u64 << 20); // bit 20 is in PA range
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::PtePhysCorrupt,
        "PA bit flip must be PtePhysCorrupt"
    );
}

// ---------------------------------------------------------------------------
// classify_flip — Present bit (P)
// ---------------------------------------------------------------------------

/// Given Present bit (bit 0) cleared (1→0),
/// when classify_flip is called, then result is PtePresentClear.
#[test]
fn given_present_bit_cleared_when_classify_flip_then_pte_present_clear() {
    let expected = model().pte_for_index(0); // P=1
    let observed = expected ^ 1u64; // clear bit 0
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::PtePresentClear,
        "P 1→0 must be PtePresentClear"
    );
}

// ---------------------------------------------------------------------------
// classify_flip — Read/Write bit (RW)
// ---------------------------------------------------------------------------

/// Given a PTE where RW=0 and the flip sets RW to 1 (0→1),
/// when classify_flip is called, then result is PteWriteSet.
///
/// This represents a read-only mapping becoming writable — a privilege
/// escalation scenario.
#[test]
fn given_rw_set_zero_to_one_when_classify_flip_then_pte_write_set() {
    // Build a PTE with RW=0 (read-only user page with NX set).
    // P=1, RW=0, US=1, NX=1 → 0x8000_0000_0000_0005
    let expected = 0x8000_0000_0000_0005u64;
    let observed = expected | (1u64 << 1); // set RW (0→1)
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::PteWriteSet,
        "RW 0→1 must be PteWriteSet"
    );
}

// ---------------------------------------------------------------------------
// classify_flip — User/Supervisor bit (US)
// ---------------------------------------------------------------------------

/// Given US bit (bit 2) cleared (1→0) with no other changes,
/// when classify_flip is called, then result is PteSupervisorEsc.
///
/// US clear locks the page out of user-mode, which is a DoS-class event.
#[test]
fn given_us_bit_cleared_when_classify_flip_then_pte_supervisor_esc() {
    let expected = model().pte_for_index(0); // US=1
    let observed = expected ^ (1u64 << 2); // clear US
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::PteSupervisorEsc,
        "US 1→0 must be PteSupervisorEsc"
    );
}

// ---------------------------------------------------------------------------
// classify_flip — Non-control bits → DataCorrupt
// ---------------------------------------------------------------------------

/// Given a flip in a non-control, non-PA bit (e.g., Dirty bit = bit 6 or
/// Accessed bit = bit 5), when classify_flip is called, then result is
/// DataCorrupt.
///
/// These bits are within a PTE but carry no exploitable semantics.
#[test]
fn given_dirty_bit_flipped_when_classify_flip_then_data_corrupt() {
    let expected = model().pte_for_index(0);
    // Bit 6 = Dirty; it is NOT in PA range [51:12] and not a control bit.
    let observed = expected ^ (1u64 << 6);
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::DataCorrupt,
        "Dirty-bit flip must be DataCorrupt"
    );
}

/// Given a flip in the Accessed bit (bit 5), which is also a non-control,
/// non-PA bit, when classify_flip is called, then result is DataCorrupt.
#[test]
fn given_accessed_bit_flipped_when_classify_flip_then_data_corrupt() {
    let expected = model().pte_for_index(0);
    // Bit 5 = Accessed — not in PA mask, not a security-relevant control bit.
    let observed = expected ^ (1u64 << 5);
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::DataCorrupt,
        "Accessed-bit flip must be DataCorrupt"
    );
}

// ---------------------------------------------------------------------------
// ctrl_bits / pa_mask constants are consistent
// ---------------------------------------------------------------------------

/// The ctrl_bits returned by the model must include P, RW, US, and NX.
#[test]
fn when_ctrl_bits_queried_then_p_rw_us_nx_all_set() {
    let m = model();
    let ctrl = m.ctrl_bits();
    assert_ne!(ctrl & (1u64 << 0), 0, "P bit must be in ctrl_bits");
    assert_ne!(ctrl & (1u64 << 1), 0, "RW bit must be in ctrl_bits");
    assert_ne!(ctrl & (1u64 << 2), 0, "US bit must be in ctrl_bits");
    assert_ne!(ctrl & (1u64 << 63), 0, "NX bit must be in ctrl_bits");
}

/// The pa_mask must not overlap with any ctrl_bits.
#[test]
fn when_pa_mask_queried_then_no_overlap_with_ctrl_bits() {
    let m = model();
    assert_eq!(
        m.pa_mask() & m.ctrl_bits(),
        0,
        "PA mask and control bits must be disjoint"
    );
}

/// The pa_mask must cover bits [51:12].
#[test]
fn when_pa_mask_queried_then_covers_bits_51_to_12() {
    // Bits [51:12] = 40 bits wide.
    let expected_mask: u64 = 0x000F_FFFF_FFFF_F000;
    let m = model();
    // The PA mask must at least cover the canonical [51:12] range.
    assert_eq!(
        m.pa_mask() & expected_mask,
        expected_mask,
        "PA mask must cover bits [51:12]"
    );
}
