// Tests for the ARM64 PTE model.
//
// Based on ARM DDI 0487 (AArch64 VMSAv8-64 stage-1 page descriptor, 4KB granule).
//
// Bit layout summary for level-3 page descriptor:
//   Bit  0 : Valid (must be 1)
//   Bit  1 : Type  (must be 1 for a page descriptor at L3)
//   Bits 11:2 : Lower attrs: AF(10), SH(9:8), AP(7:6), NS(5), NG(11)
//   Bits 47:12 : Output Address (OA)
//   Bit 53 : PXN – Privileged Execute-Never
//   Bit 54 : UXN – Unprivileged Execute-Never
//
// Sentinel (normal user RW page, not execute-never):
//   Valid=1, Type=1, AF=1, SH=ISH(0b11), AP=EL0-RW(0b01)
//   → ctrl portion = 0x0000_0000_0000_0713
//   OA encodes (i & 0xFFFFF) << 12.
//
// Tests are EXPECTED TO FAIL (unimplemented) until production code exists.

use cosmic_hammer_core::FlipClass;
use cosmic_hammer_pte::arm64::Arm64Pte;
use cosmic_hammer_pte::PteModel;

fn model() -> Arm64Pte {
    Arm64Pte
}

// ---------------------------------------------------------------------------
// pte_for_index — valid descriptor structure
// ---------------------------------------------------------------------------

/// Given index 0, when pte_for_index is called, the Valid bit (bit 0) is set.
///
/// A descriptor with Valid=0 is ignored by the MMU; our sentinel must always
/// produce valid descriptors.
#[test]
fn given_any_index_when_pte_for_index_then_valid_bit_set() {
    for i in [0usize, 1, 7, 0xFFFFF] {
        let pte = model().pte_for_index(i);
        assert_ne!(pte & 0x1, 0, "index {i:#x}: Valid (bit 0) must be 1");
    }
}

/// Given any index, the Type bit (bit 1) is set (page descriptor, not block).
#[test]
fn given_any_index_when_pte_for_index_then_type_bit_set() {
    for i in [0usize, 1, 42] {
        let pte = model().pte_for_index(i);
        assert_ne!(
            pte & 0x2,
            0,
            "index {i:#x}: Type (bit 1) must be 1 for a page descriptor"
        );
    }
}

/// Given index 0, the Output Address bits [47:12] are zero.
#[test]
fn given_index_zero_when_pte_for_index_then_oa_is_zero() {
    let pte = model().pte_for_index(0);
    // OA mask = bits [47:12]
    let oa_mask: u64 = 0x0000_FFFF_FFFF_F000;
    assert_eq!(pte & oa_mask, 0, "index 0: OA field must be zero");
}

/// Given index 1, the OA field encodes page frame 1 (bit 12 set).
#[test]
fn given_index_one_when_pte_for_index_then_oa_encodes_frame_one() {
    let pte = model().pte_for_index(1);
    assert_ne!(pte & (1u64 << 12), 0, "index 1: bit 12 of OA must be set");
}

/// Given index 0x100000 (one past the 20-bit mask boundary),
/// the OA wraps to the same value as index 0.
#[test]
fn given_index_over_20bit_max_when_pte_for_index_then_oa_wraps() {
    let pte_0 = model().pte_for_index(0);
    let pte_wrap = model().pte_for_index(0x100000);
    assert_eq!(
        pte_0, pte_wrap,
        "index 0x100000 must wrap to same OA as index 0"
    );
}

// ---------------------------------------------------------------------------
// classify_flip — UXN bit (Unprivileged Execute-Never)
// ---------------------------------------------------------------------------

/// Given UXN (bit 54) cleared (1→0), when classify_flip is called,
/// then result indicates NX-equivalent cleared (PteNxClear).
///
/// UXN clear allows unprivileged execution of a previously non-executable page.
#[test]
fn given_uxn_cleared_when_classify_flip_then_pte_nx_clear() {
    // Build a PTE with UXN=1 then clear it.
    let expected = model().pte_for_index(0) | (1u64 << 54); // UXN=1
    let observed = expected ^ (1u64 << 54); // clear UXN
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::PteNxClear,
        "UXN 1→0 must be PteNxClear"
    );
}

/// Given PXN (bit 53) cleared (1→0), when classify_flip is called,
/// then result indicates privileged-NX cleared (at least PteNxClear severity).
#[test]
fn given_pxn_cleared_when_classify_flip_then_high_severity_class() {
    let expected = model().pte_for_index(0) | (1u64 << 53); // PXN=1
    let observed = expected ^ (1u64 << 53); // clear PXN
    let class = model().classify_flip(expected, observed);
    // PXN clear is at least as severe as DataCorrupt; it must not be Benign.
    assert_ne!(class, FlipClass::Benign, "PXN 1→0 must not be Benign");
    assert_ne!(
        class,
        FlipClass::DataCorrupt,
        "PXN 1→0 must be a privilege-related class"
    );
}

// ---------------------------------------------------------------------------
// classify_flip — Output Address corruption
// ---------------------------------------------------------------------------

/// Given an OA bit (bit 20, in the [47:12] range) flipped,
/// when classify_flip is called, then result is PtePhysCorrupt.
#[test]
fn given_oa_bit_flipped_when_classify_flip_then_pte_phys_corrupt() {
    let expected = model().pte_for_index(0);
    let observed = expected ^ (1u64 << 20); // bit 20 is in OA range [47:12]
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::PtePhysCorrupt,
        "OA bit flip must be PtePhysCorrupt"
    );
}

/// Given a high OA bit (bit 40, still inside [47:12]) flipped,
/// the result remains PtePhysCorrupt.
#[test]
fn given_high_oa_bit_flipped_when_classify_flip_then_pte_phys_corrupt() {
    let expected = model().pte_for_index(0);
    let observed = expected ^ (1u64 << 40);
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::PtePhysCorrupt,
        "OA bit 40 flip must be PtePhysCorrupt"
    );
}

// ---------------------------------------------------------------------------
// classify_flip — AP field (Access Permissions, bits 7:6)
// ---------------------------------------------------------------------------

/// Given AP[1] (bit 7) flipped, escalating permissions,
/// when classify_flip is called, then a privilege-class result is returned.
///
/// AP bits control EL0 / EL1 read/write access; flipping them can grant
/// unexpected write access to user or supervisor pages.
#[test]
fn given_ap_bit7_flipped_when_classify_flip_then_privilege_class() {
    let expected = model().pte_for_index(0);
    let observed = expected ^ (1u64 << 7); // flip AP[1]
    let class = model().classify_flip(expected, observed);
    assert_ne!(class, FlipClass::Benign, "AP[1] flip must not be Benign");
}

// ---------------------------------------------------------------------------
// ctrl_bits / pa_mask sanity
// ---------------------------------------------------------------------------

/// The ctrl_bits must include Valid (bit 0) and Type (bit 1).
#[test]
fn when_ctrl_bits_queried_then_valid_and_type_included() {
    let m = model();
    assert_ne!(m.ctrl_bits() & 0x1, 0, "Valid (bit 0) must be in ctrl_bits");
    assert_ne!(m.ctrl_bits() & 0x2, 0, "Type (bit 1) must be in ctrl_bits");
}

/// The pa_mask (OA field) must not overlap ctrl_bits.
#[test]
fn when_pa_mask_queried_then_no_overlap_with_ctrl_bits() {
    let m = model();
    assert_eq!(
        m.pa_mask() & m.ctrl_bits(),
        0,
        "OA mask and ctrl_bits must be disjoint"
    );
}

/// The pa_mask must cover at least bits [47:12] (36 bits for 4KB granule).
#[test]
fn when_pa_mask_queried_then_covers_bits_47_to_12() {
    let oa_range: u64 = 0x0000_FFFF_FFFF_F000;
    let m = model();
    assert_eq!(
        m.pa_mask() & oa_range,
        oa_range,
        "OA mask must cover bits [47:12]"
    );
}
