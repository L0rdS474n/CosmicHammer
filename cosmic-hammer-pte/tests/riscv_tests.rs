// Tests for the RISC-V Sv39 PTE model.
//
// Based on the RISC-V Privileged Specification §4.4 (Sv39 virtual memory).
//
// Sv39 PTE bit layout (8 bytes):
//   Bit  0 : V  – Valid
//   Bit  1 : R  – Readable
//   Bit  2 : W  – Writable
//   Bit  3 : X  – Executable
//   Bit  4 : U  – User-mode accessible
//   Bit  5 : G  – Global mapping
//   Bit  6 : A  – Accessed (set by hardware or software)
//   Bit  7 : D  – Dirty
//   Bits 9:8  : RSW (reserved for software use)
//   Bits 53:10 : PPN[2:0] – Physical Page Number (44 bits)
//   Bits 63:54 : Reserved (must be zero)
//
// Sentinel (user RW leaf, V=1, R=1, W=1, U=1, A=1, D=1, X=0):
//   = 0x00000000000000D7
//   PPN encodes (i & 0xFFFFF) << 10.
//
// Tests are EXPECTED TO FAIL (unimplemented) until production code exists.

use cosmic_hammer_core::FlipClass;
use cosmic_hammer_pte::riscv::RiscvSv39Pte;
use cosmic_hammer_pte::PteModel;

fn model() -> RiscvSv39Pte {
    RiscvSv39Pte
}

// ---------------------------------------------------------------------------
// pte_for_index — valid leaf PTE structure
// ---------------------------------------------------------------------------

/// Given index 0, when pte_for_index is called, the V (Valid) bit is set.
///
/// An Sv39 PTE with V=0 causes a page-fault on access; our sentinel must be valid.
#[test]
fn given_any_index_when_pte_for_index_then_valid_bit_set() {
    for i in [0usize, 1, 7, 0xFFFFF] {
        let pte = model().pte_for_index(i);
        assert_ne!(pte & 0x1, 0, "index {i:#x}: V (bit 0) must be 1");
    }
}

/// Given any index, the R (Readable) bit is set in the sentinel.
#[test]
fn given_any_index_when_pte_for_index_then_r_bit_set() {
    for i in [0usize, 1, 42] {
        let pte = model().pte_for_index(i);
        assert_ne!(pte & 0x2, 0, "index {i:#x}: R (bit 1) must be 1");
    }
}

/// Given any index, the W (Writable) bit is set in the sentinel.
#[test]
fn given_any_index_when_pte_for_index_then_w_bit_set() {
    for i in [0usize, 1, 42] {
        let pte = model().pte_for_index(i);
        assert_ne!(pte & 0x4, 0, "index {i:#x}: W (bit 2) must be 1");
    }
}

/// Given any index, the U (User) bit is set — these are user pages.
#[test]
fn given_any_index_when_pte_for_index_then_u_bit_set() {
    for i in [0usize, 1, 42] {
        let pte = model().pte_for_index(i);
        assert_ne!(pte & 0x10, 0, "index {i:#x}: U (bit 4) must be 1");
    }
}

/// Given index 0, the PPN field (bits [53:10]) is zero.
#[test]
fn given_index_zero_when_pte_for_index_then_ppn_is_zero() {
    let pte = model().pte_for_index(0);
    let ppn_mask: u64 = 0x003F_FFFF_FFFF_FC00;
    assert_eq!(pte & ppn_mask, 0, "index 0: PPN must be zero");
}

/// Given index 1, the PPN field (bits [29:10]) encodes page frame 1.
#[test]
fn given_index_one_when_pte_for_index_then_ppn_encodes_frame_one() {
    let pte = model().pte_for_index(1);
    // (1 & 0xFFFFF) << 10 = bit 10 set
    assert_ne!(pte & (1u64 << 10), 0, "index 1: bit 10 of PPN must be set");
}

/// Given index 0x100000 (one past the 20-bit wrap boundary),
/// the PPN wraps to the same as index 0.
#[test]
fn given_index_over_20bit_max_when_pte_for_index_then_ppn_wraps() {
    let pte_0 = model().pte_for_index(0);
    let pte_wrap = model().pte_for_index(0x100000);
    assert_eq!(
        pte_0, pte_wrap,
        "index 0x100000 must produce same PTE as index 0"
    );
}

// ---------------------------------------------------------------------------
// classify_flip — R, W, X permission flips
// ---------------------------------------------------------------------------

/// Given the R (Readable) bit cleared (1→0), when classify_flip is called,
/// then a security-relevant classification is returned (DoS class — page becomes
/// inaccessible, equivalent to PtePresentClear semantics in RISC-V).
#[test]
fn given_r_bit_cleared_when_classify_flip_then_security_class() {
    let expected = model().pte_for_index(0); // R=1
    let observed = expected ^ 0x2u64; // clear R
    let class = model().classify_flip(expected, observed);
    assert_ne!(class, FlipClass::Benign, "R 1→0 must not be Benign");
}

/// Given the W (Writable) bit set on a read-only page (0→1),
/// when classify_flip is called, then PteWriteSet is returned.
#[test]
fn given_w_bit_set_zero_to_one_when_classify_flip_then_pte_write_set() {
    // Build a PTE where W=0 (read-only user page).
    // V=1, R=1, W=0, U=1, A=1, D=1 = 0xD3 (no W bit)
    let expected = 0x0000_0000_0000_00D3u64; // W=0
    let observed = expected | 0x4u64; // set W (0→1)
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::PteWriteSet,
        "W 0→1 on an RO page must be PteWriteSet"
    );
}

/// Given the X (Executable) bit set (0→1) on a non-executable page,
/// when classify_flip is called, then PteNxClear (or equivalent) is returned.
///
/// In RISC-V, X=0 means non-executable; flipping to X=1 grants execution.
/// This maps to the NX-cleared severity class.
#[test]
fn given_x_bit_set_zero_to_one_when_classify_flip_then_pte_nx_clear() {
    // V=1, R=1, W=1, X=0, U=1, A=1, D=1 = 0xD7 (X=0 is our sentinel)
    let expected = model().pte_for_index(0); // X=0
    let observed = expected | 0x8u64; // set X (0→1)
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::PteNxClear,
        "X 0→1 grants execution: must be PteNxClear"
    );
}

// ---------------------------------------------------------------------------
// classify_flip — PPN (Physical Page Number) corruption
// ---------------------------------------------------------------------------

/// Given a PPN bit (bit 15, inside bits [53:10]) flipped,
/// when classify_flip is called, then result is PtePhysCorrupt.
#[test]
fn given_ppn_bit_flipped_when_classify_flip_then_pte_phys_corrupt() {
    let expected = model().pte_for_index(0);
    // Bit 15 is inside PPN[0] (bits [29:10]).
    let observed = expected ^ (1u64 << 15);
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::PtePhysCorrupt,
        "PPN bit flip must be PtePhysCorrupt"
    );
}

/// Given a high PPN bit (bit 40, inside PPN[2], bits [53:28]) flipped,
/// the result remains PtePhysCorrupt.
#[test]
fn given_high_ppn_bit_flipped_when_classify_flip_then_pte_phys_corrupt() {
    let expected = model().pte_for_index(0);
    let observed = expected ^ (1u64 << 40);
    assert_eq!(
        model().classify_flip(expected, observed),
        FlipClass::PtePhysCorrupt,
        "High PPN bit flip must be PtePhysCorrupt"
    );
}

// ---------------------------------------------------------------------------
// ctrl_bits / pa_mask sanity
// ---------------------------------------------------------------------------

/// The ctrl_bits must include V, R, W, and U.
#[test]
fn when_ctrl_bits_queried_then_v_r_w_u_all_set() {
    let m = model();
    let ctrl = m.ctrl_bits();
    assert_ne!(ctrl & 0x1, 0, "V (bit 0) must be in ctrl_bits");
    assert_ne!(ctrl & 0x2, 0, "R (bit 1) must be in ctrl_bits");
    assert_ne!(ctrl & 0x4, 0, "W (bit 2) must be in ctrl_bits");
    assert_ne!(ctrl & 0x10, 0, "U (bit 4) must be in ctrl_bits");
}

/// The pa_mask (PPN field) must not overlap ctrl_bits.
#[test]
fn when_pa_mask_queried_then_no_overlap_with_ctrl_bits() {
    let m = model();
    assert_eq!(
        m.pa_mask() & m.ctrl_bits(),
        0,
        "PPN mask and ctrl_bits must be disjoint"
    );
}

/// The pa_mask must cover bits [53:10] (44 bits for Sv39 PPN).
#[test]
fn when_pa_mask_queried_then_covers_bits_53_to_10() {
    let ppn_range: u64 = 0x003F_FFFF_FFFF_FC00;
    let m = model();
    assert_eq!(
        m.pa_mask() & ppn_range,
        ppn_range,
        "PPN mask must fully cover bits [53:10]"
    );
}
