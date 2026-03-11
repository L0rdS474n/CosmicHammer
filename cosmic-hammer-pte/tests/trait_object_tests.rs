// Tests for dynamic dispatch through Box<dyn PteModel>.
//
// These tests verify that the PteModel trait is object-safe and that all three
// architecture implementations can be used uniformly through a trait object.
//
// The tests do NOT require pte_for_index or classify_flip to be implemented;
// they only call methods that are already implemented in the stubs (name,
// ctrl_bits, pa_mask).  Tests that exercise the unimplemented methods are
// marked with a comment so the implementer knows to check them after stubbing.
//
// Tests that call unimplemented methods are EXPECTED TO PANIC until the
// production implementation is filled in.

use cosmic_hammer_core::FlipClass;
use cosmic_hammer_pte::arm64::Arm64Pte;
use cosmic_hammer_pte::riscv::RiscvSv39Pte;
use cosmic_hammer_pte::x86_64::X86_64Pte;
use cosmic_hammer_pte::PteModel;

// ---------------------------------------------------------------------------
// Helper: build a heterogeneous vec of all three models
// ---------------------------------------------------------------------------

fn all_models() -> Vec<Box<dyn PteModel>> {
    vec![
        Box::new(X86_64Pte),
        Box::new(Arm64Pte),
        Box::new(RiscvSv39Pte),
    ]
}

// ---------------------------------------------------------------------------
// name() — object-safe dispatch works and returns known strings
// ---------------------------------------------------------------------------

/// Given a Box<dyn PteModel> for x86_64, name() returns "x86_64".
#[test]
fn given_x86_64_trait_object_when_name_then_returns_x86_64() {
    let m: Box<dyn PteModel> = Box::new(X86_64Pte);
    assert_eq!(m.name(), "x86_64");
}

/// Given a Box<dyn PteModel> for arm64, name() returns "arm64".
#[test]
fn given_arm64_trait_object_when_name_then_returns_arm64() {
    let m: Box<dyn PteModel> = Box::new(Arm64Pte);
    assert_eq!(m.name(), "arm64");
}

/// Given a Box<dyn PteModel> for RISC-V Sv39, name() returns "riscv-sv39".
#[test]
fn given_riscv_trait_object_when_name_then_returns_riscv_sv39() {
    let m: Box<dyn PteModel> = Box::new(RiscvSv39Pte);
    assert_eq!(m.name(), "riscv-sv39");
}

/// Given a Vec<Box<dyn PteModel>> with all three models, each name is unique.
///
/// Unique names are required so that the scanner can identify which model
/// produced a given result.
#[test]
fn given_all_models_when_names_collected_then_all_unique() {
    let models = all_models();
    let names: Vec<&str> = models.iter().map(|m| m.name()).collect();
    let mut deduped = names.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(
        names.len(),
        deduped.len(),
        "all model names must be unique; got: {:?}",
        names
    );
}

// ---------------------------------------------------------------------------
// ctrl_bits() / pa_mask() — accessible through trait object
// ---------------------------------------------------------------------------

/// Given any trait object, ctrl_bits() returns a non-zero value.
#[test]
fn given_any_trait_object_when_ctrl_bits_then_nonzero() {
    for m in all_models() {
        assert_ne!(m.ctrl_bits(), 0, "{}: ctrl_bits must not be zero", m.name());
    }
}

/// Given any trait object, pa_mask() returns a non-zero value.
#[test]
fn given_any_trait_object_when_pa_mask_then_nonzero() {
    for m in all_models() {
        assert_ne!(m.pa_mask(), 0, "{}: pa_mask must not be zero", m.name());
    }
}

/// Given any trait object, ctrl_bits and pa_mask are disjoint.
///
/// This invariant must hold for all architectures; if they overlapped the
/// flip classifier would misattribute PA corruption as control-bit flips.
#[test]
fn given_any_trait_object_when_ctrl_and_pa_mask_then_disjoint() {
    for m in all_models() {
        assert_eq!(
            m.ctrl_bits() & m.pa_mask(),
            0,
            "{}: ctrl_bits and pa_mask must not overlap",
            m.name()
        );
    }
}

// ---------------------------------------------------------------------------
// pte_for_index() — dynamic dispatch (EXPECTED TO PANIC until implemented)
// ---------------------------------------------------------------------------

/// Given a Box<dyn PteModel>, pte_for_index(0) is callable through dynamic
/// dispatch and returns a value with control bits set.
#[test]
fn given_x86_64_trait_object_when_pte_for_index_zero_then_callable() {
    let m: Box<dyn PteModel> = Box::new(X86_64Pte);
    let pte = m.pte_for_index(0);
    assert_eq!(pte & m.ctrl_bits(), m.ctrl_bits());
}

#[test]
fn given_arm64_trait_object_when_pte_for_index_zero_then_callable() {
    let m: Box<dyn PteModel> = Box::new(Arm64Pte);
    let pte = m.pte_for_index(0);
    assert_eq!(pte & m.ctrl_bits(), m.ctrl_bits());
}

#[test]
fn given_riscv_trait_object_when_pte_for_index_zero_then_callable() {
    let m: Box<dyn PteModel> = Box::new(RiscvSv39Pte);
    let pte = m.pte_for_index(0);
    assert_eq!(pte & m.ctrl_bits(), m.ctrl_bits());
}

// ---------------------------------------------------------------------------
// classify_flip() — dynamic dispatch (EXPECTED TO PANIC until implemented)
// ---------------------------------------------------------------------------

/// Given a Box<dyn PteModel>, classify_flip is callable through dynamic dispatch
/// and returns a meaningful classification.
#[test]
fn given_x86_64_trait_object_when_classify_flip_then_callable() {
    let m: Box<dyn PteModel> = Box::new(X86_64Pte);
    // P bit cleared (1→0) → PtePresentClear
    let class = m.classify_flip(0x8000_0000_0000_0007, 0x8000_0000_0000_0006);
    assert_eq!(class, FlipClass::PtePresentClear);
}

#[test]
fn given_arm64_trait_object_when_classify_flip_then_callable() {
    let m: Box<dyn PteModel> = Box::new(Arm64Pte);
    // Valid bit cleared (1→0) → PtePresentClear
    let class = m.classify_flip(0x0000_0000_0000_0713, 0x0000_0000_0000_0712);
    assert_eq!(class, FlipClass::PtePresentClear);
}

#[test]
fn given_riscv_trait_object_when_classify_flip_then_callable() {
    let m: Box<dyn PteModel> = Box::new(RiscvSv39Pte);
    // V bit cleared (1→0) → PtePresentClear
    let class = m.classify_flip(0x0000_0000_0000_00D7, 0x0000_0000_0000_00D6);
    assert_eq!(class, FlipClass::PtePresentClear);
}

// ---------------------------------------------------------------------------
// Trait object is Send + Sync
// ---------------------------------------------------------------------------

/// Verify at compile time that Box<dyn PteModel> satisfies Send + Sync,
/// allowing models to be shared across threads (e.g., in Arc<dyn PteModel>).
///
/// This test has no runtime assertion — it exists purely for the type-checker.
#[test]
fn trait_object_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Box<dyn PteModel>>();
}

// ---------------------------------------------------------------------------
// Contract: FlipClass return type is exhaustively matchable
// ---------------------------------------------------------------------------

/// Given that classify_flip returns a FlipClass, all possible variants must be
/// matchable without a wildcard arm.  This test documents the contract by
/// exhaustively matching every FlipClass variant.
#[test]
fn given_classify_flip_result_when_matched_then_all_variants_covered() {
    let m: Box<dyn PteModel> = Box::new(X86_64Pte);
    // NX bit (63) cleared AND P bit cleared → NX takes priority → PteNxClear
    let class = m.classify_flip(0x8000_0000_0000_0007, 0x0000_0000_0000_0006);
    // Exhaustive match: if new FlipClass variants are added this will fail to compile.
    match class {
        FlipClass::Benign => {}
        FlipClass::DataCorrupt => {}
        FlipClass::PtrHijack => {}
        FlipClass::PrivEsc => {}
        FlipClass::CodePage => {}
        FlipClass::PtePresentClear => {}
        FlipClass::PteWriteSet => {}
        FlipClass::PteNxClear => {}
        FlipClass::PtePhysCorrupt => {}
        FlipClass::PteSupervisorEsc => {}
    }
}
