#![forbid(unsafe_code)]

use cosmic_hammer_core::FlipClass;

/// Trait for PTE model implementations.
///
/// Object-safe: no generics, no associated types. All methods take &self.
/// Implementations must be Send + Sync so they can be placed in Arc<dyn PteModel>.
pub trait PteModel: Send + Sync {
    /// Short human-readable name, e.g. "x86_64", "arm64", "riscv-sv39".
    fn name(&self) -> &str;

    /// Produce the expected PTE value for memory slot index `i`.
    ///
    /// The physical address embedded in the PTE is derived from `i` using
    /// an architecture-defined mask so that the index wraps at the PA field
    /// width. The control bits (Present, RW, NX, etc.) are always set to
    /// the architecture's "normal user RW page, NX set" sentinel pattern.
    fn pte_for_index(&self, i: usize) -> u64;

    /// Classify a single-PTE bit-flip given the expected and observed values.
    ///
    /// The implementation must apply the same priority ordering as the
    /// C `classify_pte_flip` function:
    ///   NX-clear > PA-corrupt > P-clear > RW-set > US-clear > DataCorrupt
    fn classify_flip(&self, expected: u64, observed: u64) -> FlipClass;

    /// Bitmask of all control bits for this architecture's PTE format.
    /// Used by tests to verify that flips in non-control bits return DataCorrupt.
    fn ctrl_bits(&self) -> u64;

    /// Bitmask covering the physical-address field within the PTE.
    /// Used by tests to construct PA-corruption scenarios.
    fn pa_mask(&self) -> u64;
}

/// x86-64 4-level paging PTE model (Intel SDM Vol.3A §4.5).
pub mod x86_64;

/// ARMv8 4KB granule stage-1 PTE model (ARM DDI 0487).
pub mod arm64;

/// RISC-V Sv39 leaf PTE model (RISC-V Privileged §4.4).
pub mod riscv;
