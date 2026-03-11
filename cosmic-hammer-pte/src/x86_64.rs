// x86-64 4-level paging PTE model.
//
// Bit layout (Intel SDM Vol.3A §4.5):
//   Bit  0 : P   – Present
//   Bit  1 : RW  – Read/Write
//   Bit  2 : US  – User/Supervisor
//   Bits 51:12 : Physical address
//   Bit 63 : NX  – Execute-Disable
//
// Sentinel value (normal user RW page, NX set):
//   P=1, RW=1, US=1, NX=1 → bits 0,1,2,63 set
//   = 0x8000_0000_0000_0007 | (pa_bits << 12)
//
// PA index mask: lower 20 bits of i → bits[31:12] of PTE.
//   pa_bits = (i & 0xFFFFF) << 12

use crate::PteModel;
use cosmic_hammer_core::FlipClass;

/// x86-64 PTE sentinel control bits (P | RW | US | NX).
pub const X86_CTRL_BITS: u64 = (1u64 << 63) | 0x0000_0000_0000_0007;

/// PA mask: bits [51:12] for x86-64 4-level paging.
pub const X86_PA_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// 20-bit index mask applied to derive the PA field from a slot index.
pub const X86_INDEX_MASK: usize = 0x000F_FFFF;

/// x86-64 PTE model implementing the Intel SDM Vol.3A 4-level paging format.
pub struct X86_64Pte;

impl PteModel for X86_64Pte {
    fn name(&self) -> &str {
        "x86_64"
    }

    fn pte_for_index(&self, i: usize) -> u64 {
        X86_CTRL_BITS | (((i & X86_INDEX_MASK) as u64) << 12)
    }

    fn classify_flip(&self, expected: u64, observed: u64) -> FlipClass {
        let diff = expected ^ observed;

        // Priority 1: NX bit (63) cleared 1→0 → page becomes executable
        if (diff >> 63) & 1 != 0 && (observed >> 63) & 1 == 0 {
            return FlipClass::PteNxClear;
        }

        // Priority 2: Physical address bits [51:12] corrupted
        if diff & X86_PA_MASK != 0 {
            return FlipClass::PtePhysCorrupt;
        }

        // Priority 3: Present bit (0) cleared 1→0 → page fault / DoS
        if (diff & 1) != 0 && (observed & 1) == 0 {
            return FlipClass::PtePresentClear;
        }

        // Priority 4: RW bit (1) set 0→1 → read-only becomes writable
        if (diff >> 1) & 1 != 0 && (observed >> 1) & 1 != 0 {
            return FlipClass::PteWriteSet;
        }

        // Priority 5: US bit (2) cleared 1→0 → user page becomes supervisor-only
        if (diff >> 2) & 1 != 0 && (observed >> 2) & 1 == 0 {
            return FlipClass::PteSupervisorEsc;
        }

        // Fallback: any other bit change in the PTE
        FlipClass::DataCorrupt
    }

    fn ctrl_bits(&self) -> u64 {
        X86_CTRL_BITS
    }

    fn pa_mask(&self) -> u64 {
        X86_PA_MASK
    }
}
