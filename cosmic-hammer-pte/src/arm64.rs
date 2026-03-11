// ARMv8-A stage-1 4KB granule page descriptor model (ARM DDI 0487).
//
// Bit layout (AArch64 VMSAv8-64 stage-1 page descriptor):
//   Bit  0 : Valid  (must be 1)
//   Bit  1 : Table/Page flag (1 = page descriptor at level 3)
//   Bits 11:2 : Lower attributes (AP, SH, AF, NG, …)
//   Bits 47:12 : Output address (OA)
//   Bits 63:51 : Upper attributes (UXN, PXN, Contiguous, …)
//     Bit 54 : UXN – Unprivileged Execute-Never
//     Bit 53 : PXN – Privileged Execute-Never
//
// Sentinel (normal user RW page, UXN=0, PXN=0):
//   Valid=1, Type=1, AF=1, AP=0b01 (EL0 RW), SH=0b11 (ISH)
//   = 0x0000_0000_0000_0713  (AF=bit10, SH=bits9:8=0b11, AP=bits7:6=0b01, Valid=1, Type=1)
//
// OA index mask: lower 20 bits of i → bits[31:12] of descriptor.

use crate::PteModel;
use cosmic_hammer_core::FlipClass;

/// AF (bit 10), SH (bits 9:8 = ISH = 0b11), AP (bits 7:6 = EL0 RW = 0b01),
/// Type bit (1), Valid bit (0).  = 0x713
pub const ARM64_CTRL_BITS: u64 = 0x0000_0000_0000_0713;

/// UXN bit position (Unprivileged Execute-Never).
const ARM64_BIT_UXN: u32 = 54;

/// PXN bit position (Privileged Execute-Never).
const ARM64_BIT_PXN: u32 = 53;

/// AP field mask (bits 7:6).
const ARM64_AP_MASK: u64 = 0x0000_0000_0000_00C0;

/// Output Address mask: bits [47:12] for ARMv8 4KB granule.
pub const ARM64_OA_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// 20-bit index mask applied to derive the OA field from a slot index.
pub const ARM64_INDEX_MASK: usize = 0x000F_FFFF;

/// ARMv8 4KB granule PTE model implementing the AArch64 VMSAv8-64 stage-1
/// page descriptor format.
pub struct Arm64Pte;

impl PteModel for Arm64Pte {
    fn name(&self) -> &str {
        "arm64"
    }

    fn pte_for_index(&self, i: usize) -> u64 {
        ARM64_CTRL_BITS | (((i & ARM64_INDEX_MASK) as u64) << 12)
    }

    fn classify_flip(&self, expected: u64, observed: u64) -> FlipClass {
        let diff = expected ^ observed;

        // Priority 1: UXN (bit 54) cleared 1→0 → unprivileged execution enabled
        if (diff >> ARM64_BIT_UXN) & 1 != 0 && (observed >> ARM64_BIT_UXN) & 1 == 0 {
            return FlipClass::PteNxClear;
        }

        // Priority 1b: PXN (bit 53) cleared 1→0 → privileged execution enabled
        if (diff >> ARM64_BIT_PXN) & 1 != 0 && (observed >> ARM64_BIT_PXN) & 1 == 0 {
            return FlipClass::PteNxClear;
        }

        // Priority 2: Output Address bits [47:12] corrupted
        if diff & ARM64_OA_MASK != 0 {
            return FlipClass::PtePhysCorrupt;
        }

        // Priority 3: Valid bit (0) cleared 1→0 → descriptor invalid / DoS
        if (diff & 1) != 0 && (observed & 1) == 0 {
            return FlipClass::PtePresentClear;
        }

        // Priority 4: AP field (bits 7:6) changed → privilege/access change
        if diff & ARM64_AP_MASK != 0 {
            // AP[1] (bit 7) set 0→1 or AP[0] (bit 6) cleared 1→0 restricts
            // access (supervisor-escalation); the opposite grants access
            // (write-set). Check if the change grants broader access.
            let exp_ap = (expected >> 6) & 0x3;
            let obs_ap = (observed >> 6) & 0x3;
            // In ARM64 AP encoding:
            //   0b00 = EL1 RW, EL0 none
            //   0b01 = EL1 RW, EL0 RW
            //   0b10 = EL1 RO, EL0 none
            //   0b11 = EL1 RO, EL0 RO
            // Going from higher AP value to lower grants more write access.
            if obs_ap < exp_ap {
                return FlipClass::PteWriteSet;
            }
            return FlipClass::PteSupervisorEsc;
        }

        // Fallback: any other bit change
        FlipClass::DataCorrupt
    }

    fn ctrl_bits(&self) -> u64 {
        ARM64_CTRL_BITS
    }

    fn pa_mask(&self) -> u64 {
        ARM64_OA_MASK
    }
}
