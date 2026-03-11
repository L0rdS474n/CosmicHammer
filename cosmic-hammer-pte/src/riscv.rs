// RISC-V Sv39 leaf PTE model (RISC-V Privileged Specification S4.4).
//
// Bit layout (Sv39 PTE, 8 bytes):
//   Bit  0 : V   – Valid
//   Bit  1 : R   – Readable
//   Bit  2 : W   – Writable
//   Bit  3 : X   – Executable
//   Bit  4 : U   – User-mode accessible
//   Bit  5 : G   – Global
//   Bit  6 : A   – Accessed
//   Bit  7 : D   – Dirty
//   Bits 9:8  : RSW (reserved for software)
//   Bits 53:10 : PPN[2:0] – Physical Page Number
//   Bits 63:54 : Reserved (must be zero in Sv39)
//
// Sentinel (normal user RW leaf, V=1, R=1, W=1, U=1, A=1, D=1, X=0):
//   = 0x00000000000000D7  (D=7, U=4, W=2, R=1, V=0 → bits 7,4,2,1,0,6)
//   bit0=V=1, bit1=R=1, bit2=W=1, bit4=U=1, bit6=A=1, bit7=D=1
//   = 1 | 2 | 4 | 16 | 64 | 128 = 0xD7
//
// PPN index mask: lower 20 bits of i → PPN[0] bits[29:10] of PTE.
//   ppn_bits = (i & 0xFFFFF) << 10

use crate::PteModel;
use cosmic_hammer_core::FlipClass;

/// Sv39 leaf PTE sentinel control bits (V | R | W | U | A | D).
pub const RISCV_CTRL_BITS: u64 = 0x0000_0000_0000_00D7;

/// PPN mask covering bits[53:10] (all three PPN sub-fields).
pub const RISCV_PPN_MASK: u64 = 0x003F_FFFF_FFFF_FC00;

/// 20-bit index mask applied to derive PPN[0] from a slot index.
pub const RISCV_INDEX_MASK: usize = 0x000F_FFFF;

/// Bit positions for RISC-V Sv39 PTE permission bits.
const RISCV_BIT_R: u32 = 1;
const RISCV_BIT_W: u32 = 2;
const RISCV_BIT_X: u32 = 3;
const RISCV_BIT_U: u32 = 4;

/// RISC-V Sv39 leaf PTE model implementing the Sv39 virtual memory format.
pub struct RiscvSv39Pte;

impl PteModel for RiscvSv39Pte {
    fn name(&self) -> &str {
        "riscv-sv39"
    }

    fn pte_for_index(&self, i: usize) -> u64 {
        RISCV_CTRL_BITS | (((i & RISCV_INDEX_MASK) as u64) << 10)
    }

    fn classify_flip(&self, expected: u64, observed: u64) -> FlipClass {
        let diff = expected ^ observed;

        // Priority 1: X bit (3) set 0→1 → non-executable page becomes executable
        // In RISC-V, X=0 means NX; gaining X is the "NX cleared" equivalent.
        if (diff >> RISCV_BIT_X) & 1 != 0 && (observed >> RISCV_BIT_X) & 1 != 0 {
            return FlipClass::PteNxClear;
        }

        // Priority 2: PPN bits [53:10] corrupted
        if diff & RISCV_PPN_MASK != 0 {
            return FlipClass::PtePhysCorrupt;
        }

        // Priority 3: V bit (0) cleared 1→0 → page fault / DoS
        if (diff & 1) != 0 && (observed & 1) == 0 {
            return FlipClass::PtePresentClear;
        }

        // Priority 4: W bit (2) set 0→1 → read-only page becomes writable
        if (diff >> RISCV_BIT_W) & 1 != 0 && (observed >> RISCV_BIT_W) & 1 != 0 {
            return FlipClass::PteWriteSet;
        }

        // Priority 5: R bit (1) cleared 1→0 → page becomes unreadable (DoS/escalation)
        // U bit (4) cleared 1→0 → user page becomes supervisor-only
        if (diff >> RISCV_BIT_U) & 1 != 0 && (observed >> RISCV_BIT_U) & 1 == 0 {
            return FlipClass::PteSupervisorEsc;
        }

        if (diff >> RISCV_BIT_R) & 1 != 0 && (observed >> RISCV_BIT_R) & 1 == 0 {
            return FlipClass::PteSupervisorEsc;
        }

        // Fallback: any other bit change
        FlipClass::DataCorrupt
    }

    fn ctrl_bits(&self) -> u64 {
        RISCV_CTRL_BITS
    }

    fn pa_mask(&self) -> u64 {
        RISCV_PPN_MASK
    }
}
