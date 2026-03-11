use crate::flip::FlipClass;
use crate::region::RegionType;

/// x86-64 PTE bit positions (Intel SDM Vol.3A §4.5).
pub const PTE_BIT_P: u32 = 0;
pub const PTE_BIT_RW: u32 = 1;
pub const PTE_BIT_US: u32 = 2;
pub const PTE_BIT_NX: u32 = 63;
pub const PTE_PA_SHIFT: u32 = 12;

/// Physical address mask: bits [51:12].
pub const PTE_PA_MASK: u64 = 0x000FFFFFFFFFF000;

/// Classify a PTE-region flip by examining which control/PA bits changed.
/// Priority order: NX > PA > P > RW > US (matching C implementation).
pub fn classify_pte_flip(expected: u64, observed: u64) -> FlipClass {
    let diff = expected ^ observed;

    // NX bit cleared: 1→0 → non-exec page becomes executable (highest severity)
    if (diff >> PTE_BIT_NX) & 1 != 0 && (observed >> PTE_BIT_NX) & 1 == 0 {
        return FlipClass::PteNxClear;
    }

    // Physical address bits corrupted → arbitrary memory aliasing
    if diff & PTE_PA_MASK != 0 {
        return FlipClass::PtePhysCorrupt;
    }

    // Present bit cleared: 1→0 → page-fault loop / DoS
    if (diff >> PTE_BIT_P) & 1 != 0 && (observed >> PTE_BIT_P) & 1 == 0 {
        return FlipClass::PtePresentClear;
    }

    // Write bit set: 0→1 → RO mapping becomes writable
    if (diff >> PTE_BIT_RW) & 1 != 0 && (observed >> PTE_BIT_RW) & 1 != 0 {
        return FlipClass::PteWriteSet;
    }

    // User/Supervisor bit cleared: 1→0 → user page locked out
    if (diff >> PTE_BIT_US) & 1 != 0 && (observed >> PTE_BIT_US) & 1 == 0 {
        return FlipClass::PteSupervisorEsc;
    }

    // Anything else in a PTE is still a corruption
    FlipClass::DataCorrupt
}

/// Classify a detected bit flip based on region type and flip characteristics.
/// Matches the C classify_flip() exactly.
pub fn classify_flip(
    region: RegionType,
    expected: u64,
    observed: u64,
    direction: i32,
    n_bits: u32,
) -> FlipClass {
    // Multi-bit (>2) events are statistically improbable for cosmic rays
    if n_bits > 2 {
        return FlipClass::Benign;
    }

    match region {
        RegionType::PteSim => classify_pte_flip(expected, observed),
        RegionType::Pointer => {
            if direction > 0 {
                FlipClass::PtrHijack
            } else {
                FlipClass::DataCorrupt
            }
        }
        RegionType::RetAddr => FlipClass::CodePage,
        RegionType::Permission => {
            if direction > 0 {
                FlipClass::PrivEsc
            } else {
                FlipClass::Benign
            }
        }
        RegionType::Data => FlipClass::DataCorrupt,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_multi_bit_is_benign() {
        assert_eq!(
            classify_flip(RegionType::Pointer, 0, 0xFF, 1, 3),
            FlipClass::Benign
        );
    }

    #[test]
    fn test_classify_pointer_zero_to_one() {
        assert_eq!(
            classify_flip(
                RegionType::Pointer,
                0x00007FFF12345678,
                0x00007FFF12345679,
                1,
                1
            ),
            FlipClass::PtrHijack
        );
    }

    #[test]
    fn test_classify_pointer_one_to_zero() {
        assert_eq!(
            classify_flip(
                RegionType::Pointer,
                0x00007FFF12345678,
                0x00007FFF12345670,
                -1,
                1
            ),
            FlipClass::DataCorrupt
        );
    }

    #[test]
    fn test_classify_retaddr() {
        assert_eq!(
            classify_flip(
                RegionType::RetAddr,
                0x00007FFF87654321,
                0x00007FFF87654320,
                -1,
                1
            ),
            FlipClass::CodePage
        );
    }

    #[test]
    fn test_classify_permission_set() {
        assert_eq!(
            classify_flip(RegionType::Permission, 0x04, 0x06, 1, 1),
            FlipClass::PrivEsc
        );
    }

    #[test]
    fn test_classify_permission_clear() {
        assert_eq!(
            classify_flip(RegionType::Permission, 0x04, 0x00, -1, 1),
            FlipClass::Benign
        );
    }

    #[test]
    fn test_classify_data() {
        assert_eq!(
            classify_flip(
                RegionType::Data,
                0xAAAAAAAAAAAAAAAA,
                0xAAAAAAAAAAAAAAAA ^ (1 << 33),
                1,
                1
            ),
            FlipClass::DataCorrupt
        );
    }

    #[test]
    fn test_pte_nx_clear() {
        // NX bit (63) flipped from 1→0
        let expected = 0x8000000001A00007u64;
        let observed = expected ^ (1u64 << 63); // clear NX
        assert_eq!(classify_pte_flip(expected, observed), FlipClass::PteNxClear);
    }

    #[test]
    fn test_pte_phys_corrupt() {
        let expected = 0x8000000001A00007u64;
        let observed = expected ^ (1u64 << 20); // flip a PA bit
        assert_eq!(
            classify_pte_flip(expected, observed),
            FlipClass::PtePhysCorrupt
        );
    }

    #[test]
    fn test_pte_present_clear() {
        let expected = 0x8000000001A00007u64;
        let observed = expected ^ 1u64; // clear P bit
        assert_eq!(
            classify_pte_flip(expected, observed),
            FlipClass::PtePresentClear
        );
    }

    #[test]
    fn test_pte_write_set() {
        // RW bit starts at 1 in our PTE; to test PTE_WRITE_SET we need
        // a PTE where RW=0, then flip sets it to 1
        let expected = 0x8000000001A00005u64; // P=1, RW=0, US=1
        let observed = expected | (1u64 << 1); // set RW
        assert_eq!(
            classify_pte_flip(expected, observed),
            FlipClass::PteWriteSet
        );
    }

    #[test]
    fn test_pte_supervisor_esc() {
        let expected = 0x8000000001A00007u64;
        let observed = expected ^ (1u64 << 2); // clear US bit
        assert_eq!(
            classify_pte_flip(expected, observed),
            FlipClass::PteSupervisorEsc
        );
    }
}
