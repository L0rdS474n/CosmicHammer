use crate::region::RegionType;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Classification of a bit flip's exploitability, matching the C enum exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum FlipClass {
    Benign = 0,
    DataCorrupt = 1,
    PtrHijack = 2,
    PrivEsc = 3,
    CodePage = 4,
    PtePresentClear = 5,
    PteWriteSet = 6,
    PteNxClear = 7,
    PtePhysCorrupt = 8,
    PteSupervisorEsc = 9,
}

impl FlipClass {
    pub const COUNT: usize = 10;

    pub fn name(self) -> &'static str {
        match self {
            Self::Benign => "BENIGN",
            Self::DataCorrupt => "DATA_CORRUPTION",
            Self::PtrHijack => "PTR_HIJACK",
            Self::PrivEsc => "PRIV_ESC",
            Self::CodePage => "CODE_PAGE",
            Self::PtePresentClear => "PTE_PRESENT_CLEAR",
            Self::PteWriteSet => "PTE_WRITE_SET",
            Self::PteNxClear => "PTE_NX_CLEAR",
            Self::PtePhysCorrupt => "PTE_PHYS_CORRUPT",
            Self::PteSupervisorEsc => "PTE_SUPERVISOR_ESC",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Benign => "No control-flow impact",
            Self::DataCorrupt => "Memory corruption, no CFI bypass",
            Self::PtrHijack => "Potential control-flow hijack via pointer corruption",
            Self::PrivEsc => "Potential privilege escalation via flag corruption",
            Self::CodePage => "Return address corruption → code execution",
            Self::PtePresentClear => "PTE Present bit cleared → page fault / DoS",
            Self::PteWriteSet => "PTE Write bit set → write to read-only mapping",
            Self::PteNxClear => "PTE NX bit cleared → heap/stack becomes executable",
            Self::PtePhysCorrupt => "PTE physical address bits corrupted → arbitrary memory alias",
            Self::PteSupervisorEsc => "PTE User bit cleared → user page becomes supervisor-only",
        }
    }

    pub fn from_index(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::Benign),
            1 => Some(Self::DataCorrupt),
            2 => Some(Self::PtrHijack),
            3 => Some(Self::PrivEsc),
            4 => Some(Self::CodePage),
            5 => Some(Self::PtePresentClear),
            6 => Some(Self::PteWriteSet),
            7 => Some(Self::PteNxClear),
            8 => Some(Self::PtePhysCorrupt),
            9 => Some(Self::PteSupervisorEsc),
            _ => None,
        }
    }
}

impl fmt::Display for FlipClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Direction of a single-bit flip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlipDirection {
    ZeroToOne,
    OneToZero,
}

impl FlipDirection {
    pub fn as_int(self) -> i32 {
        match self {
            Self::ZeroToOne => 1,
            Self::OneToZero => -1,
        }
    }
}

impl fmt::Display for FlipDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroToOne => f.write_str("0→1"),
            Self::OneToZero => f.write_str("1→0"),
        }
    }
}

/// A detected bit-flip event with all metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlipEvent {
    pub timestamp: u64,
    pub offset: usize,
    pub bit_position: u8,
    pub expected: u64,
    pub observed: u64,
    pub direction: FlipDirection,
    pub n_bits: u32,
    pub region: RegionType,
    pub flip_class: FlipClass,
    pub dram_row: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // FlipClass::from_index — all valid indices
    // -----------------------------------------------------------------------

    /// Given index 0, from_index returns Benign.
    #[test]
    fn given_index_0_when_from_index_then_benign() {
        assert_eq!(FlipClass::from_index(0), Some(FlipClass::Benign));
    }

    /// Given index 1, from_index returns DataCorrupt.
    #[test]
    fn given_index_1_when_from_index_then_data_corrupt() {
        assert_eq!(FlipClass::from_index(1), Some(FlipClass::DataCorrupt));
    }

    /// Given index 2, from_index returns PtrHijack.
    #[test]
    fn given_index_2_when_from_index_then_ptr_hijack() {
        assert_eq!(FlipClass::from_index(2), Some(FlipClass::PtrHijack));
    }

    /// Given index 3, from_index returns PrivEsc.
    #[test]
    fn given_index_3_when_from_index_then_priv_esc() {
        assert_eq!(FlipClass::from_index(3), Some(FlipClass::PrivEsc));
    }

    /// Given index 4, from_index returns CodePage.
    #[test]
    fn given_index_4_when_from_index_then_code_page() {
        assert_eq!(FlipClass::from_index(4), Some(FlipClass::CodePage));
    }

    /// Given index 5, from_index returns PtePresentClear.
    #[test]
    fn given_index_5_when_from_index_then_pte_present_clear() {
        assert_eq!(FlipClass::from_index(5), Some(FlipClass::PtePresentClear));
    }

    /// Given index 6, from_index returns PteWriteSet.
    #[test]
    fn given_index_6_when_from_index_then_pte_write_set() {
        assert_eq!(FlipClass::from_index(6), Some(FlipClass::PteWriteSet));
    }

    /// Given index 7, from_index returns PteNxClear.
    #[test]
    fn given_index_7_when_from_index_then_pte_nx_clear() {
        assert_eq!(FlipClass::from_index(7), Some(FlipClass::PteNxClear));
    }

    /// Given index 8, from_index returns PtePhysCorrupt.
    #[test]
    fn given_index_8_when_from_index_then_pte_phys_corrupt() {
        assert_eq!(FlipClass::from_index(8), Some(FlipClass::PtePhysCorrupt));
    }

    /// Given index 9, from_index returns PteSupervisorEsc.
    #[test]
    fn given_index_9_when_from_index_then_pte_supervisor_esc() {
        assert_eq!(FlipClass::from_index(9), Some(FlipClass::PteSupervisorEsc));
    }

    /// Given index 10 (out of range), from_index returns None.
    #[test]
    fn given_index_10_when_from_index_then_none() {
        assert_eq!(FlipClass::from_index(10), None);
    }

    /// Given a large out-of-range index, from_index returns None.
    #[test]
    fn given_large_index_when_from_index_then_none() {
        assert_eq!(FlipClass::from_index(usize::MAX), None);
    }

    /// COUNT equals 10.
    #[test]
    fn when_count_checked_then_equals_ten() {
        assert_eq!(FlipClass::COUNT, 10);
    }

    /// from_index succeeds for every index in 0..COUNT.
    #[test]
    fn given_all_valid_indices_when_from_index_then_all_some() {
        for i in 0..FlipClass::COUNT {
            assert!(FlipClass::from_index(i).is_some(), "index {i} must be Some");
        }
    }

    // -----------------------------------------------------------------------
    // FlipClass::name() — correct strings
    // -----------------------------------------------------------------------

    /// Each variant's name() returns the expected uppercase string matching
    /// the original C enum label.
    #[test]
    fn when_name_called_then_returns_correct_string() {
        assert_eq!(FlipClass::Benign.name(), "BENIGN");
        assert_eq!(FlipClass::DataCorrupt.name(), "DATA_CORRUPTION");
        assert_eq!(FlipClass::PtrHijack.name(), "PTR_HIJACK");
        assert_eq!(FlipClass::PrivEsc.name(), "PRIV_ESC");
        assert_eq!(FlipClass::CodePage.name(), "CODE_PAGE");
        assert_eq!(FlipClass::PtePresentClear.name(), "PTE_PRESENT_CLEAR");
        assert_eq!(FlipClass::PteWriteSet.name(), "PTE_WRITE_SET");
        assert_eq!(FlipClass::PteNxClear.name(), "PTE_NX_CLEAR");
        assert_eq!(FlipClass::PtePhysCorrupt.name(), "PTE_PHYS_CORRUPT");
        assert_eq!(FlipClass::PteSupervisorEsc.name(), "PTE_SUPERVISOR_ESC");
    }

    /// No two variants share the same name.
    #[test]
    fn when_all_names_collected_then_all_unique() {
        let names: Vec<&str> = (0..FlipClass::COUNT)
            .map(|i| FlipClass::from_index(i).unwrap().name())
            .collect();
        let mut deduped = names.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(names.len(), deduped.len(), "all names must be unique");
    }

    // -----------------------------------------------------------------------
    // FlipClass Display — matches name()
    // -----------------------------------------------------------------------

    /// Given any FlipClass, Display output equals name().
    #[test]
    fn when_display_called_then_equals_name() {
        let variants = [
            FlipClass::Benign,
            FlipClass::DataCorrupt,
            FlipClass::PtrHijack,
            FlipClass::PrivEsc,
            FlipClass::CodePage,
            FlipClass::PtePresentClear,
            FlipClass::PteWriteSet,
            FlipClass::PteNxClear,
            FlipClass::PtePhysCorrupt,
            FlipClass::PteSupervisorEsc,
        ];
        for v in variants {
            assert_eq!(
                v.to_string(),
                v.name(),
                "Display must equal name() for {:?}",
                v
            );
        }
    }

    // -----------------------------------------------------------------------
    // FlipDirection::as_int()
    // -----------------------------------------------------------------------

    /// ZeroToOne returns +1.
    #[test]
    fn given_zero_to_one_when_as_int_then_positive_one() {
        assert_eq!(FlipDirection::ZeroToOne.as_int(), 1);
    }

    /// OneToZero returns -1.
    #[test]
    fn given_one_to_zero_when_as_int_then_negative_one() {
        assert_eq!(FlipDirection::OneToZero.as_int(), -1);
    }

    /// The two directions produce distinct as_int() values.
    #[test]
    fn when_both_directions_compared_then_values_differ() {
        assert_ne!(
            FlipDirection::ZeroToOne.as_int(),
            FlipDirection::OneToZero.as_int()
        );
    }

    // -----------------------------------------------------------------------
    // FlipEvent serialization/deserialization roundtrip
    // -----------------------------------------------------------------------

    /// Given a FlipEvent, serializing to JSON and deserializing back yields
    /// an identical value.
    ///
    /// This test is deterministic because all fields are fixed scalars or
    /// Copy types; no external IO is involved.
    #[test]
    fn given_flip_event_when_serde_roundtrip_then_identical() {
        let original = FlipEvent {
            timestamp: 1_700_000_000,
            offset: 4096,
            bit_position: 7,
            expected: 0x00007FFF12345678,
            observed: 0x00007FFF12345679,
            direction: FlipDirection::ZeroToOne,
            n_bits: 1,
            region: RegionType::Pointer,
            flip_class: FlipClass::PtrHijack,
            dram_row: 512,
        };

        let json = serde_json::to_string(&original).expect("serialize must not fail");
        let recovered: FlipEvent = serde_json::from_str(&json).expect("deserialize must not fail");

        assert_eq!(recovered.timestamp, original.timestamp);
        assert_eq!(recovered.offset, original.offset);
        assert_eq!(recovered.bit_position, original.bit_position);
        assert_eq!(recovered.expected, original.expected);
        assert_eq!(recovered.observed, original.observed);
        assert_eq!(recovered.direction, original.direction);
        assert_eq!(recovered.n_bits, original.n_bits);
        assert_eq!(recovered.region, original.region);
        assert_eq!(recovered.flip_class, original.flip_class);
        assert_eq!(recovered.dram_row, original.dram_row);
    }

    /// Given a FlipEvent with a PTE-class flip, the roundtrip preserves the
    /// variant precisely.
    #[test]
    fn given_pte_flip_event_when_serde_roundtrip_then_pte_class_preserved() {
        let original = FlipEvent {
            timestamp: 0,
            offset: 0,
            bit_position: 63,
            expected: 0x8000_0000_0000_0007,
            observed: 0x0000_0000_0000_0007,
            direction: FlipDirection::OneToZero,
            n_bits: 1,
            region: RegionType::PteSim,
            flip_class: FlipClass::PteNxClear,
            dram_row: 0,
        };

        let json = serde_json::to_string(&original).unwrap();
        let recovered: FlipEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.flip_class, FlipClass::PteNxClear);
        assert_eq!(recovered.region, RegionType::PteSim);
    }

    // -----------------------------------------------------------------------
    // repr(u8) discriminants match from_index inputs
    // -----------------------------------------------------------------------

    /// The repr(u8) discriminant of each FlipClass equals its from_index key.
    #[test]
    fn when_discriminants_checked_then_match_from_index_keys() {
        assert_eq!(FlipClass::Benign as usize, 0);
        assert_eq!(FlipClass::DataCorrupt as usize, 1);
        assert_eq!(FlipClass::PtrHijack as usize, 2);
        assert_eq!(FlipClass::PrivEsc as usize, 3);
        assert_eq!(FlipClass::CodePage as usize, 4);
        assert_eq!(FlipClass::PtePresentClear as usize, 5);
        assert_eq!(FlipClass::PteWriteSet as usize, 6);
        assert_eq!(FlipClass::PteNxClear as usize, 7);
        assert_eq!(FlipClass::PtePhysCorrupt as usize, 8);
        assert_eq!(FlipClass::PteSupervisorEsc as usize, 9);
    }
}
