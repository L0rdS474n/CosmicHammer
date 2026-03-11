use serde::{Deserialize, Serialize};
use std::fmt;

/// Memory region types matching the original C implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RegionType {
    Pointer = 0,
    RetAddr = 1,
    Permission = 2,
    Data = 3,
    PteSim = 4,
}

impl RegionType {
    pub const COUNT: usize = 5;

    pub fn from_index(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::Pointer),
            1 => Some(Self::RetAddr),
            2 => Some(Self::Permission),
            3 => Some(Self::Data),
            4 => Some(Self::PteSim),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Pointer => "POINTER",
            Self::RetAddr => "RETADDR",
            Self::Permission => "PERMISSION",
            Self::Data => "DATA",
            Self::PteSim => "PTE_SIM",
        }
    }
}

impl fmt::Display for RegionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // RegionType::from_index — all valid indices round-trip
    // -----------------------------------------------------------------------

    /// Given index 0, from_index returns Pointer.
    #[test]
    fn given_index_0_when_from_index_then_pointer() {
        assert_eq!(RegionType::from_index(0), Some(RegionType::Pointer));
    }

    /// Given index 1, from_index returns RetAddr.
    #[test]
    fn given_index_1_when_from_index_then_ret_addr() {
        assert_eq!(RegionType::from_index(1), Some(RegionType::RetAddr));
    }

    /// Given index 2, from_index returns Permission.
    #[test]
    fn given_index_2_when_from_index_then_permission() {
        assert_eq!(RegionType::from_index(2), Some(RegionType::Permission));
    }

    /// Given index 3, from_index returns Data.
    #[test]
    fn given_index_3_when_from_index_then_data() {
        assert_eq!(RegionType::from_index(3), Some(RegionType::Data));
    }

    /// Given index 4, from_index returns PteSim.
    #[test]
    fn given_index_4_when_from_index_then_pte_sim() {
        assert_eq!(RegionType::from_index(4), Some(RegionType::PteSim));
    }

    /// Given index 5 (out of range), from_index returns None.
    #[test]
    fn given_index_5_when_from_index_then_none() {
        assert_eq!(RegionType::from_index(5), None);
    }

    /// Given a large out-of-range index, from_index returns None.
    #[test]
    fn given_large_index_when_from_index_then_none() {
        assert_eq!(RegionType::from_index(usize::MAX), None);
    }

    /// COUNT constant equals the number of valid variants (0–4 inclusive = 5).
    #[test]
    fn when_count_checked_then_equals_five() {
        assert_eq!(RegionType::COUNT, 5);
    }

    /// from_index succeeds for every index in 0..COUNT.
    #[test]
    fn given_all_valid_indices_when_from_index_then_all_some() {
        for i in 0..RegionType::COUNT {
            assert!(
                RegionType::from_index(i).is_some(),
                "index {i} must be Some"
            );
        }
    }

    // -----------------------------------------------------------------------
    // RegionType::name() — correct string for each variant
    // -----------------------------------------------------------------------

    /// Each variant's name() returns the expected uppercase string matching
    /// the original C enum label.
    #[test]
    fn when_name_called_then_returns_correct_string() {
        assert_eq!(RegionType::Pointer.name(), "POINTER");
        assert_eq!(RegionType::RetAddr.name(), "RETADDR");
        assert_eq!(RegionType::Permission.name(), "PERMISSION");
        assert_eq!(RegionType::Data.name(), "DATA");
        assert_eq!(RegionType::PteSim.name(), "PTE_SIM");
    }

    /// No two variants share the same name string.
    #[test]
    fn when_all_names_collected_then_all_unique() {
        let names: Vec<&str> = (0..RegionType::COUNT)
            .map(|i| RegionType::from_index(i).unwrap().name())
            .collect();
        let mut deduped = names.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(names.len(), deduped.len(), "all names must be unique");
    }

    // -----------------------------------------------------------------------
    // Display impl — matches name()
    // -----------------------------------------------------------------------

    /// Given any RegionType, Display output equals name().
    #[test]
    fn when_display_called_then_equals_name() {
        let variants = [
            RegionType::Pointer,
            RegionType::RetAddr,
            RegionType::Permission,
            RegionType::Data,
            RegionType::PteSim,
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
    // repr(u8) discriminants match from_index inputs
    // -----------------------------------------------------------------------

    /// The repr(u8) discriminant of each variant equals its from_index key.
    #[test]
    fn when_discriminants_checked_then_match_from_index_keys() {
        assert_eq!(RegionType::Pointer as usize, 0);
        assert_eq!(RegionType::RetAddr as usize, 1);
        assert_eq!(RegionType::Permission as usize, 2);
        assert_eq!(RegionType::Data as usize, 3);
        assert_eq!(RegionType::PteSim as usize, 4);
    }
}
