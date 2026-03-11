/// Configuration for the memory arena.
#[derive(Debug, Clone)]
pub struct ArenaConfig {
    pub total_size: usize,
    pub region_count: usize,
    pub region_size: usize,
}

impl ArenaConfig {
    pub fn new(total_size_mb: usize) -> Self {
        let total_size = total_size_mb * 1024 * 1024;
        let region_count = 5;
        // Round down to nearest 8-byte multiple (matching C: (ARENA_SIZE/REGION_COUNT) & ~7)
        let region_size = (total_size / region_count) & !7;
        Self {
            total_size,
            region_count,
            region_size,
        }
    }

    pub fn default_512mb() -> Self {
        Self::new(512)
    }
}

impl Default for ArenaConfig {
    fn default() -> Self {
        Self::default_512mb()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ArenaConfig::new — size arithmetic matches C implementation
    // -----------------------------------------------------------------------

    /// Given 512 MB, total_size equals 512 * 1024 * 1024 = 536_870_912.
    #[test]
    fn given_512mb_when_new_then_total_size_correct() {
        let cfg = ArenaConfig::new(512);
        assert_eq!(cfg.total_size, 512 * 1024 * 1024);
    }

    /// Given 512 MB, region_count is always 5 (matching the C REGION_COUNT macro).
    #[test]
    fn given_512mb_when_new_then_region_count_five() {
        let cfg = ArenaConfig::new(512);
        assert_eq!(cfg.region_count, 5);
    }

    /// Given 512 MB, region_size is (512*1024*1024 / 5) & !7.
    ///
    /// Arithmetic:
    ///   512 * 1024 * 1024 = 536_870_912
    ///   536_870_912 / 5   = 107_374_182  (integer division)
    ///   107_374_182 & !7  = 107_374_176  (round down to 8-byte alignment)
    ///                     = 0x0666_6660
    #[test]
    fn given_512mb_when_new_then_region_size_8byte_aligned() {
        let cfg = ArenaConfig::new(512);
        let expected_region_size: usize = (512 * 1024 * 1024 / 5) & !7;
        assert_eq!(cfg.region_size, expected_region_size);
        // Explicit value from C source commentary
        assert_eq!(cfg.region_size, 0x0666_6660);
    }

    /// region_size is 8-byte aligned (lowest 3 bits are zero).
    #[test]
    fn given_any_size_when_new_then_region_size_is_8byte_aligned() {
        for mb in [1usize, 64, 128, 256, 512, 1024] {
            let cfg = ArenaConfig::new(mb);
            assert_eq!(
                cfg.region_size & 7,
                0,
                "region_size must be 8-byte aligned for {mb} MB input"
            );
        }
    }

    /// Given any input, region_size * region_count <= total_size.
    ///
    /// The region must not exceed the allocated arena.
    #[test]
    fn given_any_size_when_new_then_regions_fit_within_total() {
        for mb in [1usize, 64, 256, 512] {
            let cfg = ArenaConfig::new(mb);
            assert!(
                cfg.region_size * cfg.region_count <= cfg.total_size,
                "{mb} MB: region_size * region_count must not exceed total_size"
            );
        }
    }

    // -----------------------------------------------------------------------
    // ArenaConfig::default() — equals new(512)
    // -----------------------------------------------------------------------

    /// Default::default() produces the same values as new(512).
    #[test]
    fn when_default_then_equals_new_512mb() {
        let default_cfg = ArenaConfig::default();
        let explicit_cfg = ArenaConfig::new(512);
        assert_eq!(default_cfg.total_size, explicit_cfg.total_size);
        assert_eq!(default_cfg.region_count, explicit_cfg.region_count);
        assert_eq!(default_cfg.region_size, explicit_cfg.region_size);
    }

    /// default_512mb() produces the same values as new(512).
    #[test]
    fn when_default_512mb_then_equals_new_512mb() {
        let via_helper = ArenaConfig::default_512mb();
        let via_new = ArenaConfig::new(512);
        assert_eq!(via_helper.total_size, via_new.total_size);
        assert_eq!(via_helper.region_count, via_new.region_count);
        assert_eq!(via_helper.region_size, via_new.region_size);
    }

    // -----------------------------------------------------------------------
    // Boundary: 1 MB (smallest meaningful input)
    // -----------------------------------------------------------------------

    /// Given 1 MB, total_size is 1_048_576 and region_size is non-zero.
    #[test]
    fn given_1mb_when_new_then_region_size_nonzero() {
        let cfg = ArenaConfig::new(1);
        assert_eq!(cfg.total_size, 1_048_576);
        assert!(
            cfg.region_size > 0,
            "region_size must be > 0 for 1 MB input"
        );
    }
}
