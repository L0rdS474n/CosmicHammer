use crate::flip::FlipClass;
use crate::region::RegionType;
use serde::{Deserialize, Serialize};

/// Accumulates flip statistics over a configurable time window.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportWindow {
    pub window_start: i64,
    pub window_end: i64,
    pub scan_cycles: u64,
    pub total_bits: u64,
    pub zero_to_one: u64,
    pub one_to_zero: u64,
    pub multi_bit_events: u64,
    pub dram_rows_seen: u64,
    pub by_class: [u64; FlipClass::COUNT],
    pub by_region: [u64; RegionType::COUNT],
}

impl ReportWindow {
    pub fn new(start: i64) -> Self {
        Self {
            window_start: start,
            ..Default::default()
        }
    }

    pub fn reset(&mut self, new_start: i64) {
        *self = Self::new(new_start);
    }

    pub fn record_flip(
        &mut self,
        flip_class: FlipClass,
        region: RegionType,
        direction: i32,
        n_bits: u32,
    ) {
        self.total_bits += n_bits as u64;
        if direction > 0 {
            self.zero_to_one += 1;
        } else {
            self.one_to_zero += 1;
        }
        if n_bits > 1 {
            self.multi_bit_events += 1;
        }
        self.by_class[flip_class as usize] += 1;
        self.by_region[region as usize] += 1;
        self.dram_rows_seen += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ReportWindow::new — zero-initialized except window_start
    // -----------------------------------------------------------------------

    /// Given start time 0, new() produces a window with all counters zero.
    #[test]
    fn given_start_zero_when_new_then_all_counters_zero() {
        let w = ReportWindow::new(0);
        assert_eq!(w.window_start, 0);
        assert_eq!(w.window_end, 0);
        assert_eq!(w.scan_cycles, 0);
        assert_eq!(w.total_bits, 0);
        assert_eq!(w.zero_to_one, 0);
        assert_eq!(w.one_to_zero, 0);
        assert_eq!(w.multi_bit_events, 0);
        assert_eq!(w.dram_rows_seen, 0);
        assert!(
            w.by_class.iter().all(|&v| v == 0),
            "by_class must be all zeros"
        );
        assert!(
            w.by_region.iter().all(|&v| v == 0),
            "by_region must be all zeros"
        );
    }

    /// Given a non-zero start time, new() stores it in window_start.
    #[test]
    fn given_nonzero_start_when_new_then_window_start_stored() {
        let w = ReportWindow::new(1_700_000_000);
        assert_eq!(w.window_start, 1_700_000_000);
        // Everything else still zero
        assert_eq!(w.total_bits, 0);
    }

    // -----------------------------------------------------------------------
    // record_flip — increments exactly the right counters
    // -----------------------------------------------------------------------

    /// Given a single zero-to-one flip in PtrHijack / Pointer region,
    /// when record_flip is called, zero_to_one increments by 1 and
    /// one_to_zero stays at 0.
    #[test]
    fn given_zero_to_one_flip_when_record_flip_then_zero_to_one_incremented() {
        let mut w = ReportWindow::new(0);
        w.record_flip(FlipClass::PtrHijack, RegionType::Pointer, 1, 1);
        assert_eq!(w.zero_to_one, 1);
        assert_eq!(w.one_to_zero, 0);
    }

    /// Given a single one-to-zero flip, when record_flip is called,
    /// one_to_zero increments by 1 and zero_to_one stays at 0.
    #[test]
    fn given_one_to_zero_flip_when_record_flip_then_one_to_zero_incremented() {
        let mut w = ReportWindow::new(0);
        w.record_flip(FlipClass::DataCorrupt, RegionType::Data, -1, 1);
        assert_eq!(w.one_to_zero, 1);
        assert_eq!(w.zero_to_one, 0);
    }

    /// Given n_bits=1 (single-bit flip), multi_bit_events stays at 0.
    #[test]
    fn given_single_bit_flip_when_record_flip_then_multi_bit_events_not_incremented() {
        let mut w = ReportWindow::new(0);
        w.record_flip(FlipClass::Benign, RegionType::Data, 1, 1);
        assert_eq!(w.multi_bit_events, 0);
    }

    /// Given n_bits=2, multi_bit_events increments by 1.
    #[test]
    fn given_two_bit_flip_when_record_flip_then_multi_bit_events_incremented() {
        let mut w = ReportWindow::new(0);
        w.record_flip(FlipClass::DataCorrupt, RegionType::Data, 1, 2);
        assert_eq!(w.multi_bit_events, 1);
    }

    /// Given n_bits=3, multi_bit_events increments by 1.
    #[test]
    fn given_three_bit_flip_when_record_flip_then_multi_bit_events_incremented() {
        let mut w = ReportWindow::new(0);
        w.record_flip(FlipClass::Benign, RegionType::Data, 1, 3);
        assert_eq!(w.multi_bit_events, 1);
    }

    /// Given a PteNxClear flip, by_class[PteNxClear as usize] increments.
    #[test]
    fn given_pte_nx_clear_flip_when_record_flip_then_by_class_nx_clear_incremented() {
        let mut w = ReportWindow::new(0);
        w.record_flip(FlipClass::PteNxClear, RegionType::PteSim, -1, 1);
        assert_eq!(w.by_class[FlipClass::PteNxClear as usize], 1);
        // All other by_class entries remain zero.
        for (i, &v) in w.by_class.iter().enumerate() {
            if i != FlipClass::PteNxClear as usize {
                assert_eq!(v, 0, "by_class[{i}] must be 0");
            }
        }
    }

    /// Given a PteSim region flip, by_region[PteSim as usize] increments.
    #[test]
    fn given_pte_sim_region_flip_when_record_flip_then_by_region_pte_sim_incremented() {
        let mut w = ReportWindow::new(0);
        w.record_flip(FlipClass::PtePhysCorrupt, RegionType::PteSim, -1, 1);
        assert_eq!(w.by_region[RegionType::PteSim as usize], 1);
        // All other by_region entries remain zero.
        for (i, &v) in w.by_region.iter().enumerate() {
            if i != RegionType::PteSim as usize {
                assert_eq!(v, 0, "by_region[{i}] must be 0");
            }
        }
    }

    /// total_bits accumulates n_bits across multiple calls.
    #[test]
    fn given_multiple_flips_when_record_flip_then_total_bits_accumulated() {
        let mut w = ReportWindow::new(0);
        w.record_flip(FlipClass::Benign, RegionType::Data, 1, 1);
        w.record_flip(FlipClass::Benign, RegionType::Data, 1, 2);
        w.record_flip(FlipClass::Benign, RegionType::Data, 1, 1);
        assert_eq!(w.total_bits, 4); // 1 + 2 + 1
    }

    /// dram_rows_seen increments by 1 on each record_flip call.
    #[test]
    fn given_multiple_flips_when_record_flip_then_dram_rows_seen_incremented() {
        let mut w = ReportWindow::new(0);
        w.record_flip(FlipClass::Benign, RegionType::Data, 1, 1);
        w.record_flip(FlipClass::Benign, RegionType::Data, 1, 1);
        assert_eq!(w.dram_rows_seen, 2);
    }

    // -----------------------------------------------------------------------
    // reset — clears all counters, sets new window_start
    // -----------------------------------------------------------------------

    /// Given a populated window, reset() zeroes all counters and sets the new
    /// window_start.
    #[test]
    fn given_populated_window_when_reset_then_all_counters_cleared() {
        let mut w = ReportWindow::new(1_000);
        // Populate every counter category.
        w.record_flip(FlipClass::PtrHijack, RegionType::Pointer, 1, 2);
        w.record_flip(FlipClass::PteNxClear, RegionType::PteSim, -1, 1);
        w.scan_cycles = 42;
        w.window_end = 9_999;

        // Reset to new window.
        w.reset(2_000);

        assert_eq!(w.window_start, 2_000);
        assert_eq!(w.window_end, 0);
        assert_eq!(w.scan_cycles, 0);
        assert_eq!(w.total_bits, 0);
        assert_eq!(w.zero_to_one, 0);
        assert_eq!(w.one_to_zero, 0);
        assert_eq!(w.multi_bit_events, 0);
        assert_eq!(w.dram_rows_seen, 0);
        assert!(
            w.by_class.iter().all(|&v| v == 0),
            "by_class must be all zeros after reset"
        );
        assert!(
            w.by_region.iter().all(|&v| v == 0),
            "by_region must be all zeros after reset"
        );
    }

    /// reset() is idempotent: calling it twice leaves the window in the state
    /// matching the most recent call.
    #[test]
    fn given_window_when_reset_twice_then_second_start_wins() {
        let mut w = ReportWindow::new(0);
        w.record_flip(FlipClass::Benign, RegionType::Data, 1, 1);
        w.reset(1_000);
        w.reset(2_000);
        assert_eq!(w.window_start, 2_000);
        assert_eq!(w.total_bits, 0);
    }

    // -----------------------------------------------------------------------
    // by_class / by_region array lengths match COUNT constants
    // -----------------------------------------------------------------------

    /// by_class array length equals FlipClass::COUNT.
    #[test]
    fn when_by_class_length_checked_then_equals_flip_class_count() {
        let w = ReportWindow::new(0);
        assert_eq!(w.by_class.len(), FlipClass::COUNT);
    }

    /// by_region array length equals RegionType::COUNT.
    #[test]
    fn when_by_region_length_checked_then_equals_region_type_count() {
        let w = ReportWindow::new(0);
        assert_eq!(w.by_region.len(), RegionType::COUNT);
    }
}
