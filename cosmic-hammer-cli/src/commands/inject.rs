use std::sync::Arc;

use cosmic_hammer_core::{
    classify_flip, ArenaConfig, FlipDirection, FlipEvent, RegionType, FILL_DATA_A,
};
use cosmic_hammer_platform::allocate_arena;
use cosmic_hammer_pte::{x86_64::X86_64Pte, PteModel};

/// Allocate a small arena, fill it, manually flip a bit, scan, and display the
/// result. This is a testing/demo command to verify detection pipeline.
pub fn execute() -> anyhow::Result<()> {
    println!("[inject] Allocating 1 MB test arena...");

    let config = ArenaConfig::new(1);
    let mut arena =
        allocate_arena(&config).map_err(|e| anyhow::anyhow!("Arena allocation failed: {}", e))?;

    let pte_model: Arc<dyn PteModel> = Arc::new(X86_64Pte);
    let region_size = config.region_size;
    let ptr = arena.as_mut_ptr();
    let len = arena.len();

    // Fill region 3 (Data) with FILL_DATA_A pattern
    let data_region_offset = 3 * region_size;
    if data_region_offset + 8 > len {
        anyhow::bail!("Arena too small for inject test");
    }

    // Fill entire data region
    let slots = region_size / 8;
    for i in 0..slots {
        let offset = data_region_offset + i * 8;
        // SAFETY: offset is within bounds checked above, arena is valid memory
        unsafe {
            let slot = ptr.add(offset) as *mut u64;
            slot.write(FILL_DATA_A);
        }
    }

    // Inject a single-bit flip at the first slot of the data region
    let inject_offset = data_region_offset;
    let expected = FILL_DATA_A;
    let flipped = expected ^ (1u64 << 17); // flip bit 17

    // SAFETY: inject_offset is within bounds
    unsafe {
        let slot = ptr.add(inject_offset) as *mut u64;
        slot.write(flipped);
    }

    // Now scan the data region to find the flip
    let observed = unsafe {
        let slot = ptr.add(inject_offset) as *const u64;
        slot.read()
    };

    let diff = expected ^ observed;
    let bit_position = diff.trailing_zeros() as u8;
    let direction = if observed & (1u64 << bit_position) != 0 {
        FlipDirection::ZeroToOne
    } else {
        FlipDirection::OneToZero
    };
    let n_bits = diff.count_ones();

    let flip_class = classify_flip(
        RegionType::Data,
        expected,
        observed,
        direction.as_int(),
        n_bits,
    );

    let event = FlipEvent {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        offset: inject_offset,
        bit_position,
        expected,
        observed,
        direction,
        n_bits,
        region: RegionType::Data,
        flip_class,
        dram_row: (inject_offset / 8192) as u32,
    };

    println!();
    println!("[inject] Detected injected flip:");
    print_flip_event(&event, &*pte_model);
    println!();
    println!("[inject] Inject test complete.");

    Ok(())
}

fn print_flip_event(event: &FlipEvent, _pte_model: &dyn PteModel) {
    println!(
        "  FLIP @ offset 0x{:08X}  bit {} ({})  {} -> {}",
        event.offset, event.bit_position, event.direction, event.region, event.flip_class,
    );
    println!(
        "        expected=0x{:016X}  observed=0x{:016X}  bits={}  row={}",
        event.expected, event.observed, event.n_bits, event.dram_row,
    );
}
