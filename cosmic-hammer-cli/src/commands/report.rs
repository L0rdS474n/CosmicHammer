use std::fs;

use cosmic_hammer_report::ReportJson;

/// Read a saved JSON report file and display it.
pub fn execute(file: &str) -> anyhow::Result<()> {
    let contents = fs::read_to_string(file)
        .map_err(|e| anyhow::anyhow!("Failed to read report file '{}': {}", file, e))?;

    let report: ReportJson = serde_json::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse report JSON: {}", e))?;

    println!("CosmicHammer Report");
    println!("==================================================");
    println!("  Schema version : {}", report.schema_version);
    println!("  Window         : {:.1}h", report.window_hours);
    println!("  Window start   : {}", report.window_start);
    println!("  Window end     : {}", report.window_end);
    println!();
    println!("Platform:");
    println!("  Arch           : {}", report.platform.arch);
    println!("  OS             : {}", report.platform.os);
    println!("  RAM            : {} MB", report.platform.ram_mb);
    println!("  ECC            : {}", report.platform.ecc);
    if let Some(alt) = report.platform.altitude_m {
        println!("  Altitude       : {} m", alt);
    }
    println!();
    println!("Flip Totals:");
    println!(
        "  Total bits     : {}",
        report.flip_totals.total_bits_observed
    );
    println!("  0->1           : {}", report.flip_totals.zero_to_one);
    println!("  1->0           : {}", report.flip_totals.one_to_zero);
    println!("  Multi-bit      : {}", report.multi_bit_events);
    println!("  DRAM rows      : {}", report.dram_rows_affected);
    println!("  Scan cycles    : {}", report.scan_cycles);
    println!();
    println!("By Class:");
    for (key, val) in &report.by_class {
        println!("  {:<20} : {}", key, val);
    }
    println!();
    println!("By Region:");
    for (key, val) in &report.by_region {
        println!("  {:<20} : {}", key, val);
    }

    Ok(())
}
