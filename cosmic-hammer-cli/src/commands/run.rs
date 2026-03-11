use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cosmic_hammer_core::{
    fmt_duration, parse_report_window, ArenaConfig, FlipClass, FlipEvent, ReportWindow, VERSION,
};
use cosmic_hammer_platform::{
    allocate_arena, detect_container, get_arch, get_os_info, get_total_ram_mb, LockStatus,
};
use cosmic_hammer_pte::{arm64::Arm64Pte, riscv::RiscvSv39Pte, x86_64::X86_64Pte, PteModel};
use cosmic_hammer_report::{build_report_json, dump_report_to_file};
use cosmic_hammer_scanner::Arena;

use crate::signals::setup_signal_handler;

/// Execute the main scan loop.
#[allow(clippy::too_many_arguments)]
pub fn execute(
    report_window_str: &str,
    report_url: Option<&str>,
    altitude: Option<i32>,
    interval: u32,
    _threads: usize,
    pte_model_str: &str,
    _no_tui: bool,
    arena_size_mb: usize,
) -> anyhow::Result<()> {
    // 1. Parse report window
    let window_secs = parse_report_window(report_window_str).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid report window '{}'. Use e.g. 10s, 30m, 6h, 3d",
            report_window_str
        )
    })?;

    // 2. Select PTE model
    let pte_model: Box<dyn PteModel> = select_pte_model(pte_model_str)?;

    // 3. Create arena config
    let config = ArenaConfig::new(arena_size_mb);
    let region_count = config.region_count;

    // 4. Allocate pinned arena and wrap in scanner Arena
    println!("[*] Allocating {} MB arena...", arena_size_mb);
    let pinned =
        allocate_arena(&config).map_err(|e| anyhow::anyhow!("Arena allocation failed: {}", e))?;

    // Print arena pointer and lock status before wrapping
    let lock_label = match pinned.lock_status() {
        LockStatus::Locked => "Locked",
        LockStatus::BestEffort => "BestEffort",
        LockStatus::Unlocked => "Unlocked",
    };
    println!("[+] Arena @ {:?} (lock: {})", pinned.as_ptr(), lock_label);

    let mut arena = Arena::new(pinned, config, pte_model);

    // 5. Initial fill with sentinel patterns (matching C fill_arena exactly)
    println!("[*] Writing sentinel patterns + PTE simulation region...");
    arena.fill();
    println!("[+] Arena ready.");

    // 6. Print banner
    let os_info = get_os_info();
    let arch = get_arch();
    let ram_mb = get_total_ram_mb();
    let container = detect_container();
    let window_fmt = fmt_duration(window_secs);

    print_banner(
        &os_info,
        &arch,
        ram_mb,
        container,
        arena_size_mb,
        region_count,
        interval,
        &window_fmt,
    );

    // 7. Setup signal handler
    let running = setup_signal_handler();

    // 8. Initialize report window
    let now_secs = current_unix_secs();
    let mut report = ReportWindow::new(now_secs);
    let mut next_report_at = now_secs + window_secs;
    let mut scan_cycles: u64 = 0;
    let mut total_flips: u64 = 0;
    let mut session_by_class = [0u64; FlipClass::COUNT];
    let start_time = SystemTime::now();

    println!();
    println!("[*] Scanning... press Ctrl-C to stop.");
    println!();

    // 9. Main loop (matches C: spray -> sleep -> scan -> process)
    while running.load(Ordering::SeqCst) {
        // a. Spray pass: touch one word per 4KB page to keep pages resident
        //    (matches C's spray_pass, not a full re-fill)
        arena.spray_pass();

        // b. Sleep for interval
        sleep_interruptible(Duration::from_secs(interval as u64), &running);
        if !running.load(Ordering::SeqCst) {
            break;
        }

        // c. Scan for flips (volatile reads, sentinel restore on mismatch)
        let events = arena.scan();
        scan_cycles += 1;
        report.scan_cycles = scan_cycles;

        // d. Process events
        if events.is_empty() {
            // Overwrite same line so header stays visible
            print!(
                "\r[{}] Scan #{} \u{2014} no flips        ",
                timestamp_now(),
                scan_cycles
            );
            std::io::stdout().flush().ok();
        } else {
            // Move past the \r status line before printing flip details
            println!();
            for event in &events {
                total_flips += 1;
                session_by_class[event.flip_class as usize] += 1;
                report.record_flip(
                    event.flip_class,
                    event.region,
                    event.direction.as_int(),
                    event.n_bits,
                );

                // Print event to stdout (headless / no-TUI mode)
                print_flip_event(event, total_flips);
            }
            println!(
                "[{}] Scan #{} \u{2014} {} flip(s)",
                timestamp_now(),
                scan_cycles,
                events.len()
            );
            std::io::stdout().flush().ok();
        }

        // e. Check report window timer
        let now = current_unix_secs();
        if now >= next_report_at {
            report.window_end = now;
            emit_report(
                &report,
                window_secs,
                altitude,
                &arch,
                &os_info,
                ram_mb,
                report_url,
            );
            report.reset(now);
            next_report_at = now + window_secs;
        }
    }

    // 10. On exit: emit final report and print stats
    println!();
    println!("[*] Interrupted -- finalizing...");

    report.window_end = current_unix_secs();
    emit_report(
        &report,
        window_secs,
        altitude,
        &arch,
        &os_info,
        ram_mb,
        report_url,
    );

    let runtime_secs = start_time.elapsed().map(|d| d.as_secs()).unwrap_or(0);
    println!();
    println!("\u{2500}\u{2500}\u{2500} Session Stats \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");
    println!("  Runtime        {} s", runtime_secs);
    println!("  Total flips    {}", total_flips);
    println!("  Scan cycles    {}", scan_cycles);
    if total_flips > 0 {
        for (i, &count) in session_by_class.iter().enumerate() {
            if count > 0 {
                if let Some(cls) = FlipClass::from_index(i) {
                    println!("  {:<22} {}", cls.name(), count);
                }
            }
        }
    }
    println!("\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}");
    println!("[*] Arena released. Goodbye.");

    Ok(())
}

/// Select the PTE model based on the user's --pte-model argument.
fn select_pte_model(model: &str) -> anyhow::Result<Box<dyn PteModel>> {
    match model {
        "auto" => {
            let arch = std::env::consts::ARCH;
            match arch {
                "x86_64" | "x86" => Ok(Box::new(X86_64Pte)),
                "aarch64" | "arm" => Ok(Box::new(Arm64Pte)),
                "riscv64" | "riscv32" => Ok(Box::new(RiscvSv39Pte)),
                _ => {
                    tracing::warn!(
                        "Unknown arch '{}' for PTE model auto-detection, defaulting to x86_64",
                        arch
                    );
                    Ok(Box::new(X86_64Pte))
                }
            }
        }
        "x86_64" | "x86" => Ok(Box::new(X86_64Pte)),
        "arm64" | "aarch64" => Ok(Box::new(Arm64Pte)),
        "riscv-sv39" | "riscv" => Ok(Box::new(RiscvSv39Pte)),
        _ => Err(anyhow::anyhow!(
            "Unknown PTE model '{}'. Use: auto, x86_64, arm64, riscv-sv39",
            model
        )),
    }
}

/// Print a single flip event to stdout.
fn print_flip_event(event: &FlipEvent, flip_number: u64) {
    let severity = match event.flip_class {
        FlipClass::Benign => "---",
        FlipClass::DataCorrupt => "LOW",
        FlipClass::PtrHijack | FlipClass::PteWriteSet => "MED",
        FlipClass::PrivEsc | FlipClass::PteSupervisorEsc => "HI ",
        FlipClass::CodePage | FlipClass::PteNxClear | FlipClass::PtePhysCorrupt => "CRT",
        FlipClass::PtePresentClear => "MED",
    };

    println!(
        "[{severity}] #{flip_number}  {region}  bit {bit}  {dir}  {cls}  \
         offset=0x{offset:08X}  expected=0x{exp:016X}  observed=0x{obs:016X}  \
         bits={nbits}  row={row}",
        severity = severity,
        flip_number = flip_number,
        region = event.region,
        bit = event.bit_position,
        dir = event.direction,
        cls = event.flip_class,
        offset = event.offset,
        exp = event.expected,
        obs = event.observed,
        nbits = event.n_bits,
        row = event.dram_row,
    );
}

/// Build and emit a report (to file and optionally to URL).
fn emit_report(
    window: &ReportWindow,
    window_secs: i64,
    altitude: Option<i32>,
    arch: &str,
    os: &str,
    ram_mb: u64,
    report_url: Option<&str>,
) {
    let report_json = build_report_json(
        window,
        window_secs,
        altitude.map(|a| a as i64),
        arch,
        os,
        ram_mb,
        false, // ECC detection is handled by syscheck, default false for now
    );

    match dump_report_to_file(&report_json) {
        Ok(filename) => {
            tracing::info!("Report saved: {}", filename);
        }
        Err(e) => {
            tracing::error!("Failed to save report: {}", e);
        }
    }

    if let Some(url) = report_url {
        tracing::info!("Remote reporting URL configured: {}", url);
        // post_report is async; for now just log the intent.
        // Full async support will be added when reqwest is integrated.
        println!(
            "[*] Remote reporting to {} (stub -- not yet implemented)",
            url
        );
    }
}

/// Print the startup banner.
#[allow(clippy::too_many_arguments)]
fn print_banner(
    os: &str,
    arch: &str,
    ram_mb: u64,
    container: bool,
    arena_size_mb: usize,
    region_count: usize,
    interval: u32,
    window_fmt: &str,
) {
    println!(
        "\u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\
         \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\
         \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\
         \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\
         \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\
         \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}"
    );
    println!(
        "\u{2551}   \u{2604}  CosmicHammer v{}  \u{2014}  FuzzSociety         \u{2551}",
        VERSION
    );
    println!(
        "\u{255A}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\
         \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\
         \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\
         \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\
         \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\
         \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255D}"
    );
    println!("  Host      {} {}", os, arch);
    println!("  RAM       {} MB", ram_mb);
    println!("  Container {}", if container { "yes" } else { "no" });
    println!(
        "  Arena     {} MB / {} regions",
        arena_size_mb, region_count
    );
    println!("  Interval  {} s", interval);
    println!("  Window    {}", window_fmt);
}

/// Return the current UTC time as an ISO 8601 string (e.g. "2024-01-15T12:30:05Z").
fn timestamp_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Manual UTC breakdown (no chrono dependency)
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Days since 1970-01-01 → year/month/day (civil calendar)
    // Algorithm from Howard Hinnant (public domain)
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds
    )
}

/// Get the current time as Unix seconds.
fn current_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Sleep for the given duration, but check the running flag periodically
/// so we can break out quickly on Ctrl-C.
fn sleep_interruptible(duration: Duration, running: &Arc<AtomicBool>) {
    let step = Duration::from_millis(250);
    let mut remaining = duration;

    while remaining > Duration::ZERO && running.load(Ordering::SeqCst) {
        let sleep_time = remaining.min(step);
        std::thread::sleep(sleep_time);
        remaining = remaining.saturating_sub(sleep_time);
    }
}
