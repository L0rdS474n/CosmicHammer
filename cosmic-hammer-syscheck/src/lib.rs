// NOTE: unsafe is required in privileges.rs for libc FFI calls (geteuid, getrlimit)
// on Unix platforms. All unsafe usage is minimal and confined to that module.

pub mod check;
pub mod container;
pub mod cpu;
pub mod ecc;
pub mod mca;
pub mod memory;
pub mod msr;
pub mod numa;
pub mod output;
pub mod privileges;
pub mod swap;
pub mod thp_ksm;

use check::{CheckResult, SystemChecker};

/// Run all system checks in order and return all results with an exit code.
///
/// Exit codes:
/// - 0: system ready (no FAIL, no WARN)
/// - 1: system ready with caveats (WARNs present)
/// - 2: system not ready (FAILs present)
pub fn run_all_checks() -> (Vec<CheckResult>, i32) {
    let checkers: Vec<Box<dyn SystemChecker>> = vec![
        Box::new(privileges::PrivilegesChecker),
        Box::new(cpu::CpuChecker),
        Box::new(msr::MsrChecker),
        Box::new(ecc::EccChecker),
        Box::new(mca::McaChecker),
        Box::new(numa::NumaChecker),
        Box::new(thp_ksm::ThpKsmChecker),
        Box::new(memory::MemoryChecker),
        Box::new(swap::SwapChecker),
        Box::new(container::ContainerChecker),
    ];

    let mut all_results = Vec::new();

    for checker in &checkers {
        let results = checker.run();
        output::print_section(checker.name(), &results);
        all_results.extend(results);
    }

    let exit_code = output::print_summary(&all_results);
    (all_results, exit_code)
}

/// Print all results to the console with colored output.
///
/// This is a convenience function that takes pre-computed results
/// and displays them without re-running checks.
pub fn print_results(results: &[CheckResult]) {
    output::print_summary(results);
}
