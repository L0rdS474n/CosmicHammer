use crate::check::{CheckResult, SystemChecker};

/// Checks MSR accessibility and reads MCG_CAP and MCG_STATUS.
pub struct MsrChecker;

impl SystemChecker for MsrChecker {
    fn name(&self) -> &str {
        "MSR Access (/dev/cpu/*/msr)"
    }

    fn run(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();

        #[cfg(target_os = "linux")]
        {
            use std::path::Path;

            let msr_path = Path::new("/dev/cpu/0/msr");
            if msr_path.exists() {
                results.push(CheckResult::pass("/dev/cpu/0/msr accessible"));

                // Try to read MCG_CAP (MSR 0x179) and MCG_STATUS (MSR 0x17A)
                // These reads require root and the msr module loaded.
                // We report Info-level results since failure is common in containers.
                if let Ok(mcg_cap) = read_msr(0x179) {
                    let mca_banks = mcg_cap & 0xFF;
                    results.push(CheckResult::info(format!(
                        "MCA banks (MCG_CAP[7:0]): {}",
                        mca_banks
                    )));
                    if mca_banks > 0 {
                        results.push(CheckResult::pass(format!(
                            "MCA bank count readable: {} banks",
                            mca_banks
                        )));
                    } else {
                        results.push(CheckResult::warn(
                            "MCA bank count = 0 (virtualised or disabled)",
                        ));
                    }
                }

                if let Ok(mcg_status) = read_msr(0x17A) {
                    if mcg_status != 0 {
                        results.push(CheckResult::warn(format!(
                            "MCG_STATUS=0x{:x} non-zero -- MCE in progress or pending",
                            mcg_status
                        )));
                    } else {
                        results.push(CheckResult::pass("MCG_STATUS = 0 (no pending MCE)"));
                    }
                }
            } else {
                // Check if running in Docker
                let in_docker = std::path::Path::new("/.dockerenv").exists();
                if in_docker {
                    results.push(CheckResult::info(
                        "/dev/cpu/0/msr not exposed -- add to docker run for MCA/SMI checks:",
                    ));
                    results.push(CheckResult::info(
                        "  --device /dev/cpu/0/msr (and modprobe msr on the host first)",
                    ));
                } else {
                    results.push(CheckResult::warn(
                        "/dev/cpu/0/msr not present -- load module: modprobe msr",
                    ));
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            results.push(CheckResult::info("Not available on this platform"));
        }

        results
    }
}

/// Read a Model-Specific Register by seeking into /dev/cpu/0/msr.
///
/// The MSR device file treats offsets as MSR addresses. Reading 8 bytes
/// at offset `msr_addr` returns the 64-bit MSR value in little-endian.
#[cfg(target_os = "linux")]
fn read_msr(msr_addr: u64) -> Result<u64, std::io::Error> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open("/dev/cpu/0/msr")?;
    file.seek(SeekFrom::Start(msr_addr))?;
    let mut buf = [0u8; 8];
    file.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}
