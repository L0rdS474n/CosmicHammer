use crate::check::{CheckResult, SystemChecker};

/// Detects the virtualisation/container environment.
pub struct ContainerChecker;

/// Detected environment type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Environment {
    BareMetal,
    Docker,
    Vm(String),
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BareMetal => f.write_str("bare metal"),
            Self::Docker => f.write_str("docker"),
            Self::Vm(name) => write!(f, "vm:{}", name),
        }
    }
}

/// Detect the container/virtualisation environment.
pub fn detect_container() -> Environment {
    #[cfg(target_os = "linux")]
    {
        // Check /.dockerenv
        if std::path::Path::new("/.dockerenv").exists() {
            return Environment::Docker;
        }

        // Check /proc/1/cgroup for container indicators
        if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
            let lower = cgroup.to_lowercase();
            if lower.contains("docker")
                || lower.contains("lxc")
                || lower.contains("containerd")
                || lower.contains("kubepods")
            {
                return Environment::Docker;
            }
        }

        // Try systemd-detect-virt
        if let Ok(output) = std::process::Command::new("systemd-detect-virt")
            .arg("--vm")
            .output()
        {
            if output.status.success() {
                let virt = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !virt.is_empty() && virt != "none" {
                    return Environment::Vm(virt);
                }
            }
        }

        Environment::BareMetal
    }

    #[cfg(not(target_os = "linux"))]
    {
        Environment::BareMetal
    }
}

impl SystemChecker for ContainerChecker {
    fn name(&self) -> &str {
        "Virtualisation"
    }

    fn run(&self) -> Vec<CheckResult> {
        let mut results = Vec::new();

        let env = detect_container();
        results.push(CheckResult::info(format!("Environment: {}", env)));

        match &env {
            Environment::BareMetal => {
                results.push(CheckResult::pass(
                    "Bare metal -- direct DRAM access, no hypervisor interference",
                ));
            }
            Environment::Docker => {
                results.push(CheckResult::pass(
                    "Docker container -- host kernel handles DRAM directly, SEU detection valid",
                ));
                results.push(CheckResult::info(
                    "  Ensure: --cap-add IPC_LOCK --ulimit memlock=-1",
                ));
            }
            Environment::Vm(name) => {
                results.push(CheckResult::warn(format!(
                    "Hypervisor: {} -- DRAM access is virtualised",
                    name
                )));
                results.push(CheckResult::warn(
                    "  Prefer bare metal or Docker for accurate SEU observation",
                ));
            }
        }

        results
    }
}
