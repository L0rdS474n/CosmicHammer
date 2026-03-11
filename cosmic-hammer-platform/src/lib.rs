//! Platform abstraction for memory management in CosmicHammer.
//!
//! Provides a [`PinnedArena`] trait for page-aligned, physically-pinned memory
//! regions, with platform-specific implementations for Linux, macOS, Windows,
//! and FreeBSD. Also exposes container detection and system information queries.

pub mod container;
pub mod sysinfo;
pub mod traits;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "freebsd")]
pub mod freebsd;

// Re-export the trait and its associated types
pub use traits::{LockStatus, MemoryAdvisory, PinnedArena};

// Re-export container detection functions
pub use container::{cgroup_mem_limit, detect_container, ksm_active, thp_policy};

// Re-export system info functions
pub use sysinfo::{get_arch, get_os_info, get_total_ram_mb};

use cosmic_hammer_core::{ArenaConfig, CosmicError};

/// Allocates a platform-specific pinned memory arena based on the given configuration.
///
/// This is the primary entry point for arena allocation. It selects the
/// appropriate platform implementation at compile time and returns a
/// type-erased [`PinnedArena`].
///
/// # Errors
///
/// Returns [`CosmicError::ArenaAlloc`] if the underlying allocation fails.
/// Returns [`CosmicError::UnsupportedPlatform`] on unsupported platforms.
///
/// # Examples
///
/// ```no_run
/// use cosmic_hammer_core::ArenaConfig;
/// use cosmic_hammer_platform::allocate_arena;
///
/// let config = ArenaConfig::new(512);
/// let arena = allocate_arena(&config).expect("allocation failed");
/// assert_eq!(arena.len(), config.total_size);
/// ```
pub fn allocate_arena(config: &ArenaConfig) -> Result<Box<dyn PinnedArena>, CosmicError> {
    if config.total_size == 0 {
        return Err(CosmicError::Config(
            "arena total_size must be greater than zero".to_string(),
        ));
    }

    #[cfg(target_os = "linux")]
    {
        // Check cgroup limit before allocation
        if let Some(cg_limit) = cgroup_mem_limit() {
            if cg_limit < config.total_size as u64 {
                tracing::warn!(
                    "cgroup memory limit is {} MB - arena is {} MB. \
                     mlock will likely fail or pages will be reclaimed under pressure. \
                     Run with: docker run --memory 768m (or larger)",
                    cg_limit / (1024 * 1024),
                    config.total_size / (1024 * 1024),
                );
            }
        }

        let arena = linux::LinuxArena::new(config.total_size)?;
        Ok(Box::new(arena))
    }

    #[cfg(target_os = "macos")]
    {
        let arena = macos::MacosArena::new(config.total_size)?;
        Ok(Box::new(arena))
    }

    #[cfg(target_os = "windows")]
    {
        let arena = windows::WindowsArena::new(config.total_size)?;
        Ok(Box::new(arena))
    }

    #[cfg(target_os = "freebsd")]
    {
        let arena = freebsd::FreebsdArena::new(config.total_size)?;
        Ok(Box::new(arena))
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd"
    )))]
    {
        Err(CosmicError::UnsupportedPlatform(format!(
            "platform '{}' is not supported for arena allocation",
            std::env::consts::OS
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_arena_rejects_zero_size() {
        let config = ArenaConfig {
            total_size: 0,
            region_count: 5,
            region_size: 0,
        };
        let result = allocate_arena(&config);
        assert!(result.is_err());
    }

    #[test]
    fn lock_status_variants_are_distinct() {
        assert_ne!(LockStatus::Locked, LockStatus::BestEffort);
        assert_ne!(LockStatus::Locked, LockStatus::Unlocked);
        assert_ne!(LockStatus::BestEffort, LockStatus::Unlocked);
    }

    #[test]
    fn memory_advisory_variants_exist() {
        // Ensure all variants are constructible
        let _a = MemoryAdvisory::NoHugePage;
        let _b = MemoryAdvisory::NoMerge;
        let _c = MemoryAdvisory::NoDump;
        let _d = MemoryAdvisory::WillNeed;
    }

    #[test]
    fn reexports_are_accessible() {
        // Verify that container detection functions are accessible through re-exports
        let _d = detect_container();
        let _c = cgroup_mem_limit();
        let _k = ksm_active();
        let _t = thp_policy();

        // Verify sysinfo re-exports
        let _a = get_arch();
        let _o = get_os_info();
        let _r = get_total_ram_mb();
    }
}
