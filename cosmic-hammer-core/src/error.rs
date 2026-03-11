use thiserror::Error;

/// Central error type for the CosmicHammer system.
#[derive(Debug, Error)]
pub enum CosmicError {
    #[error("Arena allocation failed: {0}")]
    ArenaAlloc(String),

    #[error("Memory lock failed: {0}")]
    MemoryLock(String),

    #[error("Memory advisory failed: {0}")]
    MemoryAdvisory(String),

    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Report error: {0}")]
    Report(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Plugin error: {0}")]
    Plugin(String),

    #[error("JSON error: {0}")]
    Json(String),
}
