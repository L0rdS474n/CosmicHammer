use std::fmt;

/// Status level for a system check result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Info,
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => f.write_str("PASS"),
            Self::Warn => f.write_str("WARN"),
            Self::Fail => f.write_str("FAIL"),
            Self::Info => f.write_str("INFO"),
        }
    }
}

/// Result of a single system check.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub status: CheckStatus,
    pub message: String,
    pub detail: Option<String>,
}

impl CheckResult {
    /// Create a PASS result.
    pub fn pass(message: impl Into<String>) -> Self {
        Self {
            status: CheckStatus::Pass,
            message: message.into(),
            detail: None,
        }
    }

    /// Create a WARN result.
    pub fn warn(message: impl Into<String>) -> Self {
        Self {
            status: CheckStatus::Warn,
            message: message.into(),
            detail: None,
        }
    }

    /// Create a FAIL result.
    pub fn fail(message: impl Into<String>) -> Self {
        Self {
            status: CheckStatus::Fail,
            message: message.into(),
            detail: None,
        }
    }

    /// Create an INFO result.
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            status: CheckStatus::Info,
            message: message.into(),
            detail: None,
        }
    }

    /// Attach optional detail text.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Trait implemented by each system checker module.
pub trait SystemChecker {
    /// Human-readable name of this checker (displayed as section header).
    fn name(&self) -> &str;

    /// Run all checks in this module, returning a list of results.
    fn run(&self) -> Vec<CheckResult>;
}
