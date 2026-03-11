use tracing_subscriber::EnvFilter;

/// Initialize the tracing subscriber with a default filter of `cosmic_hammer=info`.
///
/// The filter can be overridden via the `RUST_LOG` environment variable.
pub fn init_logging() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("cosmic_hammer=info"));

    tracing_subscriber::fmt().with_env_filter(filter).init();
}
