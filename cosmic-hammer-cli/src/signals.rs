use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Install a Ctrl-C handler that clears the returned flag.
///
/// The caller should poll `running.load(Ordering::SeqCst)` in its main loop
/// and break when it returns `false`.
pub fn setup_signal_handler() -> Arc<AtomicBool> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");
    running
}
