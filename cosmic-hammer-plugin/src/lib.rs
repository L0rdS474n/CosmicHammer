// NOTE: forbid(unsafe_code) will be relaxed when libloading is added for plugin loading.
// For now, the loader is a stub without FFI.
#![forbid(unsafe_code)]

pub mod loader;
pub mod traits;

pub use loader::PluginRegistry;
pub use traits::{Plugin, PluginAction};
