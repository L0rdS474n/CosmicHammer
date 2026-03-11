use std::path::Path;

use cosmic_hammer_core::error::CosmicError;

use crate::traits::Plugin;

/// Registry that holds loaded plugins.
pub struct PluginRegistry {
    plugins: Vec<Box<dyn Plugin>>,
}

impl PluginRegistry {
    /// Create an empty plugin registry.
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Register a plugin manually.
    pub fn register(&mut self, plugin: Box<dyn Plugin>) {
        self.plugins.push(plugin);
    }

    /// Return a slice of all registered plugins.
    pub fn plugins(&self) -> &[Box<dyn Plugin>] {
        &self.plugins
    }

    /// Return a mutable slice of all registered plugins.
    pub fn plugins_mut(&mut self) -> &mut [Box<dyn Plugin>] {
        &mut self.plugins
    }

    /// Number of loaded plugins.
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Attempt to load plugins from shared libraries in the given directory.
    ///
    /// This is a stub implementation. When `libloading` is added as a
    /// dependency, this will scan for `.so` / `.dll` / `.dylib` files and
    /// load them as plugins.
    ///
    /// For now it returns `Ok(())` without loading anything.
    pub fn load_from_dir(&mut self, _path: &Path) -> Result<(), CosmicError> {
        // Stub: dynamic plugin loading not yet implemented.
        Ok(())
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}
