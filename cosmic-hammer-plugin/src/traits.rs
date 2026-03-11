use cosmic_hammer_core::flip::{FlipClass, FlipEvent};
use cosmic_hammer_core::report::ReportWindow;

/// Action that a plugin can request in response to events.
#[derive(Debug, Clone)]
pub enum PluginAction {
    /// Log a message.
    Log(String),
    /// Request reclassification of a flip event.
    Reclassify(FlipClass),
    /// Raise an alert with the given message.
    Alert(String),
    /// Emit a custom metric (name, value).
    CustomMetric(String, f64),
}

/// Trait for CosmicHammer plugins.
///
/// Plugins receive lifecycle callbacks and can respond with [`PluginAction`]s.
/// All methods have default no-op implementations so plugins only need to
/// override the hooks they care about.
pub trait Plugin: Send + Sync {
    /// Human-readable name of this plugin.
    fn name(&self) -> &str;

    /// Semver version string of this plugin.
    fn version(&self) -> &str;

    /// Called once when the plugin is loaded and the system initializes.
    fn on_init(&mut self) {}

    /// Called for each detected bit-flip event.
    ///
    /// Return `Some(PluginAction)` to request an action, or `None` to pass.
    fn on_flip(&self, _event: &FlipEvent) -> Option<PluginAction> {
        None
    }

    /// Called when a report window is finalized.
    ///
    /// Return `Some(PluginAction)` to request an action, or `None` to pass.
    fn on_report(&self, _report: &ReportWindow) -> Option<PluginAction> {
        None
    }

    /// Called once when the system is shutting down.
    fn on_shutdown(&self) {}
}
