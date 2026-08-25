//! Small Rust-only configuration plugin registry.
//!
//! Plugins run once while building [`TransportOptions`]. They are deliberately not packet
//! callbacks and are not exposed through the C ABI, so the data plane keeps the same ownership
//! and allocation rules as the core library.

use std::fmt;
use std::sync::Arc;

use thiserror::Error;

use crate::congestion::TransportOptions;

/// Maximum number of configuration plugins in one registry.
pub const MAX_PLUGINS: usize = 8;

/// Errors returned while registering or applying a plugin.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum PluginError {
    /// A plugin returned an empty name.
    #[error("plugin name must not be empty")]
    EmptyName,
    /// Two plugins tried to register the same name.
    #[error("plugin name is already registered: {0}")]
    DuplicateName(&'static str),
    /// The bounded registry is full.
    #[error("plugin registry is full (maximum {MAX_PLUGINS})")]
    Capacity,
    /// A plugin rejected the current transport options.
    #[error("plugin configuration rejected: {0}")]
    Configuration(String),
}

/// A configuration-time QUICP extension.
pub trait QuicpPlugin: Send + Sync {
    /// Stable name used in diagnostics and duplicate detection.
    fn name(&self) -> &'static str;

    /// Applies the plugin's transport settings.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::Configuration`] when the plugin cannot be applied to the current
    /// options.
    fn configure(&self, options: &mut TransportOptions) -> Result<(), PluginError>;
}

/// Bounded collection of configuration plugins.
pub struct PluginRegistry {
    plugins: [Option<Arc<dyn QuicpPlugin>>; MAX_PLUGINS],
    len: usize,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self {
            plugins: [const { None }; MAX_PLUGINS],
            len: 0,
        }
    }
}

impl fmt::Debug for PluginRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PluginRegistry")
            .field("plugins", &self.len)
            .finish()
    }
}

impl PluginRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one plugin.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is empty, duplicated, or the bounded registry is full.
    pub fn register<P>(&mut self, plugin: P) -> Result<(), PluginError>
    where
        P: QuicpPlugin + 'static,
    {
        self.register_arc(Arc::new(plugin))
    }

    /// Registers an already shared plugin instance.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is empty, duplicated, or the bounded registry is full.
    pub fn register_arc(&mut self, plugin: Arc<dyn QuicpPlugin>) -> Result<(), PluginError> {
        let name = plugin.name();
        if name.is_empty() {
            return Err(PluginError::EmptyName);
        }
        if self
            .plugins
            .iter()
            .flatten()
            .any(|existing| existing.name() == name)
        {
            return Err(PluginError::DuplicateName(name));
        }
        if self.len == MAX_PLUGINS {
            return Err(PluginError::Capacity);
        }
        let Some(slot) = self.plugins.iter_mut().find(|slot| slot.is_none()) else {
            return Err(PluginError::Capacity);
        };
        *slot = Some(plugin);
        self.len += 1;
        Ok(())
    }

    /// Builds options by applying plugins in registration order.
    ///
    /// # Errors
    ///
    /// Returns the first plugin configuration error.
    pub fn build_transport_options(&self) -> Result<TransportOptions, PluginError> {
        let mut options = TransportOptions::new();
        for plugin in self.plugins.iter().flatten() {
            plugin.configure(&mut options)?;
        }
        Ok(options)
    }

    /// Returns the number of registered plugins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether no plugins are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EmptyPlugin;

    impl QuicpPlugin for EmptyPlugin {
        fn name(&self) -> &'static str {
            "empty"
        }

        fn configure(&self, _options: &mut TransportOptions) -> Result<(), PluginError> {
            Ok(())
        }
    }

    #[test]
    fn registry_rejects_duplicate_names() {
        let mut registry = PluginRegistry::new();
        registry.register(EmptyPlugin).unwrap();
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.register(EmptyPlugin),
            Err(PluginError::DuplicateName("empty"))
        );
        assert!(!registry.is_empty());
    }
}
