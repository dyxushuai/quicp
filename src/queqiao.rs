//! Queqiao-inspired shared-path congestion plugin.
//!
//! This is an adapter policy, not the Queqiao wire protocol, FEC codec, SOCKS5 proxy, or TLS
//! identity layer. It shares one bounded congestion window across QUICP paths and treats
//! non-persistent, non-ECN loss below the configured floor as an erasure signal.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::congestion::{
    CongestionController, CongestionControllerFactory, CongestionEvent, CongestionMetrics,
    PacketAcked, PacketSent, TransportOptions,
};
use crate::plugin::{PluginError, QuicpPlugin};

/// Configuration for [`QueqiaoPlugin`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueqiaoConfig {
    /// Smallest congestion window in bytes.
    pub min_window: u64,
    /// Initial shared congestion window in bytes.
    pub initial_window: u64,
    /// Largest shared congestion window in bytes.
    pub max_window: u64,
    /// Optional pacing rate shared by the endpoint pair.
    pub pacing_rate_bytes_per_second: Option<u64>,
    /// Loss floor in parts per million of the current window; below it, ordinary loss is erasure.
    pub erasure_floor_ppm: u32,
}

impl Default for QueqiaoConfig {
    fn default() -> Self {
        Self {
            min_window: 12 * 1024,
            initial_window: 64 * 1024,
            max_window: 4 * 1024 * 1024,
            pacing_rate_bytes_per_second: None,
            erasure_floor_ppm: 0,
        }
    }
}

impl QueqiaoConfig {
    fn validate(self) -> Result<Self, PluginError> {
        if self.min_window == 0
            || self.initial_window < self.min_window
            || self.max_window < self.initial_window
            || self.erasure_floor_ppm > 1_000_000
            || self.pacing_rate_bytes_per_second == Some(0)
        {
            return Err(PluginError::Configuration(
                "invalid Queqiao window, pacing, or erasure-floor limits".to_owned(),
            ));
        }
        Ok(self)
    }
}

/// Shared state for all controllers created by one plugin.
#[derive(Debug)]
struct SharedPath {
    window: AtomicU64,
    in_flight: AtomicU64,
}

/// A bounded shared-path controller factory.
#[derive(Clone, Debug)]
struct QueqiaoFactory {
    config: QueqiaoConfig,
    shared: Arc<SharedPath>,
}

impl CongestionControllerFactory for QueqiaoFactory {
    fn build(&self, _now: Instant, _current_mtu: u16) -> Box<dyn CongestionController> {
        Box::new(QueqiaoController {
            config: self.config,
            shared: Arc::clone(&self.shared),
        })
    }
}

/// A Queqiao-inspired shared-path plugin.
#[derive(Clone, Debug)]
pub struct QueqiaoPlugin {
    config: QueqiaoConfig,
    shared: Arc<SharedPath>,
}

impl QueqiaoPlugin {
    /// Creates a plugin after validating its bounded limits.
    ///
    /// # Errors
    ///
    /// Returns [`PluginError::Configuration`] when a window, pacing, or erasure-floor limit is
    /// invalid.
    pub fn new(config: QueqiaoConfig) -> Result<Self, PluginError> {
        let config = config.validate()?;
        Ok(Self {
            shared: Arc::new(SharedPath {
                window: AtomicU64::new(config.initial_window),
                in_flight: AtomicU64::new(0),
            }),
            config,
        })
    }

    /// Returns the validated policy.
    #[must_use]
    pub const fn config(&self) -> QueqiaoConfig {
        self.config
    }
}

impl Default for QueqiaoPlugin {
    fn default() -> Self {
        Self::new(QueqiaoConfig::default()).expect("default Queqiao config is valid")
    }
}

impl QuicpPlugin for QueqiaoPlugin {
    fn name(&self) -> &'static str {
        "queqiao"
    }

    fn configure(&self, options: &mut TransportOptions) -> Result<(), PluginError> {
        *options = options
            .clone()
            .with_congestion_controller_factory(Arc::new(QueqiaoFactory {
                config: self.config,
                shared: Arc::clone(&self.shared),
            }));
        Ok(())
    }
}

#[derive(Debug)]
struct QueqiaoController {
    config: QueqiaoConfig,
    shared: Arc<SharedPath>,
}

impl QueqiaoController {
    fn update_window(&self, update: impl Fn(u64) -> u64) {
        let mut current = self.shared.window.load(Ordering::Relaxed);
        loop {
            let next = update(current);
            match self.shared.window.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    fn add_window(&self, bytes: u64) {
        let increment = bytes.max(1);
        self.update_window(|window| window.saturating_add(increment).min(self.config.max_window));
    }

    fn subtract_in_flight(&self, bytes: u64) {
        let mut current = self.shared.in_flight.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_sub(bytes);
            match self.shared.in_flight.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    fn reduce_window(&self) {
        self.update_window(|window| (window / 2).max(self.config.min_window));
    }
}

impl CongestionController for QueqiaoController {
    fn on_packet_sent(&mut self, event: PacketSent) {
        self.shared
            .in_flight
            .fetch_add(event.bytes, Ordering::Relaxed);
    }

    fn on_ack(&mut self, event: PacketAcked) {
        self.subtract_in_flight(event.bytes);
        self.add_window(event.bytes / 16);
    }

    fn on_congestion_event(&mut self, event: CongestionEvent) {
        let loss_ppm = event
            .lost_bytes
            .saturating_mul(1_000_000)
            .checked_div(self.window().max(1))
            .unwrap_or(u64::MAX);
        if event.persistent
            || event.ecn
            || self.config.erasure_floor_ppm == 0
            || loss_ppm > u64::from(self.config.erasure_floor_ppm)
        {
            self.reduce_window();
        }
    }

    fn window(&self) -> u64 {
        self.shared.window.load(Ordering::Relaxed)
    }

    fn metrics(&self) -> CongestionMetrics {
        CongestionMetrics {
            congestion_window: self.window(),
            pacing_rate_bytes_per_second: self.config.pacing_rate_bytes_per_second,
            ..CongestionMetrics::default()
        }
    }

    fn clone_box(&self) -> Box<dyn CongestionController> {
        Box::new(Self {
            config: self.config,
            shared: Arc::clone(&self.shared),
        })
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_window
    }
}

impl fmt::Display for QueqiaoPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "queqiao(shared-window={})",
            self.config.initial_window
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::PluginRegistry;

    #[test]
    fn plugin_builds_shared_transport_options() {
        let mut registry = PluginRegistry::new();
        registry.register(QueqiaoPlugin::default()).unwrap();
        let options = registry.build_transport_options().unwrap();
        assert!(format!("{options:?}").contains("custom_congestion: true"));
    }

    #[test]
    fn erasure_mode_keeps_window_but_persistent_loss_reduces_it() {
        let plugin = QueqiaoPlugin::new(QueqiaoConfig {
            erasure_floor_ppm: 50_000,
            ..QueqiaoConfig::default()
        })
        .unwrap();
        let factory = QueqiaoFactory {
            config: plugin.config,
            shared: Arc::clone(&plugin.shared),
        };
        let mut controller = factory.build(Instant::now(), 1200);
        let before = controller.window();
        controller.on_congestion_event(CongestionEvent {
            now: Instant::now(),
            sent: Instant::now(),
            persistent: false,
            ecn: false,
            lost_bytes: 1200,
            largest_lost_packet_number: 1,
        });
        assert_eq!(controller.window(), before);
        controller.on_congestion_event(CongestionEvent {
            now: Instant::now(),
            sent: Instant::now(),
            persistent: true,
            ecn: false,
            lost_bytes: 1200,
            largest_lost_packet_number: 2,
        });
        assert!(controller.window() < before);
    }
}
