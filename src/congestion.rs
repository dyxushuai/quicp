//! Runtime-neutral congestion-control extension points.
//!
//! The built-in profiles are configured through [`crate::CongestionControl`]. This module adds a
//! Rust-only factory seam for experiments that need a custom controller without exposing the
//! vendored `noq` controller types through the stable QUICP API or the C ABI.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::header_protection::HeaderProtectionFactory;

/// A bounded snapshot of the RTT estimator supplied to a custom controller.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RttSnapshot {
    /// The current conservative RTT estimate.
    pub conservative: Duration,
    /// The current smoothed RTT estimate.
    pub smoothed: Duration,
    /// The minimum RTT observed so far.
    pub minimum: Duration,
}

/// A packet-sent notification for a custom controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketSent {
    /// Monotonic timestamp supplied by the transport.
    pub now: Instant,
    /// Number of payload bytes sent.
    pub bytes: u64,
    /// Largest packet number in the send batch.
    pub largest_packet_number: u64,
}

/// An acknowledgement notification for a custom controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketAcked {
    /// Monotonic timestamp supplied by the transport.
    pub now: Instant,
    /// Timestamp at which the acknowledged packet was sent.
    pub sent: Instant,
    /// Number of acknowledged payload bytes.
    pub bytes: u64,
    /// Acknowledged packet number.
    pub packet_number: u64,
    /// Whether the application was unable to provide data before this ACK.
    pub app_limited: bool,
    /// RTT information available at the ACK.
    pub rtt: RttSnapshot,
}

/// A completed ACK-batch notification for a custom controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckBatch {
    /// Monotonic timestamp supplied by the transport.
    pub now: Instant,
    /// Bytes currently in flight after processing the batch.
    pub in_flight: u64,
    /// Whether the application was unable to provide data before the batch.
    pub app_limited: bool,
    /// Largest packet number acknowledged by the batch, if any.
    pub largest_packet_number: Option<u64>,
}

/// A congestion-event notification for a custom controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CongestionEvent {
    /// Monotonic timestamp supplied by the transport.
    pub now: Instant,
    /// Timestamp of the latest packet in the event.
    pub sent: Instant,
    /// Whether the event represents persistent congestion.
    pub persistent: bool,
    /// Whether ECN, rather than packet loss, triggered the event.
    pub ecn: bool,
    /// Number of lost bytes in the event.
    pub lost_bytes: u64,
    /// Largest packet number reported lost by the event.
    pub largest_lost_packet_number: u64,
}

/// Controller metrics consumed by QUICP pacing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CongestionMetrics {
    /// Congestion window in bytes.
    pub congestion_window: u64,
    /// Optional slow-start threshold in bytes.
    pub slow_start_threshold: Option<u64>,
    /// Optional pacing rate in bytes per second.
    pub pacing_rate_bytes_per_second: Option<u64>,
    /// Optional maximum send quantum in bytes.
    pub send_quantum: Option<u64>,
}

/// A custom connection/path congestion controller.
///
/// Methods are synchronous and allocation-free from the transport's perspective. Implementations
/// must keep all state bounded, return a nonzero [`Self::window`], and never mutate packet
/// authentication, recovery, flow-control, or carrier sequence state.
pub trait CongestionController: Send + Sync {
    /// Reports a batch of sent packets.
    fn on_sent(&mut self, _event: PacketSent) {}

    /// Reports one packet being sent.
    fn on_packet_sent(&mut self, _event: PacketSent) {}

    /// Reports one acknowledged packet.
    fn on_ack(&mut self, _event: PacketAcked) {}

    /// Reports the end of an ACK batch.
    fn on_end_acks(&mut self, _event: AckBatch) {}

    /// Reports packet or ECN congestion.
    fn on_congestion_event(&mut self, _event: CongestionEvent) {}

    /// Reports one packet loss.
    fn on_packet_lost(&mut self, _lost_bytes: u16, _packet_number: u64, _now: Instant) {}

    /// Reports a spurious congestion event.
    fn on_spurious_congestion_event(&mut self) {}

    /// Reports a path MTU update.
    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    /// Reports a peer ACK-frequency update.
    fn on_ack_frequency_update(
        &mut self,
        _ack_eliciting_threshold: u64,
        _requested_max_ack_delay: Duration,
    ) {
    }

    /// Returns the number of ack-eliciting bytes allowed in flight.
    fn window(&self) -> u64;

    /// Returns metrics used by QUICP pacing.
    fn metrics(&self) -> CongestionMetrics {
        CongestionMetrics {
            congestion_window: self.window(),
            ..CongestionMetrics::default()
        }
    }

    /// Clones the current controller state for backend introspection.
    fn clone_box(&self) -> Box<dyn CongestionController>;

    /// Returns the initial congestion window in bytes.
    fn initial_window(&self) -> u64;
}

/// Constructs one controller for every new QUICP connection/path.
pub trait CongestionControllerFactory: Send + Sync {
    /// Builds a controller with the transport's initial clock and MTU.
    fn build(&self, now: Instant, current_mtu: u16) -> Box<dyn CongestionController>;
}

/// Options that are intentionally separate from serialized configuration.
///
/// The optional factories are Rust-only extensions. The C ABI does not accept callbacks; a future
/// native configuration ABI should select built-in enums instead.
#[derive(Clone, Default)]
pub struct TransportOptions {
    custom_congestion: Option<Arc<dyn CongestionControllerFactory>>,
    custom_header_protection: Option<Arc<dyn HeaderProtectionFactory>>,
}

impl fmt::Debug for TransportOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportOptions")
            .field("custom_congestion", &self.custom_congestion.is_some())
            .field(
                "custom_header_protection",
                &self.custom_header_protection.is_some(),
            )
            .finish()
    }
}

impl TransportOptions {
    /// Creates options using the configured built-in congestion profile.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            custom_congestion: None,
            custom_header_protection: None,
        }
    }

    /// Installs a Rust-only custom congestion controller factory.
    #[must_use]
    pub fn with_congestion_controller_factory(
        mut self,
        factory: Arc<dyn CongestionControllerFactory>,
    ) -> Self {
        self.custom_congestion = Some(factory);
        self
    }

    /// Installs Rust-only custom header protection for the no-TLS profile.
    #[must_use]
    pub fn with_header_protection_factory(
        mut self,
        factory: Arc<dyn HeaderProtectionFactory>,
    ) -> Self {
        self.custom_header_protection = Some(factory);
        self
    }

    pub(crate) fn custom_congestion(&self) -> Option<Arc<dyn CongestionControllerFactory>> {
        self.custom_congestion.clone()
    }

    pub(crate) fn custom_header_protection(&self) -> Option<Arc<dyn HeaderProtectionFactory>> {
        self.custom_header_protection.clone()
    }
}

pub(crate) struct BackendFactory {
    inner: Arc<dyn CongestionControllerFactory>,
}

impl BackendFactory {
    pub(crate) fn new(inner: Arc<dyn CongestionControllerFactory>) -> Self {
        Self { inner }
    }
}

impl fmt::Debug for BackendFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BackendFactory(..)")
    }
}

impl noq::congestion::ControllerFactory for BackendFactory {
    fn build(
        self: Arc<Self>,
        now: Instant,
        current_mtu: u16,
    ) -> Box<dyn noq::congestion::Controller> {
        Box::new(BackendController {
            inner: self.inner.build(now, current_mtu),
        })
    }
}

struct BackendController {
    inner: Box<dyn CongestionController>,
}

impl fmt::Debug for BackendController {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BackendController(..)")
    }
}

impl noq::congestion::Controller for BackendController {
    fn on_sent(&mut self, now: Instant, bytes: u64, largest_pn: u64) {
        self.inner.on_sent(PacketSent {
            now,
            bytes,
            largest_packet_number: largest_pn,
        });
    }

    fn on_packet_sent(&mut self, now: Instant, bytes: u16, pn: u64) {
        self.inner.on_packet_sent(PacketSent {
            now,
            bytes: u64::from(bytes),
            largest_packet_number: pn,
        });
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        pn: u64,
        app_limited: bool,
        rtt: &noq_proto::RttEstimator,
    ) {
        self.inner.on_ack(PacketAcked {
            now,
            sent,
            bytes,
            packet_number: pn,
            app_limited,
            rtt: RttSnapshot {
                conservative: rtt.conservative(),
                smoothed: rtt.get(),
                minimum: rtt.min(),
            },
        });
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.inner.on_end_acks(AckBatch {
            now,
            in_flight,
            app_limited,
            largest_packet_number: largest_packet_num_acked,
        });
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        is_ecn: bool,
        lost_bytes: u64,
        largest_lost_pn: u64,
    ) {
        self.inner.on_congestion_event(CongestionEvent {
            now,
            sent,
            persistent: is_persistent_congestion,
            ecn: is_ecn,
            lost_bytes,
            largest_lost_packet_number: largest_lost_pn,
        });
    }

    fn on_packet_lost(&mut self, lost_bytes: u16, pn: u64, now: Instant) {
        self.inner.on_packet_lost(lost_bytes, pn, now);
    }

    fn on_spurious_congestion_event(&mut self) {
        self.inner.on_spurious_congestion_event();
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.inner.on_mtu_update(new_mtu);
    }

    fn on_ack_frequency_update(
        &mut self,
        ack_eliciting_threshold: u64,
        requested_max_ack_delay: Duration,
    ) {
        self.inner
            .on_ack_frequency_update(ack_eliciting_threshold, requested_max_ack_delay);
    }

    fn window(&self) -> u64 {
        self.inner.window()
    }

    fn metrics(&self) -> noq::congestion::ControllerMetrics {
        let metrics = self.inner.metrics();
        let mut backend = noq::congestion::ControllerMetrics::default();
        backend.congestion_window = metrics.congestion_window;
        backend.ssthresh = metrics.slow_start_threshold;
        backend.pacing_rate = metrics.pacing_rate_bytes_per_second;
        backend.send_quantum = metrics.send_quantum;
        backend
    }

    fn clone_box(&self) -> Box<dyn noq::congestion::Controller> {
        Box::new(Self {
            inner: self.inner.clone_box(),
        })
    }

    fn initial_window(&self) -> u64 {
        self.inner.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BackendFactory, CongestionController, CongestionControllerFactory, CongestionMetrics,
        PacketSent, TransportOptions,
    };
    use std::sync::Arc;
    use std::time::Instant;

    #[derive(Debug)]
    struct ProbeFactory;

    #[derive(Debug)]
    struct ProbeController;

    impl CongestionController for ProbeController {
        fn on_sent(&mut self, _event: PacketSent) {}

        fn window(&self) -> u64 {
            42_000
        }

        fn metrics(&self) -> CongestionMetrics {
            CongestionMetrics {
                congestion_window: 42_000,
                slow_start_threshold: Some(21_000),
                pacing_rate_bytes_per_second: Some(84_000),
                send_quantum: Some(1_200),
            }
        }

        fn clone_box(&self) -> Box<dyn CongestionController> {
            Box::new(Self)
        }

        fn initial_window(&self) -> u64 {
            2_400
        }
    }

    impl CongestionControllerFactory for ProbeFactory {
        fn build(&self, _now: Instant, _current_mtu: u16) -> Box<dyn CongestionController> {
            Box::new(ProbeController)
        }
    }

    #[test]
    fn custom_factory_is_adapted_without_leaking_backend_types() {
        let options =
            TransportOptions::new().with_congestion_controller_factory(Arc::new(ProbeFactory));
        assert!(format!("{options:?}").contains("true"));

        let backend_factory = Arc::new(BackendFactory::new(Arc::new(ProbeFactory)));
        let mut controller = <BackendFactory as noq::congestion::ControllerFactory>::build(
            backend_factory,
            Instant::now(),
            1_200,
        );
        controller.on_sent(Instant::now(), 1_200, 7);
        assert_eq!(controller.window(), 42_000);
        assert_eq!(controller.initial_window(), 2_400);
        let metrics = controller.metrics();
        assert_eq!(metrics.congestion_window, 42_000);
        assert_eq!(metrics.ssthresh, Some(21_000));
        assert_eq!(metrics.pacing_rate, Some(84_000));
        assert_eq!(metrics.send_quantum, Some(1_200));
        assert_eq!(controller.clone_box().window(), 42_000);
    }
}
