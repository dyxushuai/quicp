use std::sync::Arc;

use noq::{
    AckFrequencyConfig, IdleTimeout, MtuDiscoveryConfig, PathEvent, PathId, PathStatus,
    TransportConfig, VarInt,
};
use thiserror::Error;

use crate::config::{CongestionControl, MultipathMode, PmtuMode, QuicpTransportConfig};
use crate::congestion::{BackendFactory, CongestionControllerFactory};
use crate::faketcp::FourTuple;

const MAX_PATH_IDS: usize = 8;
const INITIAL_BACKOFF_SECONDS: u64 = 5;
const MAX_BACKOFF_SECONDS: u64 = 60;
const CHURN_BURST: u8 = 2;
const CHURN_REFILL_SECONDS: u64 = 5;
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PathRole {
    Primary,
    Backup,
}

impl PathRole {
    const fn index(self) -> usize {
        match self {
            Self::Primary => 0,
            Self::Backup => 1,
        }
    }

    const fn expected_status() -> PathStatus {
        // Path status is local scheduler state. A peer-created path starts as Available on the
        // remote endpoint even when this endpoint opened it as a local Backup path.
        PathStatus::Available
    }
}

/// Aggregate readiness of the configured primary and backup paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathHealth {
    /// Required path validation has not completed.
    NotReady,
    /// Every required path is available.
    Ready,
    /// The primary remains usable but a backup path is unavailable.
    Degraded,
    /// No required path remains usable.
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PathState {
    Validating,
    Established,
    Lost,
}

#[derive(Clone, Copy, Debug)]
struct Path {
    id: PathId,
    role: PathRole,
    state: PathState,
    remote_status: Option<PathStatus>,
    carrier_tuple: Option<FourTuple>,
}

impl Path {
    fn usable(self) -> bool {
        self.state == PathState::Established
            && self.remote_status == Some(PathRole::expected_status())
    }
}

#[derive(Debug)]
pub struct PathManager {
    mode: MultipathMode,
    paths: [Option<Path>; 2],
    path_count: usize,
    seen: [Option<PathId>; MAX_PATH_IDS],
    seen_count: usize,
    retry_at: [u64; 2],
    retry_delay: [u64; 2],
    activated: bool,
    reliable: bool,
}

impl PathManager {
    #[must_use]
    pub fn new(mode: MultipathMode) -> Self {
        Self {
            mode,
            paths: [None; 2],
            path_count: 0,
            seen: [None; MAX_PATH_IDS],
            seen_count: 0,
            retry_at: [0; 2],
            retry_delay: [INITIAL_BACKOFF_SECONDS; 2],
            activated: false,
            reliable: true,
        }
    }

    /// Reserves a fresh path ID before transport validation starts.
    ///
    /// # Errors
    ///
    /// Returns an error if the role, path budget, ID, or retry timing is invalid.
    pub fn begin_path(
        &mut self,
        role: PathRole,
        id: PathId,
        now_seconds: u64,
    ) -> Result<(), PathError> {
        self.ensure_reliable()?;
        if self.mode == MultipathMode::Off && role == PathRole::Backup {
            return Err(PathError::RoleDisabled);
        }
        let index = role.index();
        if self.paths.iter().flatten().any(|path| path.role == role) {
            return Err(PathError::RoleBusy);
        }
        if self
            .paths
            .iter()
            .flatten()
            .any(|path| path.state == PathState::Validating)
        {
            return Err(PathError::ValidationInFlight);
        }
        if self.path_count == usize::from(self.mode.path_limit()) {
            return Err(PathError::PathLimit);
        }
        if self.seen[..self.seen_count].contains(&Some(id)) {
            return Err(PathError::ReusedPathId);
        }
        if self.seen_count == MAX_PATH_IDS {
            return Err(PathError::LifetimeCap);
        }
        if now_seconds < self.retry_at[index] {
            return Err(PathError::Backoff {
                retry_at: self.retry_at[index],
            });
        }

        let Some(slot) = self.paths.iter_mut().find(|path| path.is_none()) else {
            return Err(PathError::PathLimit);
        };
        self.seen[self.seen_count] = Some(id);
        self.seen_count += 1;
        *slot = Some(Path {
            id,
            role,
            state: PathState::Validating,
            remote_status: None,
            carrier_tuple: None,
        });
        self.path_count += 1;
        Ok(())
    }

    /// Binds one path to its own `FakeTCP` four-tuple before packet I/O starts.
    ///
    /// QUICP path IDs may share a session ID, but a changed tuple must never reuse another path's
    /// `FakeTCP` sequence or replay window.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown path, an already-bound path, or a duplicate tuple.
    pub fn bind_carrier_tuple(&mut self, id: PathId, tuple: FourTuple) -> Result<(), PathError> {
        self.ensure_reliable()?;
        if self
            .paths
            .iter()
            .flatten()
            .any(|path| path.carrier_tuple == Some(tuple))
        {
            return Err(PathError::CarrierTupleBusy);
        }
        let path = self.path_mut(id)?;
        if path.carrier_tuple.is_some() {
            return Err(PathError::CarrierTupleBound);
        }
        path.carrier_tuple = Some(tuple);
        Ok(())
    }

    /// Returns the tuple assigned to a path, if the carrier has been initialized.
    #[must_use]
    pub fn carrier_tuple(&self, id: PathId) -> Option<FourTuple> {
        self.paths
            .iter()
            .flatten()
            .find(|path| path.id == id)
            .and_then(|path| path.carrier_tuple)
    }

    /// Records successful transport validation.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown path, invalid transition, or unreliable event view.
    pub fn established(&mut self, id: PathId) -> Result<(), PathError> {
        self.ensure_reliable()?;
        let Some(position) = self.path_position(id) else {
            self.reliable = false;
            return Err(PathError::UnknownPath);
        };
        let Some(path) = self.paths[position].as_mut() else {
            self.reliable = false;
            return Err(PathError::UnknownPath);
        };
        match path.state {
            PathState::Established => Ok(()),
            PathState::Validating => {
                path.state = PathState::Established;
                self.refresh_activation();
                Ok(())
            }
            PathState::Lost => {
                self.reliable = false;
                Err(PathError::InvalidTransition)
            }
        }
    }

    /// Records the peer's path status.
    ///
    /// # Errors
    ///
    /// Returns an error and makes the connection unusable if the event is unknown or mismatched.
    pub fn remote_status(&mut self, id: PathId, status: PathStatus) -> Result<(), PathError> {
        self.ensure_reliable()?;
        let Some(position) = self.path_position(id) else {
            self.reliable = false;
            return Err(PathError::UnknownPath);
        };
        if status != PathRole::expected_status() {
            self.reliable = false;
            return Err(PathError::StatusMismatch);
        }
        let Some(path) = self.paths[position].as_mut() else {
            self.reliable = false;
            return Err(PathError::UnknownPath);
        };
        if path.state == PathState::Lost {
            self.reliable = false;
            return Err(PathError::InvalidTransition);
        }
        if path.remote_status == Some(status) {
            return Ok(());
        }
        path.remote_status = Some(status);
        self.refresh_activation();
        Ok(())
    }

    /// Marks an established path unusable while retaining its permit.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown path, invalid transition, or unreliable event view.
    pub fn lost(&mut self, id: PathId) -> Result<(), PathError> {
        self.ensure_reliable()?;
        let Some(position) = self.path_position(id) else {
            self.reliable = false;
            return Err(PathError::UnknownPath);
        };
        let Some(path) = self.paths[position].as_mut() else {
            self.reliable = false;
            return Err(PathError::UnknownPath);
        };
        if !matches!(path.state, PathState::Validating | PathState::Established) {
            self.reliable = false;
            return Err(PathError::InvalidTransition);
        }
        path.state = PathState::Lost;
        Ok(())
    }

    /// Releases a retained path and starts its role's replacement backoff.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown path or unreliable event view.
    pub fn discarded(&mut self, id: PathId, now_seconds: u64) -> Result<(), PathError> {
        self.ensure_reliable()?;
        let Some(position) = self.path_position(id) else {
            self.reliable = false;
            return Err(PathError::UnknownPath);
        };
        let Some(path) = self.paths[position].take() else {
            self.reliable = false;
            return Err(PathError::UnknownPath);
        };
        let role = path.role;
        self.path_count -= 1;
        let index = role.index();
        self.retry_at[index] = now_seconds.saturating_add(self.retry_delay[index]);
        self.retry_delay[index] = (self.retry_delay[index] * 2).min(MAX_BACKOFF_SECONDS);
        Ok(())
    }

    pub const fn event_lagged(&mut self) {
        self.reliable = false;
    }

    /// Applies one event from `noq`'s bounded path event stream.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or unknown event and marks the path view unreliable.
    pub fn apply_noq_event(
        &mut self,
        event: &PathEvent,
        now_seconds: u64,
    ) -> Result<(), PathError> {
        let result = match event {
            PathEvent::Established { id, .. } => self.established(*id),
            PathEvent::Abandoned { id, .. } => self.lost(*id),
            PathEvent::Discarded { id, .. } => self.discarded_event(*id, now_seconds),
            PathEvent::RemoteStatus { id, status, .. } => self.remote_status(*id, *status),
            PathEvent::ObservedAddr { .. } => Ok(()),
            _ => {
                self.reliable = false;
                Err(PathError::UnknownTransportEvent)
            }
        };
        if result.is_err() {
            self.reliable = false;
        }
        result
    }

    fn discarded_event(&mut self, id: PathId, now_seconds: u64) -> Result<(), PathError> {
        self.ensure_reliable()?;
        let Some(path) = self.paths.iter().flatten().find(|path| path.id == id) else {
            self.reliable = false;
            return Err(PathError::UnknownPath);
        };
        if path.state != PathState::Lost {
            self.reliable = false;
            return Err(PathError::InvalidTransition);
        }
        self.discarded(id, now_seconds)
    }

    #[must_use]
    pub fn retained_paths(&self) -> usize {
        self.path_count
    }

    #[must_use]
    pub fn health(&self) -> PathHealth {
        if !self.reliable {
            return PathHealth::Failed;
        }
        if !self.activated {
            return PathHealth::NotReady;
        }
        match self
            .paths
            .iter()
            .flatten()
            .filter(|path| path.usable())
            .count()
        {
            count if count == usize::from(self.mode.path_limit()) => PathHealth::Ready,
            0 => PathHealth::Failed,
            _ => PathHealth::Degraded,
        }
    }

    fn ensure_reliable(&self) -> Result<(), PathError> {
        if self.reliable {
            Ok(())
        } else {
            Err(PathError::Unreliable)
        }
    }

    fn path_mut(&mut self, id: PathId) -> Result<&mut Path, PathError> {
        let Some(position) = self.path_position(id) else {
            self.reliable = false;
            return Err(PathError::UnknownPath);
        };
        let Some(path) = self.paths[position].as_mut() else {
            self.reliable = false;
            return Err(PathError::UnknownPath);
        };
        Ok(path)
    }

    fn path_position(&self, id: PathId) -> Option<usize> {
        self.paths
            .iter()
            .position(|path| path.is_some_and(|path| path.id == id))
    }

    fn refresh_activation(&mut self) {
        self.activated = self.activated
            || self
                .paths
                .iter()
                .flatten()
                .filter(|path| path.usable())
                .count()
                == usize::from(self.mode.path_limit());
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PathError {
    #[error("role is disabled in single-path mode")]
    RoleDisabled,
    #[error("role already retains a path")]
    RoleBusy,
    #[error("another path validation is in flight")]
    ValidationInFlight,
    #[error("concurrent path limit reached")]
    PathLimit,
    #[error("path ID was already used")]
    ReusedPathId,
    #[error("connection path ID lifetime cap reached")]
    LifetimeCap,
    #[error("path replacement is delayed until {retry_at}")]
    Backoff { retry_at: u64 },
    #[error("unknown path event")]
    UnknownPath,
    #[error("invalid path state transition")]
    InvalidTransition,
    #[error("peer path status does not match the configured role")]
    StatusMismatch,
    #[error("path event view is unreliable")]
    Unreliable,
    #[error("unknown transport path event")]
    UnknownTransportEvent,
    #[error("path already has a FakeTCP tuple")]
    CarrierTupleBound,
    #[error("FakeTCP tuple is already assigned to another path")]
    CarrierTupleBusy,
}

/// Builds the bounded transport profile used by the current QUIC-compatible backend.
#[must_use]
pub fn backend_transport_config(mode: MultipathMode) -> TransportConfig {
    backend_transport_config_with_congestion(mode, CongestionControl::default())
}

/// Builds the bounded transport profile with an explicit congestion controller.
#[must_use]
pub fn backend_transport_config_with_congestion(
    mode: MultipathMode,
    congestion_control: CongestionControl,
) -> TransportConfig {
    let policy = QuicpTransportConfig::default().with_congestion_control(congestion_control);
    backend_transport_config_with_options(mode, &policy, None, None)
}

/// Builds a bounded transport profile with either a built-in or Rust custom controller.
pub(crate) fn backend_transport_config_with_options(
    mode: MultipathMode,
    transport_policy: &QuicpTransportConfig,
    custom_congestion: Option<Arc<dyn CongestionControllerFactory>>,
    payload_ceiling: Option<u16>,
) -> TransportConfig {
    let mut config = TransportConfig::default();
    if let Some(factory) = custom_congestion {
        config.congestion_controller_factory(Arc::new(BackendFactory::new(factory)));
    } else {
        match transport_policy.congestion_control {
            CongestionControl::Cubic => {
                config.congestion_controller_factory(Arc::new(
                    noq::congestion::CubicConfig::default(),
                ));
            }
            CongestionControl::NewReno => {
                config.congestion_controller_factory(Arc::new(
                    noq::congestion::NewRenoConfig::default(),
                ));
            }
            CongestionControl::Bbr3 => {
                config.congestion_controller_factory(Arc::new(
                    noq::congestion::Bbr3Config::default(),
                ));
            }
        }
    }
    let mut ack_frequency = AckFrequencyConfig::default();
    ack_frequency
        .ack_eliciting_threshold(transport_policy.ack_eliciting_threshold.into())
        .max_ack_delay(Some(transport_policy.max_ack_delay));
    let mut mtu_discovery = MtuDiscoveryConfig::default();
    let upper_bound = [
        payload_ceiling,
        transport_policy.mtu.max_quic_payload,
        transport_policy.mtu.pmtu_upper_bound,
    ]
    .into_iter()
    .flatten()
    .min()
    .unwrap_or(crate::config::MAX_QUIC_PAYLOAD);
    mtu_discovery
        .interval(transport_policy.mtu.pmtu_interval)
        .upper_bound(upper_bound)
        .black_hole_cooldown(transport_policy.mtu.pmtu_black_hole_cooldown)
        .minimum_change(transport_policy.mtu.pmtu_minimum_change);
    config
        .initial_mtu(transport_policy.mtu.initial_quic_payload)
        .min_mtu(transport_policy.mtu.min_quic_payload)
        .mtu_discovery_config(
            (transport_policy.mtu.pmtu != PmtuMode::Disabled).then_some(mtu_discovery),
        )
        .max_idle_timeout(Some(
            IdleTimeout::try_from(transport_policy.idle_timeout)
                .expect("validated QUICP idle timeout fits QUIC varint"),
        ))
        .default_path_keep_alive_interval(Some(transport_policy.keep_alive_interval))
        .default_path_max_idle_timeout(Some(transport_policy.path_idle_timeout))
        .send_window(transport_policy.connection_send_window)
        .receive_window(
            VarInt::from_u64(transport_policy.connection_receive_window).unwrap_or(VarInt::MAX),
        )
        .stream_receive_window(VarInt::from_u32(transport_policy.stream_receive_window))
        .max_concurrent_bidi_streams(VarInt::from_u32(
            transport_policy.max_concurrent_bidi_streams,
        ))
        .max_concurrent_uni_streams(VarInt::from_u32(
            transport_policy.max_concurrent_uni_streams,
        ))
        .datagram_receive_buffer_size(None)
        .datagram_send_buffer_size(0)
        .ack_frequency_config(Some(ack_frequency))
        .enable_segmentation_offload(true);
    if mode.path_limit() > 1 {
        config.max_concurrent_multipath_paths(u32::from(mode.path_limit()));
    }
    config
}

#[derive(Clone, Copy, Debug)]
pub struct ChurnBucket {
    tokens: u8,
    last_refill: u64,
}

impl ChurnBucket {
    #[must_use]
    pub const fn new(now_seconds: u64) -> Self {
        Self {
            tokens: CHURN_BURST,
            last_refill: now_seconds,
        }
    }

    pub fn try_consume(&mut self, now_seconds: u64) -> bool {
        let Some(elapsed) = now_seconds.checked_sub(self.last_refill) else {
            return false;
        };
        let refills = elapsed / CHURN_REFILL_SECONDS;
        if refills != 0 {
            self.tokens = self
                .tokens
                .saturating_add(u8::try_from(refills).unwrap_or(CHURN_BURST))
                .min(CHURN_BURST);
            self.last_refill = self
                .last_refill
                .saturating_add(refills * CHURN_REFILL_SECONDS);
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChurnBucket, PathError, PathHealth, PathManager, PathRole, backend_transport_config,
        backend_transport_config_with_congestion,
    };
    use crate::config::{CongestionControl, MultipathMode};
    use noq::{PathId, PathStatus};
    use std::net::{Ipv4Addr, SocketAddr};

    fn id(value: u8) -> PathId {
        PathId::ZERO.saturating_add(value)
    }

    fn ready_failover() -> PathManager {
        let mut manager = PathManager::new(MultipathMode::Failover);
        manager.begin_path(PathRole::Primary, id(0), 0).unwrap();
        manager.established(id(0)).unwrap();
        manager.remote_status(id(0), PathStatus::Available).unwrap();
        manager.begin_path(PathRole::Backup, id(1), 0).unwrap();
        manager.established(id(1)).unwrap();
        manager.remote_status(id(1), PathStatus::Available).unwrap();
        manager
    }

    #[test]
    fn failover_activation_requires_both_paths_and_statuses() {
        let mut manager = PathManager::new(MultipathMode::Failover);
        assert_eq!(manager.health(), PathHealth::NotReady);

        manager.begin_path(PathRole::Primary, id(0), 0).unwrap();
        manager.established(id(0)).unwrap();
        manager.remote_status(id(0), PathStatus::Available).unwrap();
        assert_eq!(manager.health(), PathHealth::NotReady);

        manager.begin_path(PathRole::Backup, id(1), 0).unwrap();
        manager.established(id(1)).unwrap();
        assert_eq!(manager.health(), PathHealth::NotReady);
        manager.remote_status(id(1), PathStatus::Available).unwrap();
        assert_eq!(manager.health(), PathHealth::Ready);
    }

    #[test]
    fn replacement_waits_for_discard_and_backoff() {
        let mut manager = ready_failover();
        manager.lost(id(0)).unwrap();
        assert_eq!(manager.health(), PathHealth::Degraded);
        assert_eq!(manager.retained_paths(), 2);
        assert!(matches!(
            manager.begin_path(PathRole::Primary, id(2), 10),
            Err(PathError::RoleBusy)
        ));

        manager.discarded(id(0), 10).unwrap();
        assert_eq!(manager.retained_paths(), 1);
        assert_eq!(
            manager.begin_path(PathRole::Primary, id(2), 14),
            Err(PathError::Backoff { retry_at: 15 })
        );
        manager.begin_path(PathRole::Primary, id(2), 15).unwrap();
        manager.established(id(2)).unwrap();
        manager.remote_status(id(2), PathStatus::Available).unwrap();
        assert_eq!(manager.health(), PathHealth::Ready);
    }

    #[test]
    fn validation_ids_and_candidate_count_are_bounded() {
        let mut manager = PathManager::new(MultipathMode::Failover);
        manager.begin_path(PathRole::Primary, id(0), 0).unwrap();
        assert_eq!(
            manager.begin_path(PathRole::Backup, id(1), 0),
            Err(PathError::ValidationInFlight)
        );
        manager.discarded(id(0), 0).unwrap();
        assert_eq!(
            manager.begin_path(PathRole::Primary, id(0), 5),
            Err(PathError::ReusedPathId)
        );

        let mut now = 5;
        for path_id in 1..8 {
            manager
                .begin_path(PathRole::Primary, id(path_id), now)
                .unwrap();
            manager.discarded(id(path_id), now).unwrap();
            now += 60;
        }
        assert_eq!(
            manager.begin_path(PathRole::Primary, id(8), now),
            Err(PathError::LifetimeCap)
        );

        let mut off = PathManager::new(MultipathMode::Off);
        assert_eq!(
            off.begin_path(PathRole::Backup, id(0), 0),
            Err(PathError::RoleDisabled)
        );
    }

    #[test]
    fn unreliable_events_fail_closed() {
        let mut mismatch = PathManager::new(MultipathMode::Failover);
        mismatch.begin_path(PathRole::Backup, id(1), 0).unwrap();
        mismatch.established(id(1)).unwrap();
        assert_eq!(
            mismatch.remote_status(id(1), PathStatus::Backup),
            Err(PathError::StatusMismatch)
        );
        assert_eq!(mismatch.health(), PathHealth::Failed);

        let mut lagged = ready_failover();
        lagged.event_lagged();
        assert_eq!(lagged.health(), PathHealth::Failed);
        assert_eq!(lagged.established(id(99)), Err(PathError::Unreliable));
    }

    #[test]
    fn late_and_repeated_events_fail_closed() {
        let mut late = PathManager::new(MultipathMode::Failover);
        late.begin_path(PathRole::Backup, id(1), 0).unwrap();
        late.lost(id(1)).unwrap();
        assert_eq!(late.established(id(1)), Err(PathError::InvalidTransition));
        assert_eq!(late.health(), PathHealth::Failed);

        let mut repeated = ready_failover();
        repeated.lost(id(0)).unwrap();
        assert_eq!(repeated.lost(id(0)), Err(PathError::InvalidTransition));
        assert_eq!(repeated.health(), PathHealth::Failed);

        let mut stale_status = ready_failover();
        stale_status.lost(id(0)).unwrap();
        assert_eq!(
            stale_status.remote_status(id(0), PathStatus::Available),
            Err(PathError::InvalidTransition)
        );
        assert_eq!(stale_status.health(), PathHealth::Failed);

        let mut out_of_order_discard = ready_failover();
        assert_eq!(
            out_of_order_discard.discarded_event(id(0), 0),
            Err(PathError::InvalidTransition)
        );
        assert_eq!(out_of_order_discard.health(), PathHealth::Failed);
    }

    #[test]
    fn validation_failure_can_abandon_before_established() {
        let mut manager = PathManager::new(MultipathMode::Failover);
        manager.begin_path(PathRole::Backup, id(1), 0).unwrap();
        manager.lost(id(1)).unwrap();
        assert_eq!(manager.health(), PathHealth::NotReady);
        assert_eq!(manager.retained_paths(), 1);
    }

    #[test]
    fn transport_profile_enables_only_two_path_failover() {
        let single = format!("{:?}", backend_transport_config(MultipathMode::Off));
        let failover = format!("{:?}", backend_transport_config(MultipathMode::Failover));

        assert!(single.contains("max_concurrent_multipath_paths: None"));
        assert!(failover.contains("max_concurrent_multipath_paths: Some(2)"));
        for profile in [&single, &failover] {
            assert!(profile.contains("max_concurrent_bidi_streams: 128"));
            assert!(profile.contains("max_concurrent_uni_streams: 0"));
            assert!(profile.contains("stream_receive_window: 131072"));
            assert!(profile.contains("ack_frequency_config: Some"));
            assert!(profile.contains("datagram_receive_buffer_size: None"));
            assert!(profile.contains("datagram_send_buffer_size: 0"));
            assert!(profile.contains("enable_segmentation_offload: true"));
        }
    }

    #[test]
    fn transport_profile_accepts_each_built_in_congestion_controller() {
        for algorithm in [
            CongestionControl::Cubic,
            CongestionControl::NewReno,
            CongestionControl::Bbr3,
        ] {
            let _ = backend_transport_config_with_congestion(MultipathMode::Off, algorithm);
        }
    }

    #[test]
    fn churn_bucket_refills_one_token_every_five_seconds() {
        let mut bucket = ChurnBucket::new(0);
        assert!(bucket.try_consume(0));
        assert!(bucket.try_consume(0));
        assert!(!bucket.try_consume(0));
        assert!(!bucket.try_consume(4));
        assert!(bucket.try_consume(5));
        assert!(bucket.try_consume(15));
        assert!(bucket.try_consume(15));
        assert!(!bucket.try_consume(15));
    }

    #[test]
    fn each_quicp_path_requires_a_distinct_faketcp_tuple() {
        let mut manager = PathManager::new(MultipathMode::Failover);
        let primary = crate::faketcp::FourTuple::new(
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 10), 40_000)),
            SocketAddr::from((Ipv4Addr::new(198, 51, 100, 20), 443)),
        );
        let backup = crate::faketcp::FourTuple::new(
            SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 40_001)),
            SocketAddr::from((Ipv4Addr::new(198, 51, 100, 20), 443)),
        );
        manager.begin_path(PathRole::Primary, id(0), 0).unwrap();
        manager.bind_carrier_tuple(id(0), primary).unwrap();
        assert_eq!(manager.carrier_tuple(id(0)), Some(primary));
        manager.discarded(id(0), 0).unwrap();
        manager.begin_path(PathRole::Primary, id(1), 5).unwrap();
        manager.bind_carrier_tuple(id(1), backup).unwrap();
        assert_eq!(manager.carrier_tuple(id(1)), Some(backup));
    }
}
