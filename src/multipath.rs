use std::sync::Arc;

use noq::{
    AckFrequencyConfig, IdleTimeout, MtuDiscoveryConfig, PathEvent, PathId, PathStatus,
    TransportConfig, VarInt,
};
use thiserror::Error;

use crate::config::{
    CongestionControl, MultipathMode, PmtuMode, QuicpTransportConfig, RecoveryMode,
};
use crate::congestion::{BackendFactory, CongestionControllerFactory};
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
    state: PathState,
    remote_status: Option<PathStatus>,
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
    activated: bool,
    reliable: bool,
}

impl PathManager {
    #[must_use]
    pub fn new(mode: MultipathMode) -> Self {
        Self {
            mode,
            paths: [None; 2],
            activated: false,
            reliable: true,
        }
    }

    /// Reserves a fresh path ID before transport validation starts.
    ///
    /// # Errors
    ///
    /// Returns an error if the role or path ID is invalid.
    pub fn begin_path(&mut self, role: PathRole, id: PathId) -> Result<(), PathError> {
        self.ensure_reliable()?;
        if self.mode == MultipathMode::Off && role == PathRole::Backup {
            return Err(PathError::RoleDisabled);
        }
        let index = role.index();
        if self.paths[index].is_some() {
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
        if self.paths.iter().flatten().any(|path| path.id == id) {
            return Err(PathError::ReusedPathId);
        }
        self.paths[index] = Some(Path {
            id,
            state: PathState::Validating,
            remote_status: None,
        });
        Ok(())
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

    pub const fn event_lagged(&mut self) {
        self.reliable = false;
    }

    /// Applies one event from `noq`'s bounded path event stream.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or unknown event and marks the path view unreliable.
    pub fn apply_noq_event(&mut self, event: &PathEvent) -> Result<(), PathError> {
        let result = match event {
            PathEvent::Established { id, .. } => self.established(*id),
            PathEvent::Abandoned { id, .. } => self.lost(*id),
            PathEvent::Discarded { id, .. } => self.discarded_event(*id),
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

    fn discarded_event(&mut self, id: PathId) -> Result<(), PathError> {
        self.ensure_reliable()?;
        let Some(position) = self.path_position(id) else {
            self.reliable = false;
            return Err(PathError::UnknownPath);
        };
        let path = self.paths[position].expect("path_position returns an occupied slot");
        if path.state != PathState::Lost {
            self.reliable = false;
            return Err(PathError::InvalidTransition);
        }
        self.paths[position] = None;
        Ok(())
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
    #[error("path ID is already active")]
    ReusedPathId,
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
}

/// Builds the bounded transport profile used by the current QUIC-compatible backend.
#[must_use]
#[cfg(test)]
pub fn backend_transport_config(mode: MultipathMode) -> TransportConfig {
    backend_transport_config_with_congestion(mode, CongestionControl::default())
}

/// Builds the bounded transport profile with an explicit congestion controller.
#[must_use]
#[cfg(test)]
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
        .datagram_receive_buffer_size(
            (transport_policy.recovery.mode == RecoveryMode::Adaptive)
                .then_some(transport_policy.recovery.reassembly_buffer_bytes as usize),
        )
        .datagram_send_buffer_size(
            if transport_policy.recovery.mode == RecoveryMode::Adaptive {
                transport_policy.recovery.replay_buffer_bytes as usize
            } else {
                0
            },
        )
        .ack_frequency_config(Some(ack_frequency))
        .enable_segmentation_offload(true);
    if mode.path_limit() > 1 {
        config.max_concurrent_multipath_paths(u32::from(mode.path_limit()));
    }
    config
}

#[cfg(test)]
mod tests {
    use super::{
        PathError, PathHealth, PathManager, PathRole, backend_transport_config,
        backend_transport_config_with_congestion,
    };
    use crate::config::{CongestionControl, MultipathMode};
    use noq::{PathId, PathStatus};

    fn id(value: u8) -> PathId {
        PathId::ZERO.saturating_add(value)
    }

    fn ready_failover() -> PathManager {
        let mut manager = PathManager::new(MultipathMode::Failover);
        manager.begin_path(PathRole::Primary, id(0)).unwrap();
        manager.established(id(0)).unwrap();
        manager.remote_status(id(0), PathStatus::Available).unwrap();
        manager.begin_path(PathRole::Backup, id(1)).unwrap();
        manager.established(id(1)).unwrap();
        manager.remote_status(id(1), PathStatus::Available).unwrap();
        manager
    }

    #[test]
    fn failover_activation_requires_both_paths_and_statuses() {
        let mut manager = PathManager::new(MultipathMode::Failover);
        assert_eq!(manager.health(), PathHealth::NotReady);

        manager.begin_path(PathRole::Primary, id(0)).unwrap();
        manager.established(id(0)).unwrap();
        manager.remote_status(id(0), PathStatus::Available).unwrap();
        assert_eq!(manager.health(), PathHealth::NotReady);

        manager.begin_path(PathRole::Backup, id(1)).unwrap();
        manager.established(id(1)).unwrap();
        assert_eq!(manager.health(), PathHealth::NotReady);
        manager.remote_status(id(1), PathStatus::Available).unwrap();
        assert_eq!(manager.health(), PathHealth::Ready);
    }

    #[test]
    fn initial_path_roles_and_ids_are_bounded() {
        let mut manager = PathManager::new(MultipathMode::Failover);
        manager.begin_path(PathRole::Primary, id(0)).unwrap();
        assert_eq!(
            manager.begin_path(PathRole::Backup, id(1)),
            Err(PathError::ValidationInFlight)
        );
        manager.established(id(0)).unwrap();
        manager.remote_status(id(0), PathStatus::Available).unwrap();
        assert_eq!(
            manager.begin_path(PathRole::Backup, id(0)),
            Err(PathError::ReusedPathId)
        );
        assert_eq!(
            manager.begin_path(PathRole::Primary, id(2)),
            Err(PathError::RoleBusy)
        );

        let mut off = PathManager::new(MultipathMode::Off);
        assert_eq!(
            off.begin_path(PathRole::Backup, id(0)),
            Err(PathError::RoleDisabled)
        );
    }

    #[test]
    fn unreliable_events_fail_closed() {
        let mut mismatch = PathManager::new(MultipathMode::Failover);
        mismatch.begin_path(PathRole::Backup, id(1)).unwrap();
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
        late.begin_path(PathRole::Backup, id(1)).unwrap();
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
            out_of_order_discard.discarded_event(id(0)),
            Err(PathError::InvalidTransition)
        );
        assert_eq!(out_of_order_discard.health(), PathHealth::Failed);
    }

    #[test]
    fn validation_failure_can_abandon_before_established() {
        let mut manager = PathManager::new(MultipathMode::Failover);
        manager.begin_path(PathRole::Backup, id(1)).unwrap();
        manager.lost(id(1)).unwrap();
        assert_eq!(manager.health(), PathHealth::NotReady);
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
            assert!(profile.contains("datagram_receive_buffer_size: Some(262144)"));
            assert!(profile.contains("datagram_send_buffer_size: 262144"));
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
}
