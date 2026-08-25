use thiserror::Error;

use crate::config::MultipathMode;
use crate::wire::{OpenStatus, WireError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationProfile {
    SinglePath,
    Multipath,
}

impl ApplicationProfile {
    #[must_use]
    pub const fn profile_token(self) -> &'static [u8] {
        match self {
            Self::SinglePath => b"quicp/1",
            Self::Multipath => b"quicp/1-mp",
        }
    }

    /// Validates the negotiated profile token and transport state as one profile.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown profile token or any token/multipath mismatch.
    pub fn validate(
        self,
        selected_profile_token: &[u8],
        multipath_enabled: bool,
    ) -> Result<(), SessionError> {
        let selected = [Self::SinglePath, Self::Multipath]
            .into_iter()
            .find(|profile| profile.profile_token() == selected_profile_token)
            .ok_or(SessionError::UnsupportedProfileToken)?;
        if selected != self || multipath_enabled != matches!(self, Self::Multipath) {
            return Err(SessionError::ProfileMismatch);
        }
        Ok(())
    }

    /// Validates profile and policy evidence.
    ///
    /// # Errors
    ///
    /// Returns an error until peer admission, current policy, profile token, and multipath state
    /// all agree.
    fn admit_evidence(self, evidence: &HandshakeEvidence) -> Result<(), SessionError> {
        if evidence.peer_admission == PeerAdmission::Unauthenticated {
            return Err(SessionError::PeerUnauthenticated);
        }
        if !evidence.current_policy_authorized {
            return Err(SessionError::PolicyRejected);
        }
        self.validate(&evidence.selected_profile_token, evidence.multipath_enabled)?;
        Ok(())
    }

    /// Admits a fully established backend connection against the selected profile.
    ///
    /// The no-security profile admits an established handshake that carries a matching
    /// profile token. The TLS adapter also requires a nonempty peer certificate chain.
    ///
    /// # Errors
    ///
    /// Returns an error unless the negotiated profile token, multipath state, and current
    /// authorization policy all agree. TLS sessions also fail without a peer identity.
    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn admit_connection(
        self,
        connection: &noq::Connection,
        current_policy_authorized: bool,
    ) -> Result<(), SessionError> {
        let evidence = handshake_evidence(connection, current_policy_authorized)?;
        self.admit_evidence(&evidence)
    }

    /// Admits whichever profile the established handshake actually negotiated.
    ///
    /// # Errors
    ///
    /// Returns an error when handshake data is missing, the token is unknown, or the
    /// token does not match the negotiated multipath state.
    pub(crate) fn admit_negotiated(
        connection: &noq::Connection,
        current_policy_authorized: bool,
    ) -> Result<(), SessionError> {
        let evidence = handshake_evidence(connection, current_policy_authorized)?;
        let selected = [Self::SinglePath, Self::Multipath]
            .into_iter()
            .find(|profile| profile.profile_token() == evidence.selected_profile_token.as_slice())
            .ok_or(SessionError::UnsupportedProfileToken)?;
        selected.admit_evidence(&evidence)
    }
}

impl From<MultipathMode> for ApplicationProfile {
    fn from(mode: MultipathMode) -> Self {
        match mode {
            MultipathMode::Off => Self::SinglePath,
            MultipathMode::Failover => Self::Multipath,
        }
    }
}

#[derive(Clone, Debug)]
struct HandshakeEvidence {
    selected_profile_token: Vec<u8>,
    multipath_enabled: bool,
    peer_admission: PeerAdmission,
    current_policy_authorized: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerAdmission {
    #[cfg(feature = "tls-rustls")]
    Authenticated,
    ExplicitlyUnauthenticated,
    Unauthenticated,
}

fn handshake_evidence(
    connection: &noq::Connection,
    current_policy_authorized: bool,
) -> Result<HandshakeEvidence, SessionError> {
    let handshake = connection
        .handshake_data()
        .ok_or(SessionError::PeerUnauthenticated)?;
    match handshake.downcast::<crate::no_security::NoSecurityHandshakeData>() {
        Ok(plain) => Ok(HandshakeEvidence {
            selected_profile_token: plain.profile_token,
            multipath_enabled: connection.is_multipath_enabled(),
            peer_admission: PeerAdmission::ExplicitlyUnauthenticated,
            current_policy_authorized,
        }),
        Err(handshake) => tls_handshake_evidence(connection, handshake, current_policy_authorized),
    }
}

#[cfg(feature = "tls-rustls")]
fn tls_handshake_evidence(
    connection: &noq::Connection,
    handshake: Box<dyn std::any::Any>,
    current_policy_authorized: bool,
) -> Result<HandshakeEvidence, SessionError> {
    let handshake = handshake
        .downcast::<noq::crypto::rustls::HandshakeData>()
        .map_err(|_| SessionError::UnsupportedCrypto)?;
    let selected_profile_token = handshake
        .protocol
        .ok_or(SessionError::UnsupportedProfileToken)?;
    let peer_admission = if connection
        .peer_identity()
        .and_then(|identity| {
            identity
                .downcast::<Vec<noq::rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .is_some_and(|certificates| !certificates.is_empty())
    {
        PeerAdmission::Authenticated
    } else {
        PeerAdmission::Unauthenticated
    };
    Ok(HandshakeEvidence {
        selected_profile_token,
        multipath_enabled: connection.is_multipath_enabled(),
        peer_admission,
        current_policy_authorized,
    })
}

#[cfg(not(feature = "tls-rustls"))]
fn tls_handshake_evidence(
    _connection: &noq::Connection,
    _handshake: Box<dyn std::any::Any>,
    _current_policy_authorized: bool,
) -> Result<HandshakeEvidence, SessionError> {
    Err(SessionError::UnsupportedCrypto)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientOpenGate {
    state: OpenState,
}

impl ClientOpenGate {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: OpenState::AwaitingStatus,
        }
    }

    #[must_use]
    pub const fn may_forward_payload(self) -> bool {
        matches!(self.state, OpenState::Ready)
    }

    /// Consumes the single server status byte for a flow.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown status or a second status transition.
    pub fn accept_status(&mut self, value: u8) -> Result<OpenDisposition, SessionError> {
        if self.state != OpenState::AwaitingStatus {
            return Err(SessionError::InvalidState);
        }
        let status = match OpenStatus::decode(value) {
            Ok(status) => status,
            Err(error) => {
                self.state = OpenState::Terminal;
                return Err(error.into());
            }
        };
        if status == OpenStatus::Ok {
            self.state = OpenState::Ready;
            Ok(OpenDisposition::Ready)
        } else {
            self.state = OpenState::Terminal;
            Ok(OpenDisposition::Rejected(status))
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum OpenState {
    #[default]
    AwaitingStatus,
    Ready,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenDisposition {
    Ready,
    Rejected(OpenStatus),
}

/// Stable QUICP application error codes sent when closing flows or connections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum ApplicationError {
    /// Malformed or unexpected flow protocol data.
    FlowProtocol = 0x100,
    /// A local application aborted a flow.
    FlowAbort = 0x101,
    /// The peer rejected a flow request.
    FlowRejected = 0x102,
    /// A required backup path was unavailable.
    MultipathRequired = 0x103,
    /// Path churn exceeded the bounded policy.
    MultipathChurn = 0x104,
}

impl ApplicationError {
    #[must_use]
    /// Returns the stable wire code.
    pub const fn code(self) -> u64 {
        self as u64
    }

    #[must_use]
    /// Maps a peer wire code, using [`Self::FlowProtocol`] for unknown values.
    pub const fn from_peer_code(code: u64) -> Self {
        match code {
            value if value == Self::FlowAbort.code() => Self::FlowAbort,
            value if value == Self::FlowRejected.code() => Self::FlowRejected,
            value if value == Self::MultipathRequired.code() => Self::MultipathRequired,
            value if value == Self::MultipathChurn.code() => Self::MultipathChurn,
            _ => Self::FlowProtocol,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
/// An error raised while validating session admission or profile state.
pub enum SessionError {
    /// The peer has not completed authentication.
    #[error("peer authentication is incomplete")]
    PeerUnauthenticated,
    /// The active admission policy rejected the peer.
    #[error("peer is not authorized by current policy")]
    PolicyRejected,
    /// The peer selected an unsupported QUICP profile token.
    #[error("unsupported QUICP profile token")]
    UnsupportedProfileToken,
    /// The selected security backend cannot provide the requested session.
    #[error("unsupported security backend session")]
    UnsupportedCrypto,
    /// TLS authentication was requested without enabling its crate feature.
    #[error("TLS authentication requires the `tls-rustls` feature")]
    SecurityFeatureDisabled,
    /// The negotiated profile token conflicts with the multipath state.
    #[error("profile token and multipath state do not match")]
    ProfileMismatch,
    /// A flow attempted an invalid session-state transition.
    #[error("invalid flow state transition")]
    InvalidState,
    /// Session wire encoding or decoding failed.
    #[error(transparent)]
    Wire(#[from] WireError),
}

#[cfg(test)]
mod tests {
    use super::{ApplicationProfile, HandshakeEvidence, PeerAdmission};

    #[test]
    fn session_admission_requires_profile_and_policy_evidence() {
        let profile = ApplicationProfile::SinglePath;
        for evidence in [
            HandshakeEvidence {
                selected_profile_token: b"quicp/1".to_vec(),
                multipath_enabled: false,
                peer_admission: PeerAdmission::Unauthenticated,
                current_policy_authorized: true,
            },
            HandshakeEvidence {
                selected_profile_token: b"quicp/1".to_vec(),
                multipath_enabled: false,
                peer_admission: PeerAdmission::ExplicitlyUnauthenticated,
                current_policy_authorized: false,
            },
        ] {
            assert!(profile.admit_evidence(&evidence).is_err());
        }

        profile
            .admit_evidence(&HandshakeEvidence {
                selected_profile_token: b"quicp/1".to_vec(),
                multipath_enabled: false,
                peer_admission: PeerAdmission::ExplicitlyUnauthenticated,
                current_policy_authorized: true,
            })
            .expect("explicit no-security admission");
    }
}
