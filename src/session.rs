use thiserror::Error;

use crate::config::{MultipathMode, ZeroRttMode};
use crate::wire::{OpenRequest, OpenStatus, WireError};

pub const MAX_OPEN_HEADER: u16 = 256;

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

    /// Produces the only token that permits parsing an early OPEN header.
    ///
    /// # Errors
    ///
    /// Returns an error until peer authentication, current policy, profile token, and
    /// multipath state all agree.
    fn authenticate(
        self,
        evidence: &HandshakeEvidence,
    ) -> Result<AuthenticatedSession, SessionError> {
        if !evidence.peer_authenticated {
            return Err(SessionError::PeerUnauthenticated);
        }
        if !evidence.current_policy_authorized {
            return Err(SessionError::PolicyRejected);
        }
        self.validate(&evidence.selected_profile_token, evidence.multipath_enabled)?;
        Ok(AuthenticatedSession { profile: self })
    }

    /// Authenticates a fully established backend connection against the selected profile.
    ///
    /// The no-security profile admits an established handshake that carries a matching
    /// profile token. The TLS adapter also requires a nonempty peer certificate chain.
    ///
    /// # Errors
    ///
    /// Returns an error unless the negotiated profile token, multipath state, and current
    /// authorization policy all agree. TLS sessions also fail without a peer identity.
    pub fn authenticate_connection(
        self,
        connection: &noq::Connection,
        current_policy_authorized: bool,
    ) -> Result<AuthenticatedSession, SessionError> {
        let evidence = handshake_evidence(connection, current_policy_authorized)?;
        self.authenticate(&evidence)
    }

    /// Admits whichever profile the established handshake actually negotiated.
    ///
    /// # Errors
    ///
    /// Returns an error when handshake data is missing, the token is unknown, or the
    /// token does not match the negotiated multipath state.
    pub fn admit_negotiated(
        connection: &noq::Connection,
        current_policy_authorized: bool,
    ) -> Result<AuthenticatedSession, SessionError> {
        let evidence = handshake_evidence(connection, current_policy_authorized)?;
        let selected = [Self::SinglePath, Self::Multipath]
            .into_iter()
            .find(|profile| profile.profile_token() == evidence.selected_profile_token.as_slice())
            .ok_or(SessionError::UnsupportedProfileToken)?;
        selected.authenticate(&evidence)
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
    peer_authenticated: bool,
    current_policy_authorized: bool,
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
            peer_authenticated: true,
            current_policy_authorized,
        }),
        Err(handshake) => {
            tls_handshake_evidence(connection, handshake, current_policy_authorized)
        }
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
    let peer_authenticated = connection
        .peer_identity()
        .and_then(|identity| {
            identity
                .downcast::<Vec<noq::rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .is_some_and(|certificates| !certificates.is_empty());
    Ok(HandshakeEvidence {
        selected_profile_token,
        multipath_enabled: connection.is_multipath_enabled(),
        peer_authenticated,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedSession {
    profile: ApplicationProfile,
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

impl AuthenticatedSession {
    #[must_use]
    pub const fn profile(self) -> ApplicationProfile {
        self.profile
    }

    /// Parses a buffered early OPEN only after authentication and rejects payload bytes.
    ///
    /// # Errors
    ///
    /// Returns a wire error for a malformed header or [`SessionError::EarlyPayload`]
    /// when bytes follow the header.
    pub fn decode_early_open(self, bytes: &[u8]) -> Result<OpenRequest, SessionError> {
        let (request, consumed) = OpenRequest::decode(bytes)?;
        if consumed != bytes.len() {
            return Err(SessionError::EarlyPayload);
        }
        Ok(request)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumptionMetadata {
    server_fingerprint: [u8; 32],
    expires_at_unix_seconds: u64,
    policy_epoch: u64,
    profile: ApplicationProfile,
    header_limit: u16,
}

pub const MAX_RESUMPTION_ENTRIES: usize = 256;

/// Bounded application-owned admission metadata for the optional security resumption cache.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResumptionCache {
    entries: Vec<ResumptionMetadata>,
}

impl ResumptionCache {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds metadata and evicts the oldest entry when the bounded cache is full.
    pub fn insert(&mut self, metadata: ResumptionMetadata) {
        if metadata.header_limit > MAX_OPEN_HEADER {
            return;
        }
        if let Some(index) = self.entries.iter().position(|entry| entry == &metadata) {
            self.entries.remove(index);
        }
        if self.entries.len() == MAX_RESUMPTION_ENTRIES {
            self.entries.remove(0);
        }
        self.entries.push(metadata);
    }

    /// Retains only metadata admitted by the current policy and reports whether any remains.
    pub fn admit(&mut self, current: &ResumptionPolicy) -> bool {
        self.entries.retain(|metadata| metadata.admits(current));
        !self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl ResumptionMetadata {
    #[must_use]
    pub const fn new(
        server_fingerprint: [u8; 32],
        expires_at_unix_seconds: u64,
        policy_epoch: u64,
        profile: ApplicationProfile,
        header_limit: u16,
    ) -> Self {
        Self {
            server_fingerprint,
            expires_at_unix_seconds,
            policy_epoch,
            profile,
            header_limit,
        }
    }

    #[must_use]
    pub fn admits(&self, current: &ResumptionPolicy) -> bool {
        current.mode == ZeroRttMode::SafeOpenOnly
            && current.now_unix_seconds < self.expires_at_unix_seconds
            && current.server_fingerprint == self.server_fingerprint
            && current.policy_epoch == self.policy_epoch
            && current.profile == self.profile
            && current.header_limit == self.header_limit
            && current.header_limit <= MAX_OPEN_HEADER
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumptionPolicy {
    pub mode: ZeroRttMode,
    pub server_fingerprint: [u8; 32],
    pub now_unix_seconds: u64,
    pub policy_epoch: u64,
    pub profile: ApplicationProfile,
    pub header_limit: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EarlyDataOutcome {
    Accepted,
    ExplicitlyRejected,
    AmbiguousOrFailed,
}

/// Resolves the temporary backend's ambiguous early-data result without replaying after failure.
pub async fn zero_rtt_outcome(
    connection: &noq::Connection,
    accepted: noq::ZeroRttAccepted,
) -> EarlyDataOutcome {
    classify_zero_rtt(accepted.await, connection.close_reason().is_none())
}

const fn classify_zero_rtt(accepted: bool, connection_alive: bool) -> EarlyDataOutcome {
    match (accepted, connection_alive) {
        (true, _) => EarlyDataOutcome::Accepted,
        (false, true) => EarlyDataOutcome::ExplicitlyRejected,
        (false, false) => EarlyDataOutcome::AmbiguousOrFailed,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EarlyDecision {
    Continue,
    RetryOnceAtOneRtt,
    Abort,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EarlyAttempt {
    fallback_used: bool,
    non_replayable: bool,
}

impl EarlyAttempt {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fallback_used: false,
            non_replayable: false,
        }
    }

    pub const fn mark_non_replayable(&mut self) {
        self.non_replayable = true;
    }

    pub fn resolve(&mut self, outcome: EarlyDataOutcome) -> EarlyDecision {
        match outcome {
            EarlyDataOutcome::Accepted => EarlyDecision::Continue,
            EarlyDataOutcome::ExplicitlyRejected if !self.fallback_used && !self.non_replayable => {
                self.fallback_used = true;
                EarlyDecision::RetryOnceAtOneRtt
            }
            EarlyDataOutcome::ExplicitlyRejected | EarlyDataOutcome::AmbiguousOrFailed => {
                EarlyDecision::Abort
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum ApplicationError {
    FlowProtocol = 0x100,
    FlowAbort = 0x101,
    FlowRejected = 0x102,
    MultipathRequired = 0x103,
    MultipathChurn = 0x104,
}

impl ApplicationError {
    #[must_use]
    pub const fn code(self) -> u64 {
        self as u64
    }

    #[must_use]
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
pub enum SessionError {
    #[error("peer authentication is incomplete")]
    PeerUnauthenticated,
    #[error("peer is not authorized by current policy")]
    PolicyRejected,
    #[error("unsupported QUICP profile token")]
    UnsupportedProfileToken,
    #[error("unsupported security backend session")]
    UnsupportedCrypto,
    #[error("TLS authentication requires the `tls-rustls` feature")]
    SecurityFeatureDisabled,
    #[error("profile token and multipath state do not match")]
    ProfileMismatch,
    #[error("0-RTT OPEN contains application payload")]
    EarlyPayload,
    #[error("invalid flow state transition")]
    InvalidState,
    #[error(transparent)]
    Wire(#[from] WireError),
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU16;

    use super::{
        ApplicationProfile, EarlyDataOutcome, HandshakeEvidence, SessionError, classify_zero_rtt,
    };
    use crate::wire::{CanonicalHost, OpenRequest};

    #[test]
    fn early_open_parsing_requires_authenticated_evidence() {
        let profile = ApplicationProfile::SinglePath;
        for evidence in [
            HandshakeEvidence {
                selected_profile_token: b"quicp/1".to_vec(),
                multipath_enabled: false,
                peer_authenticated: false,
                current_policy_authorized: true,
            },
            HandshakeEvidence {
                selected_profile_token: b"quicp/1".to_vec(),
                multipath_enabled: false,
                peer_authenticated: true,
                current_policy_authorized: false,
            },
        ] {
            assert!(profile.authenticate(&evidence).is_err());
        }

        let session = profile
            .authenticate(&HandshakeEvidence {
                selected_profile_token: b"quicp/1".to_vec(),
                multipath_enabled: false,
                peer_authenticated: true,
                current_policy_authorized: true,
            })
            .expect("authenticated session");
        let request = OpenRequest::new(
            CanonicalHost::parse("www.example.com").expect("host"),
            NonZeroU16::new(443).expect("port"),
        );
        let mut early = request.encode();
        early.push(b'x');
        assert_eq!(session.profile(), profile);
        assert!(matches!(
            session.decode_early_open(&early),
            Err(SessionError::EarlyPayload)
        ));
        assert_eq!(
            session
                .decode_early_open(&request.encode())
                .expect("header only"),
            request
        );
    }

    #[test]
    fn zero_rtt_rejection_requires_a_live_connection() {
        assert_eq!(
            classify_zero_rtt(false, true),
            EarlyDataOutcome::ExplicitlyRejected
        );
        assert_eq!(
            classify_zero_rtt(false, false),
            EarlyDataOutcome::AmbiguousOrFailed
        );
        assert_eq!(classify_zero_rtt(true, false), EarlyDataOutcome::Accepted);
    }
}
