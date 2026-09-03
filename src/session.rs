use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;

use crate::wire::{QUICP_PROFILE, WireError};

const REPLAY_TOKEN_VERSION: u8 = 1;
const REPLAY_TOKEN_BODY_BYTES: usize = 1 + 8 + 8 + 8 + 16;
const REPLAY_TOKEN_BYTES: usize = REPLAY_TOKEN_BODY_BYTES + 32;
const REPLAY_TOKEN_DOMAIN: &[u8] = b"quicp replay token\0";
const REPLAY_TOKEN_AUTH_BYTES: usize = REPLAY_TOKEN_DOMAIN.len() + REPLAY_TOKEN_BODY_BYTES;
const MAX_REPLAY_ATTEMPTS: usize = 65_536;

/// Server-issued admission token for one replay-safe early attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayToken([u8; REPLAY_TOKEN_BYTES]);

impl ReplayToken {
    #[cfg(feature = "ffi-c")]
    pub(crate) const BYTE_LEN: usize = REPLAY_TOKEN_BYTES;

    /// Imports one bounded token received from a trusted application store.
    ///
    /// # Errors
    ///
    /// Returns an error unless the token has the exact length and version.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ReplayTokenError> {
        let bytes: [u8; REPLAY_TOKEN_BYTES] =
            bytes.try_into().map_err(|_| ReplayTokenError::Malformed)?;
        if bytes[0] != REPLAY_TOKEN_VERSION {
            return Err(ReplayTokenError::Malformed);
        }
        Ok(Self(bytes))
    }

    /// Returns the stable opaque token bytes for persistence by the caller.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Process-local issuer and bounded replay cache for explicit replay-safe attempts.
#[derive(Debug)]
pub struct ReplayAdmission {
    key: hmac::Key,
    epoch: u64,
    max_attempts: usize,
    attempts: Mutex<HashMap<[u8; 24], u64>>,
}

impl ReplayAdmission {
    /// Creates replay protection from a dedicated server secret and epoch.
    ///
    /// # Errors
    ///
    /// Returns an error when the secret is shorter than 32 bytes or the cache capacity is outside
    /// `1..=65_536`.
    pub fn new(secret: &[u8], epoch: u64, max_attempts: usize) -> Result<Self, ReplayTokenError> {
        if secret.len() < 32 || !(1..=MAX_REPLAY_ATTEMPTS).contains(&max_attempts) {
            return Err(ReplayTokenError::InvalidPolicy);
        }
        Ok(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
            epoch,
            max_attempts,
            attempts: Mutex::new(HashMap::new()),
        })
    }

    /// Issues one expiring token bound to the current capability fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero/overflowing TTL or unavailable system randomness.
    pub fn issue(
        &self,
        now_seconds: u64,
        ttl_seconds: u64,
        capability_fingerprint: u64,
    ) -> Result<ReplayToken, ReplayTokenError> {
        let mut identity = [0; 16];
        SystemRandom::new()
            .fill(&mut identity)
            .map_err(|_| ReplayTokenError::Random)?;
        let expiry = now_seconds
            .checked_add(ttl_seconds)
            .filter(|_| ttl_seconds != 0)
            .ok_or(ReplayTokenError::InvalidPolicy)?;
        let mut bytes = [0; REPLAY_TOKEN_BYTES];
        bytes[0] = REPLAY_TOKEN_VERSION;
        bytes[1..9].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[9..17].copy_from_slice(&expiry.to_be_bytes());
        bytes[17..25].copy_from_slice(&capability_fingerprint.to_be_bytes());
        bytes[25..REPLAY_TOKEN_BODY_BYTES].copy_from_slice(&identity);
        let authenticated = replay_token_auth_data(&bytes[..REPLAY_TOKEN_BODY_BYTES])?;
        let tag = hmac::sign(&self.key, &authenticated);
        bytes[REPLAY_TOKEN_BODY_BYTES..].copy_from_slice(tag.as_ref());
        Ok(ReplayToken(bytes))
    }

    /// Validates and consumes one exact `(token identity, nonce)` attempt.
    ///
    /// # Errors
    ///
    /// Returns an error before cache mutation for malformed, expired, replayed, incompatible, or
    /// over-capacity attempts.
    pub fn admit(
        &self,
        token: &ReplayToken,
        nonce: u64,
        now_seconds: u64,
        capability_fingerprint: u64,
    ) -> Result<(), ReplayTokenError> {
        let body = token
            .0
            .get(..REPLAY_TOKEN_BODY_BYTES)
            .ok_or(ReplayTokenError::Malformed)?;
        let tag = token
            .0
            .get(REPLAY_TOKEN_BODY_BYTES..)
            .ok_or(ReplayTokenError::Malformed)?;
        let authenticated = replay_token_auth_data(body)?;
        hmac::verify(&self.key, &authenticated, tag).map_err(|_| ReplayTokenError::InvalidMac)?;
        let epoch = read_token_u64(body, 1)?;
        let expiry = read_token_u64(body, 9)?;
        let capabilities = read_token_u64(body, 17)?;
        if epoch != self.epoch {
            return Err(ReplayTokenError::WrongEpoch);
        }
        if expiry < now_seconds {
            return Err(ReplayTokenError::Expired);
        }
        if capabilities != capability_fingerprint {
            return Err(ReplayTokenError::CapabilitiesChanged);
        }
        let mut attempt = [0; 24];
        attempt[..16].copy_from_slice(&body[25..41]);
        attempt[16..].copy_from_slice(&nonce.to_be_bytes());
        let mut attempts = self.attempts.lock().unwrap_or_else(PoisonError::into_inner);
        if attempts
            .get(&attempt)
            .is_some_and(|expires| *expires >= now_seconds)
        {
            return Err(ReplayTokenError::Replayed);
        }
        if attempts.len() == self.max_attempts {
            attempts.retain(|_, expires| *expires >= now_seconds);
            if attempts.len() == self.max_attempts {
                return Err(ReplayTokenError::Capacity);
            }
        }
        attempts.insert(attempt, expiry);
        Ok(())
    }
}

fn replay_token_auth_data(body: &[u8]) -> Result<[u8; REPLAY_TOKEN_AUTH_BYTES], ReplayTokenError> {
    if body.len() != REPLAY_TOKEN_BODY_BYTES {
        return Err(ReplayTokenError::Malformed);
    }
    let mut authenticated = [0; REPLAY_TOKEN_AUTH_BYTES];
    authenticated[..REPLAY_TOKEN_DOMAIN.len()].copy_from_slice(REPLAY_TOKEN_DOMAIN);
    authenticated[REPLAY_TOKEN_DOMAIN.len()..].copy_from_slice(body);
    Ok(authenticated)
}

fn read_token_u64(body: &[u8], offset: usize) -> Result<u64, ReplayTokenError> {
    let bytes = body
        .get(offset..offset + 8)
        .ok_or(ReplayTokenError::Malformed)?;
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| ReplayTokenError::Malformed)?;
    Ok(u64::from_be_bytes(bytes))
}

/// Replay-safe early-admission token errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReplayTokenError {
    /// The connection has not negotiated the capabilities bound into a token.
    #[error("replay token requires negotiated capabilities")]
    CapabilitiesUnavailable,
    /// The token length, version, or layout is invalid.
    #[error("malformed replay token")]
    Malformed,
    /// The token authentication code is invalid.
    #[error("invalid replay token MAC")]
    InvalidMac,
    /// The token was issued by another server epoch.
    #[error("replay token server epoch changed")]
    WrongEpoch,
    /// The token is past its expiration time.
    #[error("replay token expired")]
    Expired,
    /// Remembered transport capabilities no longer match.
    #[error("replay token capabilities changed")]
    CapabilitiesChanged,
    /// This exact token and nonce pair was already admitted.
    #[error("replay-safe attempt was already admitted")]
    Replayed,
    /// The process-local attempt cache is full.
    #[error("replay-attempt cache is full")]
    Capacity,
    /// The replay policy has an invalid secret, TTL, or capacity.
    #[error("invalid replay policy")]
    InvalidPolicy,
    /// The operating system random source failed.
    #[error("replay token identity generation failed")]
    Random,
}

#[must_use]
pub(crate) const fn application_profile_token() -> &'static [u8] {
    QUICP_PROFILE
}

fn admit_evidence(evidence: &HandshakeEvidence) -> Result<(), SessionError> {
    if evidence.peer_admission == PeerAdmission::Unauthenticated {
        return Err(SessionError::PeerUnauthenticated);
    }
    if !evidence.current_policy_authorized {
        return Err(SessionError::PolicyRejected);
    }
    if evidence.selected_profile_token != QUICP_PROFILE {
        return Err(SessionError::UnsupportedProfileToken);
    }
    Ok(())
}

/// Admits an established backend connection using the QUICP application profile.
///
/// # Errors
///
/// Returns an error when handshake data is missing, the token is unknown, the peer is not
/// admitted, or the current policy rejects it.
pub(crate) fn admit_negotiated(
    connection: &noq::Connection,
    current_policy_authorized: bool,
) -> Result<(), SessionError> {
    let evidence = handshake_evidence(connection, current_policy_authorized)?;
    admit_evidence(&evidence)
}

#[derive(Clone, Debug)]
struct HandshakeEvidence {
    selected_profile_token: Vec<u8>,
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
    /// A flow attempted an invalid session-state transition.
    #[error("invalid flow state transition")]
    InvalidState,
    /// Session wire encoding or decoding failed.
    #[error(transparent)]
    Wire(#[from] WireError),
}

#[cfg(test)]
mod tests {
    use super::{
        ApplicationError, HandshakeEvidence, MAX_REPLAY_ATTEMPTS, PeerAdmission, ReplayAdmission,
        ReplayToken, ReplayTokenError, SessionError, admit_evidence, application_profile_token,
    };

    #[test]
    fn session_admission_requires_profile_and_policy_evidence() {
        for evidence in [
            HandshakeEvidence {
                selected_profile_token: b"quicp".to_vec(),
                peer_admission: PeerAdmission::Unauthenticated,
                current_policy_authorized: true,
            },
            HandshakeEvidence {
                selected_profile_token: b"quicp".to_vec(),
                peer_admission: PeerAdmission::ExplicitlyUnauthenticated,
                current_policy_authorized: false,
            },
        ] {
            assert!(admit_evidence(&evidence).is_err());
        }

        admit_evidence(&HandshakeEvidence {
            selected_profile_token: b"quicp".to_vec(),
            peer_admission: PeerAdmission::ExplicitlyUnauthenticated,
            current_policy_authorized: true,
        })
        .expect("explicit no-security admission");
    }

    #[test]
    fn profile_requires_exact_token() {
        assert_eq!(application_profile_token(), b"quicp");
        assert!(matches!(
            admit_evidence(&HandshakeEvidence {
                selected_profile_token: b"quicp-legacy".to_vec(),
                peer_admission: PeerAdmission::ExplicitlyUnauthenticated,
                current_policy_authorized: true,
            }),
            Err(SessionError::UnsupportedProfileToken)
        ));
    }

    #[test]
    fn application_error_mapping_fails_unknown_codes_to_protocol_error() {
        assert_eq!(
            ApplicationError::from_peer_code(0x101),
            ApplicationError::FlowAbort
        );
        assert_eq!(
            ApplicationError::from_peer_code(0xdead),
            ApplicationError::FlowProtocol
        );
    }

    #[test]
    fn replay_tokens_reject_replay_expiry_mac_epoch_and_capability_changes() {
        let admission = ReplayAdmission::new(&[7; 32], 4, 2).unwrap();
        let token = admission.issue(100, 10, 9).unwrap();
        admission.admit(&token, 11, 100, 9).unwrap();
        assert_eq!(
            admission.admit(&token, 11, 100, 9),
            Err(ReplayTokenError::Replayed)
        );
        assert_eq!(
            admission.admit(&token, 12, 111, 9),
            Err(ReplayTokenError::Expired)
        );
        assert_eq!(
            admission.admit(&token, 12, 100, 10),
            Err(ReplayTokenError::CapabilitiesChanged)
        );
        let other_epoch = ReplayAdmission::new(&[7; 32], 5, 2).unwrap();
        assert_eq!(
            other_epoch.admit(&token, 12, 100, 9),
            Err(ReplayTokenError::WrongEpoch)
        );
        let mut corrupted = token.as_bytes().to_vec();
        corrupted[10] ^= 1;
        let corrupted = ReplayToken::from_bytes(&corrupted).unwrap();
        assert_eq!(
            admission.admit(&corrupted, 12, 100, 9),
            Err(ReplayTokenError::InvalidMac)
        );
    }

    #[test]
    fn replay_cache_is_bounded_before_mutation() {
        let admission = ReplayAdmission::new(&[7; 32], 4, 1).unwrap();
        let first = admission.issue(100, 10, 9).unwrap();
        let second = admission.issue(100, 10, 9).unwrap();
        admission.admit(&first, 1, 100, 9).unwrap();
        assert_eq!(
            admission.admit(&second, 2, 100, 9),
            Err(ReplayTokenError::Capacity)
        );
    }

    #[test]
    fn replay_cache_rejects_excessive_capacity_without_allocating() {
        assert!(matches!(
            ReplayAdmission::new(&[7; 32], 4, MAX_REPLAY_ATTEMPTS + 1),
            Err(ReplayTokenError::InvalidPolicy)
        ));
    }
}
