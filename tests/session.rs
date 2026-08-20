use quicp::config::{MultipathMode, ZeroRttMode};
use quicp::session::{
    ApplicationError, ApplicationProfile, ClientOpenGate, EarlyAttempt, EarlyDataOutcome,
    EarlyDecision, OpenDisposition, ResumptionCache, ResumptionMetadata, ResumptionPolicy,
    SessionError,
};
use quicp::wire::OpenStatus;

#[test]
fn profile_requires_exact_token_and_transport_state() {
    let single = ApplicationProfile::from(MultipathMode::Off);
    let multipath = ApplicationProfile::from(MultipathMode::Failover);

    assert_eq!(single.profile_token(), b"quicp/1");
    assert_eq!(multipath.profile_token(), b"quicp/1-mp");
    assert!(single.validate(b"quicp/1", false).is_ok());
    assert!(multipath.validate(b"quicp/1-mp", true).is_ok());
    assert!(matches!(
        single.validate(b"quicp/1", true),
        Err(SessionError::ProfileMismatch)
    ));
    assert!(matches!(
        multipath.validate(b"quicp/1-mp", false),
        Err(SessionError::ProfileMismatch)
    ));
    assert!(matches!(
        single.validate(b"quicp/2", false),
        Err(SessionError::UnsupportedProfileToken)
    ));
}

#[test]
fn resumption_metadata_must_match_current_identity_and_policy() {
    let metadata = ResumptionMetadata::new([7; 32], 1_000, 4, ApplicationProfile::Multipath, 256);
    let mut policy = ResumptionPolicy {
        mode: ZeroRttMode::SafeOpenOnly,
        server_fingerprint: [7; 32],
        now_unix_seconds: 999,
        policy_epoch: 4,
        profile: ApplicationProfile::Multipath,
        header_limit: 256,
    };

    assert!(metadata.admits(&policy));
    policy.mode = ZeroRttMode::Off;
    assert!(!metadata.admits(&policy));
    policy.mode = ZeroRttMode::SafeOpenOnly;
    policy.now_unix_seconds = 1_000;
    assert!(!metadata.admits(&policy));
    policy.now_unix_seconds = 999;
    policy.policy_epoch = 5;
    assert!(!metadata.admits(&policy));
    policy.policy_epoch = 4;
    policy.server_fingerprint = [8; 32];
    assert!(!metadata.admits(&policy));
    policy.server_fingerprint = [7; 32];
    policy.profile = ApplicationProfile::SinglePath;
    assert!(!metadata.admits(&policy));
    policy.profile = ApplicationProfile::Multipath;
    policy.header_limit = 257;
    assert!(!metadata.admits(&policy));
}

#[test]
fn resumption_cache_clears_stale_entries_before_admission() {
    let metadata = ResumptionMetadata::new([7; 32], 1_000, 4, ApplicationProfile::Multipath, 256);
    let mut cache = ResumptionCache::new();
    cache.insert(metadata);
    let policy = ResumptionPolicy {
        mode: ZeroRttMode::SafeOpenOnly,
        server_fingerprint: [8; 32],
        now_unix_seconds: 999,
        policy_epoch: 4,
        profile: ApplicationProfile::Multipath,
        header_limit: 256,
    };

    assert!(!cache.admit(&policy));
    assert_eq!(cache.len(), 0);
}

#[test]
fn rejected_early_data_retries_once_only_on_a_live_authenticated_connection() {
    let mut accepted = EarlyAttempt::new();
    assert_eq!(
        accepted.resolve(EarlyDataOutcome::Accepted),
        EarlyDecision::Continue
    );

    let mut attempt = EarlyAttempt::new();
    assert_eq!(
        attempt.resolve(EarlyDataOutcome::ExplicitlyRejected),
        EarlyDecision::RetryOnceAtOneRtt
    );
    assert_eq!(
        attempt.resolve(EarlyDataOutcome::ExplicitlyRejected),
        EarlyDecision::Abort
    );

    let mut failed = EarlyAttempt::new();
    assert_eq!(
        failed.resolve(EarlyDataOutcome::AmbiguousOrFailed),
        EarlyDecision::Abort
    );

    let mut ambiguous = EarlyAttempt::new();
    ambiguous.mark_non_replayable();
    assert_eq!(
        ambiguous.resolve(EarlyDataOutcome::ExplicitlyRejected),
        EarlyDecision::Abort
    );
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
fn local_payload_stays_blocked_until_open_ok() {
    let mut accepted = ClientOpenGate::new();
    assert!(!accepted.may_forward_payload());
    assert_eq!(
        accepted.accept_status(OpenStatus::Ok.encode()),
        Ok(OpenDisposition::Ready)
    );
    assert!(accepted.may_forward_payload());
    assert!(matches!(
        accepted.accept_status(OpenStatus::Ok.encode()),
        Err(SessionError::InvalidState)
    ));

    let mut rejected = ClientOpenGate::new();
    assert_eq!(
        rejected.accept_status(OpenStatus::PolicyDenied.encode()),
        Ok(OpenDisposition::Rejected(OpenStatus::PolicyDenied))
    );
    assert!(!rejected.may_forward_payload());

    let mut malformed = ClientOpenGate::new();
    assert!(malformed.accept_status(0xff).is_err());
    assert!(!malformed.may_forward_payload());
    assert!(matches!(
        malformed.accept_status(OpenStatus::Ok.encode()),
        Err(SessionError::InvalidState)
    ));
}
