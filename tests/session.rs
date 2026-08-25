#![cfg(feature = "internal-bench")]

use quicp::config::MultipathMode;
use quicp::session::{
    ApplicationError, ApplicationProfile, ClientOpenGate, OpenDisposition, SessionError,
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
