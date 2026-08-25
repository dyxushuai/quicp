use std::num::NonZeroU16;

use quicp::{CanonicalHost, OpenRequest, OpenStatus, WireError};

#[test]
fn open_request_round_trips() {
    let request = OpenRequest::new(
        CanonicalHost::parse("www.example.com").expect("valid host"),
        NonZeroU16::new(443).expect("nonzero port"),
    );

    let encoded = request.encode();
    let mut caller_buffer = [0u8; 256];
    let caller_length = request
        .encode_into(&mut caller_buffer)
        .expect("caller buffer fits");
    let (decoded, consumed) = OpenRequest::decode(&encoded).expect("valid frame");

    assert_eq!(decoded, request);
    assert_eq!(consumed, encoded.len());
    assert_eq!(request.encoded_len(), encoded.len());
    assert_eq!(&caller_buffer[..caller_length], encoded);
    assert_eq!(
        request.encode_into(&mut [0; 1]),
        Err(WireError::OutputTooSmall {
            required: encoded.len(),
            available: 1,
        })
    );
    assert!(encoded.len() <= 256);
}

#[test]
fn canonical_host_rejects_non_wire_names() {
    for invalid in [
        "EXAMPLE.com",
        "example.com.",
        "localhost",
        "127.0.0.1",
        "-bad.example",
        "bad-.example",
        "bad_name.example",
        "bad..example",
    ] {
        assert!(
            CanonicalHost::parse(invalid).is_err(),
            "accepted invalid host {invalid}"
        );
    }
}

#[test]
fn decoder_rejects_truncated_and_invalid_headers() {
    assert_eq!(OpenRequest::decode(&[]), Err(WireError::Truncated));
    assert_eq!(OpenRequest::decode(&[0]), Err(WireError::InvalidHostLength));
    assert_eq!(OpenRequest::decode(&[3, b'a']), Err(WireError::Truncated));
    assert_eq!(
        OpenRequest::decode(&[3, b'a', b'.', b'b', 0, 0]),
        Err(WireError::ZeroPort)
    );
}

#[test]
fn open_decoder_is_closed_under_truncation_and_byte_mutation() {
    let request = OpenRequest::new(
        CanonicalHost::parse("fuzz.example.com").expect("valid host"),
        NonZeroU16::new(443).expect("nonzero port"),
    );
    let encoded = request.encode();

    for length in 0..encoded.len() {
        assert!(OpenRequest::decode(&encoded[..length]).is_err());
    }
    for index in 0..encoded.len() {
        for value in u8::MIN..=u8::MAX {
            let mut mutated = encoded.clone();
            mutated[index] = value;
            if let Ok((decoded, consumed)) = OpenRequest::decode(&mutated) {
                assert!(consumed <= mutated.len());
                assert_eq!(decoded.encode(), mutated[..consumed]);
            }
        }
    }
}

#[test]
fn status_decoder_is_closed_over_known_values() {
    for status in [
        OpenStatus::Ok,
        OpenStatus::GeneralFailure,
        OpenStatus::PolicyDenied,
        OpenStatus::ResolutionFailure,
        OpenStatus::ConnectionRefused,
        OpenStatus::ConnectionTimeout,
        OpenStatus::CapacityExhausted,
    ] {
        assert_eq!(OpenStatus::decode(status.encode()), Ok(status));
    }
    assert_eq!(
        OpenStatus::decode(0xff),
        Err(WireError::UnknownStatus(0xff))
    );

    for value in u8::MIN..=u8::MAX {
        match OpenStatus::decode(value) {
            Ok(status) => assert_eq!(status.encode(), value),
            Err(error) => assert_eq!(error, WireError::UnknownStatus(value)),
        }
    }
}
