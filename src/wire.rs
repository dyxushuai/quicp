use alloc::{sync::Arc, vec, vec::Vec};
use core::{fmt, net::IpAddr, num::NonZeroU16, str};

use thiserror::Error;

const MAX_CANONICAL_HOST_BYTES: usize = 253;
pub(crate) const MAX_OPEN_FRAME_BYTES: usize = MAX_CANONICAL_HOST_BYTES + 3;

/// Validated lowercase ASCII DNS name used by the QUICP OPEN message.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CanonicalHost(Arc<str>);

impl CanonicalHost {
    /// Validates a lowercase ASCII multi-label DNS wire name.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidHost`] when the name is not canonical.
    pub fn parse(host: &str) -> Result<Self, WireError> {
        if host.len() > MAX_CANONICAL_HOST_BYTES
            || !host.contains('.')
            || host.parse::<IpAddr>().is_ok()
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(WireError::InvalidHost);
        }

        Ok(Self(host.into()))
    }

    #[must_use]
    /// Returns the canonical host text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Validated request to open a TCP-like flow to one host and port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenRequest {
    /// Canonical destination hostname.
    pub host: CanonicalHost,
    /// Nonzero destination port.
    pub port: NonZeroU16,
}

impl OpenRequest {
    #[must_use]
    /// Creates an OPEN request from already validated parts.
    pub fn new(host: CanonicalHost, port: NonZeroU16) -> Self {
        Self { host, port }
    }

    #[must_use]
    /// Returns the encoded OPEN frame length.
    pub fn encoded_len(&self) -> usize {
        self.host.as_str().len() + 3
    }

    /// Encodes the validated OPEN header into caller-owned storage.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::OutputTooSmall`] when the supplied storage cannot hold the frame.
    pub fn encode_into(&self, output: &mut [u8]) -> Result<usize, WireError> {
        let host = self.host.as_str().as_bytes();
        let required = self.encoded_len();
        if output.len() < required {
            return Err(WireError::OutputTooSmall {
                required,
                available: output.len(),
            });
        }
        output[0] = u8::try_from(host.len()).map_err(|_| WireError::InvalidHost)?;
        output[1..=host.len()].copy_from_slice(host);
        output[1 + host.len()..required].copy_from_slice(&self.port.get().to_be_bytes());
        Ok(required)
    }

    /// Encodes the validated OPEN header.
    ///
    /// # Panics
    ///
    /// The private host invariant guarantees its length fits in `u8`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = vec![0; self.encoded_len()];
        self.encode_into(&mut encoded)
            .expect("canonical OPEN request fits its encoded length");
        encoded
    }

    /// Decodes one OPEN header and reports the consumed byte count.
    ///
    /// # Errors
    ///
    /// Returns a wire error for truncated or invalid input.
    pub fn decode(input: &[u8]) -> Result<(Self, usize), WireError> {
        let Some(&host_len) = input.first() else {
            return Err(WireError::Truncated);
        };
        if host_len == 0 {
            return Err(WireError::InvalidHostLength);
        }

        let consumed = usize::from(host_len) + 3;
        if input.len() < consumed {
            return Err(WireError::Truncated);
        }
        let host = str::from_utf8(&input[1..=usize::from(host_len)])
            .map_err(|_| WireError::InvalidHost)
            .and_then(CanonicalHost::parse)?;
        let port = u16::from_be_bytes([input[consumed - 2], input[consumed - 1]]);
        let port = NonZeroU16::new(port).ok_or(WireError::ZeroPort)?;

        Ok((Self::new(host, port), consumed))
    }
}

/// Terminal status returned for one OPEN request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OpenStatus {
    /// The destination flow is ready.
    Ok = 0x00,
    /// The destination failed without a more specific status.
    GeneralFailure = 0x01,
    /// Current policy denied the destination.
    PolicyDenied = 0x02,
    /// Name resolution failed.
    ResolutionFailure = 0x03,
    /// The destination refused the connection.
    ConnectionRefused = 0x04,
    /// Connecting to the destination timed out.
    ConnectionTimeout = 0x05,
    /// A bounded flow or connection limit is exhausted.
    CapacityExhausted = 0x06,
}

impl OpenStatus {
    #[must_use]
    /// Encodes the status as its stable one-byte wire value.
    pub const fn encode(self) -> u8 {
        self as u8
    }

    /// Decodes a closed set of protocol status values.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::UnknownStatus`] for unassigned values.
    pub const fn decode(value: u8) -> Result<Self, WireError> {
        match value {
            0x00 => Ok(Self::Ok),
            0x01 => Ok(Self::GeneralFailure),
            0x02 => Ok(Self::PolicyDenied),
            0x03 => Ok(Self::ResolutionFailure),
            0x04 => Ok(Self::ConnectionRefused),
            0x05 => Ok(Self::ConnectionTimeout),
            0x06 => Ok(Self::CapacityExhausted),
            unknown => Err(WireError::UnknownStatus(unknown)),
        }
    }
}

/// OPEN request and status decoding errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WireError {
    /// The input ends before a complete field or frame.
    #[error("truncated frame")]
    Truncated,
    /// The encoded hostname length is zero.
    #[error("invalid host length")]
    InvalidHostLength,
    /// The hostname is not canonical lowercase ASCII DNS text.
    #[error("invalid canonical host")]
    InvalidHost,
    /// The encoded destination port is zero.
    #[error("port must be nonzero")]
    ZeroPort,
    /// The peer sent an unassigned status value.
    #[error("unknown OPEN status {0:#04x}")]
    UnknownStatus(u8),
    /// Caller-owned output storage cannot hold the encoded OPEN frame.
    #[error("OPEN output capacity {available} is smaller than required {required}")]
    OutputTooSmall {
        /// Required frame bytes.
        required: usize,
        /// Supplied output bytes.
        available: usize,
    },
}
