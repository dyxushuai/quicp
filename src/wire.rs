use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;

use thiserror::Error;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CanonicalHost(Arc<str>);

impl CanonicalHost {
    /// Validates a lowercase ASCII multi-label DNS wire name.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidHost`] when the name is not canonical.
    pub fn parse(host: &str) -> Result<Self, WireError> {
        if host.len() > 253
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
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenRequest {
    pub host: CanonicalHost,
    pub port: NonZeroU16,
}

impl OpenRequest {
    #[must_use]
    pub fn new(host: CanonicalHost, port: NonZeroU16) -> Self {
        Self { host, port }
    }

    /// Encodes the validated OPEN header.
    ///
    /// # Panics
    ///
    /// The private host invariant guarantees its length fits in `u8`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let host = self.host.as_str().as_bytes();
        let mut encoded = Vec::with_capacity(host.len() + 3);
        encoded.push(u8::try_from(host.len()).expect("canonical host length fits in u8"));
        encoded.extend_from_slice(host);
        encoded.extend_from_slice(&self.port.get().to_be_bytes());
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
        let host = std::str::from_utf8(&input[1..=usize::from(host_len)])
            .map_err(|_| WireError::InvalidHost)
            .and_then(CanonicalHost::parse)?;
        let port = u16::from_be_bytes([input[consumed - 2], input[consumed - 1]]);
        let port = NonZeroU16::new(port).ok_or(WireError::ZeroPort)?;

        Ok((Self::new(host, port), consumed))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OpenStatus {
    Ok = 0x00,
    GeneralFailure = 0x01,
    PolicyDenied = 0x02,
    ResolutionFailure = 0x03,
    ConnectionRefused = 0x04,
    ConnectionTimeout = 0x05,
    CapacityExhausted = 0x06,
}

impl OpenStatus {
    #[must_use]
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

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WireError {
    #[error("truncated frame")]
    Truncated,
    #[error("invalid host length")]
    InvalidHostLength,
    #[error("invalid canonical host")]
    InvalidHost,
    #[error("port must be nonzero")]
    ZeroPort,
    #[error("unknown OPEN status {0:#04x}")]
    UnknownStatus(u8),
}
