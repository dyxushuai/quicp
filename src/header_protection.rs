//! Optional QUICP packet-header protection for the no-TLS profile.
//!
//! This seam maps to the backend's QUIC-style header-protection operation. It does not encrypt
//! the outer IPv4/TCP headers, hide connection IDs, or authenticate the QUICP payload. Use the
//! TLS profile or a separate authenticated packet layer when confidentiality and integrity are
//! required.

use std::sync::Arc;

/// Which endpoint direction is creating a header-protection key pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderProtectionSide {
    /// The client/initiator side.
    Client,
    /// The server/acceptor side.
    Server,
}

/// A user-provided QUICP packet-header protector.
pub trait QuicpHeaderProtector: Send + Sync {
    /// Removes protection from the packet header in place.
    ///
    /// The slice contains the whole backend packet so an implementation can sample it; only
    /// header-protection bits may be changed.
    fn decrypt(&self, packet_number_offset: usize, packet: &mut [u8]);

    /// Applies protection to the packet header in place.
    ///
    /// The slice contains the whole backend packet so an implementation can sample it; only
    /// header-protection bits may be changed.
    fn encrypt(&self, packet_number_offset: usize, packet: &mut [u8]);

    /// Returns the sample bytes required by the protector.
    ///
    /// Zero disables the callback and therefore selects the default plaintext header. A
    /// nonzero value must leave enough bytes after `packet_number_offset + 4` for the backend to
    /// sample on every packet.
    fn sample_size(&self) -> usize;
}

/// The local and remote protectors used by one no-TLS endpoint.
#[derive(Clone)]
pub struct HeaderProtectionKeys {
    pub(crate) local: Arc<dyn QuicpHeaderProtector>,
    pub(crate) remote: Arc<dyn QuicpHeaderProtector>,
}

impl HeaderProtectionKeys {
    /// Creates a directional local/remote key pair.
    #[must_use]
    pub fn new(
        local: Arc<dyn QuicpHeaderProtector>,
        remote: Arc<dyn QuicpHeaderProtector>,
    ) -> Self {
        Self { local, remote }
    }
}

/// Builds header-protection keys for a no-TLS client or server endpoint.
pub trait HeaderProtectionFactory: Send + Sync {
    /// Builds stable directional keys for the selected endpoint side.
    ///
    /// A client/server pair must return matching directions: the client's local protector must
    /// behave like the server's remote protector, and vice versa.
    fn build(&self, side: HeaderProtectionSide) -> HeaderProtectionKeys;
}

pub(crate) struct BackendHeaderKey {
    inner: Arc<dyn QuicpHeaderProtector>,
}

impl BackendHeaderKey {
    pub(crate) fn new(inner: Arc<dyn QuicpHeaderProtector>) -> Self {
        Self { inner }
    }
}

impl noq_proto::crypto::HeaderKey for BackendHeaderKey {
    fn decrypt(&self, packet_number_offset: usize, packet: &mut [u8]) {
        self.inner.decrypt(packet_number_offset, packet);
    }

    fn encrypt(&self, packet_number_offset: usize, packet: &mut [u8]) {
        self.inner.encrypt(packet_number_offset, packet);
    }

    fn sample_size(&self) -> usize {
        self.inner.sample_size()
    }
}

#[cfg(test)]
mod tests {
    use super::{HeaderProtectionFactory, HeaderProtectionKeys, HeaderProtectionSide};
    use std::sync::Arc;

    #[derive(Debug)]
    struct PlainProbe;

    impl super::QuicpHeaderProtector for PlainProbe {
        fn decrypt(&self, _packet_number_offset: usize, _packet: &mut [u8]) {}

        fn encrypt(&self, _packet_number_offset: usize, _packet: &mut [u8]) {}

        fn sample_size(&self) -> usize {
            0
        }
    }

    #[derive(Debug)]
    struct ProbeFactory;

    impl HeaderProtectionFactory for ProbeFactory {
        fn build(&self, _side: HeaderProtectionSide) -> HeaderProtectionKeys {
            HeaderProtectionKeys::new(Arc::new(PlainProbe), Arc::new(PlainProbe))
        }
    }

    #[test]
    fn factory_builds_directional_keys_without_backend_types() {
        let keys = ProbeFactory.build(HeaderProtectionSide::Client);
        assert_eq!(keys.local.sample_size(), 0);
        assert_eq!(keys.remote.sample_size(), 0);
    }
}
