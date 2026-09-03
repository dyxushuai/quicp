//! No-TLS crypto adapter used by the QUICP baseline.
//!
//! This deliberately does not implement IETF QUIC payload security. It supplies the backend seam
//! needed by the current `noq` stream engine, with optional user-provided packet-header protection.
//! The TLS adapter remains available as an opt-in configuration.

use std::{
    any::Any,
    io::Cursor,
    sync::{Arc, Mutex, PoisonError},
};

use bytes::BytesMut;
use noq_proto::{
    ConnectError, ConnectionId, PathId, Side, TransportError, TransportErrorCode,
    crypto::{
        ClientConfig, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey,
        ServerConfig, Session, UnsupportedVersion,
    },
    transport_parameters::TransportParameters,
};

use crate::header_protection::{
    BackendHeaderKey, HeaderProtectionFactory, HeaderProtectionKeys, HeaderProtectionSide,
};

const MAGIC: [u8; 4] = *b"QPCS";
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const CLIENT_CONFIRM: u8 = 3;
const MAX_PROFILE_TOKEN: usize = 32;
const MAX_HANDSHAKE_MESSAGE: usize = 65_575;

#[derive(Clone, Copy, Debug, Default)]
struct PlainKey;

impl HeaderKey for PlainKey {
    fn decrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

    fn encrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

    fn sample_size(&self) -> usize {
        0
    }
}

impl PacketKey for PlainKey {
    fn encrypt(&self, _path_id: PathId, _packet: u64, _buf: &mut [u8], _header_len: usize) {}

    fn decrypt(
        &self,
        _path_id: PathId,
        _packet: u64,
        _header: &[u8],
        _payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        Ok(())
    }

    fn tag_len(&self) -> usize {
        0
    }

    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }

    fn integrity_limit(&self) -> u64 {
        u64::MAX
    }
}

fn keys(header_keys: Option<&HeaderProtectionKeys>) -> Keys {
    let header = header_keys.map_or_else(
        || KeyPair {
            local: Box::new(PlainKey) as Box<dyn HeaderKey>,
            remote: Box::new(PlainKey) as Box<dyn HeaderKey>,
        },
        |header_keys| KeyPair {
            local: Box::new(BackendHeaderKey::new(Arc::clone(&header_keys.local)))
                as Box<dyn HeaderKey>,
            remote: Box::new(BackendHeaderKey::new(Arc::clone(&header_keys.remote)))
                as Box<dyn HeaderKey>,
        },
    );
    Keys {
        header,
        packet: KeyPair {
            local: Box::new(PlainKey),
            remote: Box::new(PlainKey),
        },
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NoSecurityHandshakeData {
    pub(crate) profile_token: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    New,
    ServerKeysReady,
    AwaitingConfirm,
    HelloSent,
    Established,
}

pub(crate) struct NoSecuritySession {
    side: Side,
    profile_token: Vec<u8>,
    params: TransportParameters,
    stage: Stage,
    peer_token: Option<Vec<u8>>,
    peer_params: Option<TransportParameters>,
    input: Vec<u8>,
    header_keys: Option<Arc<HeaderProtectionKeys>>,
    remembered_params: Option<Arc<Mutex<Option<TransportParameters>>>>,
}

impl NoSecuritySession {
    fn new(
        side: Side,
        profile_token: Vec<u8>,
        params: &TransportParameters,
        header_keys: Option<Arc<HeaderProtectionKeys>>,
        remembered_params: Option<Arc<Mutex<Option<TransportParameters>>>>,
    ) -> Self {
        let peer_params = remembered_params
            .as_ref()
            .and_then(|remembered| *remembered.lock().unwrap_or_else(PoisonError::into_inner));
        Self {
            side,
            profile_token,
            params: *params,
            stage: Stage::New,
            peer_token: None,
            peer_params,
            input: Vec::new(),
            header_keys,
            remembered_params,
        }
    }

    fn message(kind: u8, token: &[u8], params: &TransportParameters, output: &mut Vec<u8>) {
        output.extend_from_slice(&MAGIC);
        output.push(kind);
        output.push(u8::try_from(token.len()).expect("QUICP profile token is short"));
        let params_len_offset = output.len();
        output.extend_from_slice(&[0, 0]);
        output.extend_from_slice(token);
        let params_start = output.len();
        params.write(output);
        let params_len = u16::try_from(output.len() - params_start)
            .expect("QUICP transport parameters are short");
        output[params_len_offset..params_len_offset + 2].copy_from_slice(&params_len.to_be_bytes());
    }

    fn protocol_error(reason: &'static str) -> TransportError {
        TransportError::new(TransportErrorCode::PROTOCOL_VIOLATION, reason.to_owned())
    }

    fn expected_token(&self) -> &[u8] {
        self.peer_token.as_deref().unwrap_or(&self.profile_token)
    }

    fn read_message(
        &mut self,
        expected_kind: u8,
    ) -> Result<Option<(Vec<u8>, TransportParameters)>, TransportError> {
        if self.input.len() < 8 {
            return Ok(None);
        }
        if self.input[..4] != MAGIC || self.input[4] != expected_kind {
            return Err(Self::protocol_error("invalid QUICP plaintext handshake"));
        }
        let token_len = usize::from(self.input[5]);
        if token_len == 0 || token_len > MAX_PROFILE_TOKEN {
            return Err(Self::protocol_error("invalid QUICP profile token length"));
        }
        let params_len = usize::from(u16::from_be_bytes([self.input[6], self.input[7]]));
        let message_len = 8 + token_len + params_len;
        if self.input.len() < message_len {
            return Ok(None);
        }
        if self.input.len() != message_len {
            return Err(Self::protocol_error(
                "unexpected QUICP plaintext handshake data",
            ));
        }
        let token_end = 8 + token_len;
        let token = self.input[8..token_end].to_vec();
        let mut params = Cursor::new(&self.input[token_end..message_len]);
        let params = TransportParameters::read(self.side, &mut params)
            .map_err(|_| Self::protocol_error("invalid QUICP transport parameters"))?;
        self.input.clear();
        Ok(Some((token, params)))
    }

    fn validate_peer_token(&self, token: &[u8]) -> Result<(), TransportError> {
        let valid = token == crate::wire::QUICP_PROFILE;
        if !valid || (self.side == Side::Client && token != self.profile_token) {
            return Err(Self::protocol_error("unsupported QUICP profile token"));
        }
        Ok(())
    }

    fn incoming_message_len(&self, buf: &[u8]) -> Result<Option<usize>, TransportError> {
        let total = self
            .input
            .len()
            .checked_add(buf.len())
            .ok_or_else(|| Self::protocol_error("QUICP plaintext handshake is too large"))?;
        if total > MAX_HANDSHAKE_MESSAGE {
            return Err(Self::protocol_error(
                "QUICP plaintext handshake is too large",
            ));
        }
        if total < 8 {
            return Ok(None);
        }

        let mut header = [0; 8];
        let retained = self.input.len().min(header.len());
        header[..retained].copy_from_slice(&self.input[..retained]);
        if retained < header.len() {
            let missing = header.len() - retained;
            header[retained..].copy_from_slice(&buf[..missing]);
        }
        let token_len = usize::from(header[5]);
        if token_len == 0 || token_len > MAX_PROFILE_TOKEN {
            return Err(Self::protocol_error("invalid QUICP profile token length"));
        }
        let params_len = usize::from(u16::from_be_bytes([header[6], header[7]]));
        Ok(Some(8 + token_len + params_len))
    }
}

impl Session for NoSecuritySession {
    fn initial_keys(&self, _dst_cid: ConnectionId, _side: Side) -> Keys {
        keys(self.header_keys.as_deref())
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        matches!(self.stage, Stage::AwaitingConfirm | Stage::Established).then(|| {
            Box::new(NoSecurityHandshakeData {
                profile_token: self
                    .peer_token
                    .clone()
                    .unwrap_or_else(|| self.profile_token.clone()),
            }) as Box<dyn Any>
        })
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        if self.side == Side::Client && self.peer_params.is_none() {
            return None;
        }
        let keys = keys(self.header_keys.as_deref());
        Some((keys.header.local, keys.packet.local))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        Some(true)
    }

    fn is_handshaking(&self) -> bool {
        self.stage != Stage::Established
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        if self
            .incoming_message_len(buf)?
            .is_some_and(|message_len| self.input.len() + buf.len() > message_len)
        {
            return Err(Self::protocol_error(
                "unexpected QUICP plaintext handshake data",
            ));
        }
        self.input.extend_from_slice(buf);
        let message = match (self.side, self.stage) {
            (Side::Client, Stage::HelloSent) => self.read_message(SERVER_HELLO)?,
            (Side::Server, Stage::New) => self.read_message(CLIENT_HELLO)?,
            (Side::Server, Stage::AwaitingConfirm) => self.read_message(CLIENT_CONFIRM)?,
            _ => {
                return Err(Self::protocol_error(
                    "unexpected QUICP plaintext handshake state",
                ));
            }
        };
        let Some((token, params)) = message else {
            return Ok(false);
        };
        self.validate_peer_token(&token)?;
        match (self.side, self.stage) {
            (Side::Client, Stage::HelloSent) | (Side::Server, Stage::New) => {
                self.peer_token = Some(token);
                self.peer_params = Some(params);
                if self.side == Side::Client
                    && let Some(remembered) = &self.remembered_params
                {
                    *remembered.lock().unwrap_or_else(PoisonError::into_inner) = Some(params);
                }
            }
            (Side::Server, Stage::AwaitingConfirm) => self.stage = Stage::Established,
            _ => unreachable!("validated plaintext handshake state"),
        }
        Ok(self.stage == Stage::Established)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        Ok(self.peer_params)
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        match (self.side, self.stage) {
            (Side::Client, Stage::New) => {
                Self::message(CLIENT_HELLO, &self.profile_token, &self.params, buf);
                self.stage = Stage::HelloSent;
                Some(keys(self.header_keys.as_deref()))
            }
            (Side::Client, Stage::HelloSent) if self.peer_token.is_some() => {
                Self::message(CLIENT_CONFIRM, self.expected_token(), &self.params, buf);
                self.stage = Stage::Established;
                Some(keys(self.header_keys.as_deref()))
            }
            (Side::Server, Stage::New) if self.peer_token.is_some() => {
                self.stage = Stage::ServerKeysReady;
                Some(keys(self.header_keys.as_deref()))
            }
            (Side::Server, Stage::ServerKeysReady) => {
                Self::message(SERVER_HELLO, self.expected_token(), &self.params, buf);
                self.stage = Stage::AwaitingConfirm;
                Some(keys(self.header_keys.as_deref()))
            }
            _ => None,
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        Some(KeyPair {
            local: Box::new(PlainKey),
            remote: Box::new(PlainKey),
        })
    }

    fn is_valid_retry(&self, _orig_dst_cid: ConnectionId, _header: &[u8], _payload: &[u8]) -> bool {
        true
    }

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        Err(ExportKeyingMaterialError)
    }
}

pub(crate) struct NoSecurityClientConfig {
    profile_token: Vec<u8>,
    header_keys: Option<Arc<HeaderProtectionKeys>>,
    remembered_params: Arc<Mutex<Option<TransportParameters>>>,
}

impl NoSecurityClientConfig {
    pub(crate) fn new(
        profile_token: &[u8],
        header_factory: Option<Arc<dyn HeaderProtectionFactory>>,
    ) -> Self {
        Self {
            profile_token: profile_token.to_vec(),
            header_keys: header_factory
                .map(|factory| Arc::new(factory.build(HeaderProtectionSide::Client))),
            remembered_params: Arc::new(Mutex::new(None)),
        }
    }
}

impl ClientConfig for NoSecurityClientConfig {
    fn start_session(
        &self,
        _version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        Ok(Box::new(NoSecuritySession::new(
            Side::Client,
            self.profile_token.clone(),
            params,
            self.header_keys.clone(),
            Some(Arc::clone(&self.remembered_params)),
        )))
    }
}

pub(crate) struct NoSecurityServerConfig {
    header_keys: Option<Arc<HeaderProtectionKeys>>,
}

impl NoSecurityServerConfig {
    pub(crate) fn new(header_factory: Option<Arc<dyn HeaderProtectionFactory>>) -> Self {
        Self {
            header_keys: header_factory
                .map(|factory| Arc::new(factory.build(HeaderProtectionSide::Server))),
        }
    }
}

impl ServerConfig for NoSecurityServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        _dst_cid: ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        (version == 1)
            .then(|| keys(self.header_keys.as_deref()))
            .ok_or(UnsupportedVersion)
    }

    fn retry_tag(&self, _version: u32, _orig_dst_cid: ConnectionId, _packet: &[u8]) -> [u8; 16] {
        [0; 16]
    }

    fn start_session(&self, _version: u32, params: &TransportParameters) -> Box<dyn Session> {
        Box::new(NoSecuritySession::new(
            Side::Server,
            Vec::new(),
            params,
            self.header_keys.clone(),
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct XorHeader;

    impl crate::QuicpHeaderProtector for XorHeader {
        fn decrypt(&self, packet_number_offset: usize, packet: &mut [u8]) {
            packet[packet_number_offset] ^= 0x80;
        }

        fn encrypt(&self, packet_number_offset: usize, packet: &mut [u8]) {
            packet[packet_number_offset] ^= 0x80;
        }

        fn sample_size(&self) -> usize {
            1
        }
    }

    #[test]
    fn plaintext_keys_leave_packet_bytes_unchanged() {
        let key = PlainKey;
        let mut bytes = b"payload".to_vec();
        PacketKey::encrypt(&key, PathId::ZERO, 0, &mut bytes, 0);
        assert_eq!(bytes, b"payload");
        let mut payload = BytesMut::from(&b"payload"[..]);
        PacketKey::decrypt(&key, PathId::ZERO, 0, &[], &mut payload).unwrap();
        assert_eq!(&payload[..], b"payload");
        assert_eq!(key.sample_size(), 0);
        assert_eq!(key.tag_len(), 0);
    }

    #[test]
    fn custom_header_protection_only_changes_the_backend_header() {
        let header_keys = HeaderProtectionKeys::new(Arc::new(XorHeader), Arc::new(XorHeader));
        let keys = keys(Some(&header_keys));
        let mut bytes = [0x01, 0x02, 0x03, 0x04, 0x05];
        keys.header.local.encrypt(0, &mut bytes);
        assert_eq!(bytes, [0x81, 0x02, 0x03, 0x04, 0x05]);
        keys.header.remote.decrypt(0, &mut bytes);
        assert_eq!(bytes, [0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(keys.packet.local.tag_len(), 0);
    }

    #[test]
    fn server_stays_handshaking_until_client_confirmation() {
        let params = TransportParameters::read(Side::Client, &mut Cursor::new(&[][..])).unwrap();
        let mut client = NoSecuritySession::new(
            Side::Client,
            crate::wire::QUICP_PROFILE.to_vec(),
            &params,
            None,
            None,
        );
        let mut server = NoSecuritySession::new(Side::Server, Vec::new(), &params, None, None);
        let mut client_hello = Vec::new();
        client.write_handshake(&mut client_hello).unwrap();
        assert!(!server.read_handshake(&client_hello).unwrap());

        assert!(server.write_handshake(&mut Vec::new()).is_some());
        let mut server_hello = Vec::new();
        server.write_handshake(&mut server_hello).unwrap();
        assert!(server.is_handshaking());
        assert!(server.handshake_data().is_some());

        assert!(!client.read_handshake(&server_hello).unwrap());
        let mut client_confirm = Vec::new();
        client.write_handshake(&mut client_confirm).unwrap();
        assert!(!client.is_handshaking());
        assert!(server.is_handshaking());
        assert!(server.read_handshake(&client_confirm).unwrap());
        assert!(!server.is_handshaking());
    }

    #[test]
    fn oversized_handshake_is_rejected_before_buffer_growth() {
        let params = TransportParameters::read(Side::Client, &mut Cursor::new(&[][..])).unwrap();
        let mut server = NoSecuritySession::new(Side::Server, Vec::new(), &params, None, None);
        assert!(
            server
                .read_handshake(&vec![0; MAX_HANDSHAKE_MESSAGE + 1])
                .is_err()
        );
        assert!(server.input.is_empty());

        let mut oversized = MAGIC.to_vec();
        oversized.extend_from_slice(&[CLIENT_HELLO, 1, 0, 0]);
        oversized.extend_from_slice(&[0; 64]);
        assert!(server.read_handshake(&oversized).is_err());
        assert!(server.input.is_empty());
    }
}
