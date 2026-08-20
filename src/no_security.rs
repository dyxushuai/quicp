//! Plaintext crypto adapter used by the QUICP baseline.
//!
//! This deliberately does not implement IETF QUIC security. It only supplies the backend seam
//! needed by the current `noq` stream engine, so the QUICP no-TLS profile can be measured without
//! TLS or packet AEAD. The TLS adapter remains available as an opt-in configuration.

use std::{any::Any, io::Cursor};

use bytes::BytesMut;
use noq_proto::{
    ConnectError, ConnectionId, PathId, Side, TransportError, TransportErrorCode,
    crypto::{
        ClientConfig, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey,
        ServerConfig, Session, UnsupportedVersion,
    },
    transport_parameters::TransportParameters,
};

const MAGIC: [u8; 4] = *b"QPCS";
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const CLIENT_CONFIRM: u8 = 3;
const MAX_PROFILE_TOKEN: usize = 32;

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

fn plain_keys() -> Keys {
    Keys {
        header: KeyPair {
            local: Box::new(PlainKey),
            remote: Box::new(PlainKey),
        },
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
}

impl NoSecuritySession {
    fn new(side: Side, profile_token: Vec<u8>, params: &TransportParameters) -> Self {
        Self {
            side,
            profile_token,
            params: *params,
            stage: Stage::New,
            peer_token: None,
            peer_params: None,
            input: Vec::new(),
        }
    }

    fn message(kind: u8, token: &[u8], params: &TransportParameters, output: &mut Vec<u8>) {
        let mut encoded_params = Vec::new();
        params.write(&mut encoded_params);
        output.extend_from_slice(&MAGIC);
        output.push(kind);
        output.push(u8::try_from(token.len()).expect("QUICP profile token is short"));
        output.extend_from_slice(
            &u16::try_from(encoded_params.len())
                .expect("QUICP transport parameters are short")
                .to_be_bytes(),
        );
        output.extend_from_slice(token);
        output.extend_from_slice(&encoded_params);
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
        let valid = token == b"quicp/1" || token == b"quicp/1-mp";
        if !valid || (self.side == Side::Client && token != self.profile_token) {
            return Err(Self::protocol_error("unsupported QUICP profile token"));
        }
        Ok(())
    }
}

impl Session for NoSecuritySession {
    fn initial_keys(&self, _dst_cid: ConnectionId, _side: Side) -> Keys {
        plain_keys()
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        (self.stage == Stage::Established).then(|| {
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
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        self.stage != Stage::Established
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.input.extend_from_slice(buf);
        let message = match (self.side, self.stage) {
            (Side::Client, Stage::HelloSent) => self.read_message(SERVER_HELLO)?,
            (Side::Server, Stage::New) => self.read_message(CLIENT_HELLO)?,
            (Side::Server, Stage::Established) => self.read_message(CLIENT_CONFIRM)?,
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
            }
            (Side::Server, Stage::Established) => {}
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
                Some(plain_keys())
            }
            (Side::Client, Stage::HelloSent) if self.peer_token.is_some() => {
                Self::message(CLIENT_CONFIRM, self.expected_token(), &self.params, buf);
                self.stage = Stage::Established;
                Some(plain_keys())
            }
            (Side::Server, Stage::New) if self.peer_token.is_some() => {
                self.stage = Stage::ServerKeysReady;
                Some(plain_keys())
            }
            (Side::Server, Stage::ServerKeysReady) => {
                Self::message(SERVER_HELLO, self.expected_token(), &self.params, buf);
                self.stage = Stage::Established;
                Some(plain_keys())
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
}

impl NoSecurityClientConfig {
    pub(crate) fn new(profile_token: &[u8]) -> Self {
        Self {
            profile_token: profile_token.to_vec(),
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
        )))
    }
}

#[derive(Default)]
pub(crate) struct NoSecurityServerConfig;

impl ServerConfig for NoSecurityServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        _dst_cid: ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        (version == 1).then(plain_keys).ok_or(UnsupportedVersion)
    }

    fn retry_tag(&self, _version: u32, _orig_dst_cid: ConnectionId, _packet: &[u8]) -> [u8; 16] {
        [0; 16]
    }

    fn start_session(&self, _version: u32, params: &TransportParameters) -> Box<dyn Session> {
        Box::new(NoSecuritySession::new(Side::Server, Vec::new(), params))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
