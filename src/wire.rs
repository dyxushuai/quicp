//! QUICP wire syntax and bounded decoding.
//!
//! This module validates canonical fields and frame lengths before exposing borrowed payloads.
//! Flow admission, recovery memory accounting, and state mutation belong to its callers.

use core::{fmt, net::IpAddr, num::NonZeroU16, str};
use std::{sync::Arc, vec, vec::Vec};

use thiserror::Error;

use crate::config::{MAX_DECODER_WINDOW, MAX_REPAIR_SPAN};

pub(crate) const QUICP_PROFILE: &[u8] = b"quicp";
pub(crate) const SOURCE_DATAGRAM: u8 = 0x20;
pub(crate) const REPAIR_DATAGRAM: u8 = 0x21;
// Type, repair ID, first symbol ID, span, symbol size, and coding seed.
pub(crate) const REPAIR_DATAGRAM_HEADER_BYTES: usize = 1 + 4 + 4 + 2 + 2 + 4;
// SOURCE header (type, symbol ID, count), then the largest single-record header
// (flow ID, offset, flags, length). Varints occupy at most eight bytes.
pub(crate) const SINGLE_SOURCE_MAX_OVERHEAD: usize = (1 + 4 + 1) + (8 + 8 + 1 + 8);
pub(crate) const MAX_SOURCE_RECORDS: usize = 32;

const FRAME_CAPABILITIES: u8 = 0x01;
const FRAME_OPEN: u8 = 0x02;
const FRAME_STATUS: u8 = 0x03;
const FRAME_ACK: u8 = 0x04;
const FRAME_MAX_OFFSET: u8 = 0x05;
const FRAME_FIN: u8 = 0x06;
const FRAME_STREAM_DATA: u8 = 0x08;
const FRAME_EARLY_OPEN: u8 = 0x09;
const CAPABILITY_DATAGRAM: u8 = 0x01;
const CAPABILITY_RLC: u8 = 0x02;
const CAPABILITY_REPLAY_SAFE: u8 = 0x08;
const CAPABILITY_MASK: u8 = CAPABILITY_DATAGRAM | CAPABILITY_RLC | CAPABILITY_REPLAY_SAFE;
pub(crate) const MAX_WIRE_OFFSET: u64 = (1 << 62) - 1;

pub(crate) const MAX_CANONICAL_HOST_BYTES: usize = 253;
pub(crate) const MAX_OPEN_FRAME_BYTES: usize = MAX_CANONICAL_HOST_BYTES + 3;
const _: () = assert!(MAX_CANONICAL_HOST_BYTES <= u8::MAX as usize);

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

    #[allow(clippy::cast_possible_truncation)]
    fn wire_len(&self) -> u8 {
        // Only parse() constructs this type; its limit is checked at compile time above.
        self.0.len() as u8
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
        output[0] = self.host.wire_len();
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

/// QUICP connection capabilities repeated during flow admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Capabilities {
    pub(crate) flags: u8,
    pub(crate) max_symbol: u16,
    pub(crate) max_span: u16,
    pub(crate) decoder_window: u16,
    pub(crate) max_ack_ranges: u8,
}

impl Capabilities {
    pub(crate) fn local(adaptive: bool) -> Self {
        let mut flags = CAPABILITY_REPLAY_SAFE;
        if adaptive {
            flags |= CAPABILITY_DATAGRAM | CAPABILITY_RLC;
        }
        Self {
            flags,
            max_symbol: 0,
            max_span: 0,
            decoder_window: 0,
            max_ack_ranges: 0,
        }
    }

    pub(crate) fn intersect(self, peer: Self) -> Self {
        Self {
            flags: self.flags & peer.flags,
            max_symbol: self.max_symbol.min(peer.max_symbol),
            max_span: self.max_span.min(peer.max_span),
            decoder_window: self.decoder_window.min(peer.decoder_window),
            max_ack_ranges: self.max_ack_ranges.min(peer.max_ack_ranges),
        }
    }

    pub(crate) fn supports_adaptive(self) -> bool {
        self.flags & (CAPABILITY_DATAGRAM | CAPABILITY_RLC) == CAPABILITY_DATAGRAM | CAPABILITY_RLC
    }
}

/// One decoded QUICP reliable control frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ControlFrame<'a> {
    Capabilities(Capabilities),
    Open(OpenRequest),
    Status(OpenStatus),
    Ack {
        contiguous: u64,
        ranges: Vec<core::ops::Range<u64>>,
    },
    MaxOffset(u64),
    Fin(u64),
    StreamData {
        offset: u64,
        fin: bool,
        data: &'a [u8],
    },
    EarlyOpen {
        token: &'a [u8],
        nonce: u64,
        request: OpenRequest,
        initial: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SourceRecord<'a> {
    pub(crate) flow_id: u64,
    pub(crate) offset: u64,
    pub(crate) fin: bool,
    pub(crate) data: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourceDatagram<'a> {
    pub(crate) symbol_id: u32,
    first_record: SourceRecord<'a>,
    remaining_records: &'a [u8],
    record_count: usize,
}

impl<'a> SourceDatagram<'a> {
    pub(crate) fn record_count(&self) -> usize {
        self.record_count
    }

    pub(crate) fn single_record(&self) -> Option<SourceRecord<'a>> {
        (self.record_count == 1).then_some(self.first_record)
    }

    /// Traverses the validated bytes without allocating record storage.
    pub(crate) fn records(
        &self,
    ) -> impl Iterator<Item = Result<SourceRecord<'a>, CodecError>> + '_ {
        let mut cursor = Cursor::new(self.remaining_records);
        std::iter::once(Ok(self.first_record))
            .chain((1..self.record_count).map(move |_| decode_source_record(&mut cursor)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RepairDatagram<'a> {
    pub(crate) repair_id: u32,
    pub(crate) first_symbol_id: u32,
    pub(crate) span: u16,
    pub(crate) symbol_size: u16,
    pub(crate) seed: u32,
    pub(crate) coded: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum CodecError {
    #[error("truncated QUICP frame")]
    Truncated,
    #[error("QUICP integer is not canonical")]
    NonCanonical,
    #[error("QUICP field is invalid")]
    InvalidField,
    #[error("QUICP frame type is unknown")]
    UnknownType,
    #[error("QUICP frame has trailing bytes")]
    TrailingBytes,
    #[error("QUICP frame exceeds a negotiated limit")]
    Limit,
}

fn control_payload_range(
    input: &[u8],
    max_frame_bytes: usize,
) -> Result<core::ops::Range<usize>, CodecError> {
    let rest = input.get(1..).ok_or(CodecError::Truncated)?;
    let (length, length_bytes) = decode_varint(rest)?;
    let length = usize::try_from(length).map_err(|_| CodecError::Limit)?;
    let header = 1 + length_bytes;
    let end = header
        .checked_add(length)
        .filter(|end| *end <= max_frame_bytes)
        .ok_or(CodecError::Limit)?;
    Ok(header..end)
}

/// Returns the bounded byte count needed for the next prefix or complete frame.
pub(crate) fn control_frame_read_target(
    input: &[u8],
    max_frame_bytes: usize,
) -> Result<usize, CodecError> {
    match control_payload_range(input, max_frame_bytes) {
        Ok(payload) => Ok(payload.end),
        Err(CodecError::Truncated) => {
            let needed = input.get(1).map_or(2, |first| 1 + (1usize << (first >> 6)));
            if needed > max_frame_bytes {
                return Err(CodecError::Limit);
            }
            Ok(needed)
        }
        Err(error) => Err(error),
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn decode_control(
    input: &[u8],
    max_ack_ranges: usize,
    max_frame_bytes: usize,
) -> Result<(ControlFrame<'_>, usize), CodecError> {
    let range = control_payload_range(input, max_frame_bytes)?;
    let end = range.end;
    let payload = input.get(range).ok_or(CodecError::Truncated)?;
    let mut cursor = Cursor::new(payload);
    let frame = match input[0] {
        FRAME_CAPABILITIES => {
            let flags = cursor.varint()?;
            if flags & !u64::from(CAPABILITY_MASK) != 0 {
                return Err(CodecError::InvalidField);
            }
            let capabilities = Capabilities {
                flags: u8::try_from(flags).map_err(|_| CodecError::InvalidField)?,
                max_symbol: cursor.u16()?,
                max_span: cursor.u16()?,
                decoder_window: cursor.u16()?,
                max_ack_ranges: cursor.u8()?,
            };
            if capabilities.max_symbol < 64
                || capabilities.max_span == 0
                || capabilities.max_span > MAX_REPAIR_SPAN
                || !(512..=MAX_DECODER_WINDOW).contains(&capabilities.decoder_window)
                || capabilities.max_ack_ranges == 0
                || capabilities.max_ack_ranges > 32
            {
                return Err(CodecError::InvalidField);
            }
            ControlFrame::Capabilities(capabilities)
        }
        FRAME_OPEN => {
            let (request, consumed) =
                OpenRequest::decode(payload).map_err(|_| CodecError::InvalidField)?;
            if consumed != payload.len() {
                return Err(CodecError::TrailingBytes);
            }
            return Ok((ControlFrame::Open(request), end));
        }
        FRAME_STATUS => ControlFrame::Status(
            OpenStatus::decode(cursor.u8()?).map_err(|_| CodecError::InvalidField)?,
        ),
        FRAME_ACK => {
            let contiguous = cursor.varint()?;
            let count = usize::from(cursor.u8()?);
            if count > max_ack_ranges {
                return Err(CodecError::Limit);
            }
            let mut ranges = Vec::with_capacity(count);
            let mut previous = contiguous;
            for _ in 0..count {
                let start = cursor.varint()?;
                let end = cursor.varint()?;
                if start < previous || start >= end || end > MAX_WIRE_OFFSET {
                    return Err(CodecError::InvalidField);
                }
                previous = end;
                ranges.push(start..end);
            }
            ControlFrame::Ack { contiguous, ranges }
        }
        FRAME_MAX_OFFSET => ControlFrame::MaxOffset(cursor.varint()?),
        FRAME_FIN => ControlFrame::Fin(cursor.varint()?),
        FRAME_STREAM_DATA => {
            let offset = cursor.varint()?;
            let flags = cursor.u8()?;
            if flags & !1 != 0 {
                return Err(CodecError::InvalidField);
            }
            let data = cursor.remaining();
            return Ok((
                ControlFrame::StreamData {
                    offset,
                    fin: flags == 1,
                    data,
                },
                end,
            ));
        }
        FRAME_EARLY_OPEN => {
            let token_len = usize::from(cursor.u8()?);
            if token_len == 0 || token_len > 128 {
                return Err(CodecError::Limit);
            }
            let token = cursor.take(token_len)?;
            let nonce = cursor.u64()?;
            let remaining = cursor.remaining();
            let (request, consumed) =
                OpenRequest::decode(remaining).map_err(|_| CodecError::InvalidField)?;
            let initial = &remaining[consumed..];
            if initial.is_empty() {
                return Err(CodecError::InvalidField);
            }
            return Ok((
                ControlFrame::EarlyOpen {
                    token,
                    nonce,
                    request,
                    initial,
                },
                end,
            ));
        }
        _ => return Err(CodecError::UnknownType),
    };
    if !cursor.is_empty() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((frame, end))
}

pub(crate) fn encode_control(frame: &ControlFrame<'_>, output: &mut Vec<u8>) {
    let kind = match frame {
        ControlFrame::Capabilities(_) => FRAME_CAPABILITIES,
        ControlFrame::Open(_) => FRAME_OPEN,
        ControlFrame::Status(_) => FRAME_STATUS,
        ControlFrame::Ack { .. } => FRAME_ACK,
        ControlFrame::MaxOffset(_) => FRAME_MAX_OFFSET,
        ControlFrame::Fin(_) => FRAME_FIN,
        ControlFrame::StreamData { .. } => FRAME_STREAM_DATA,
        ControlFrame::EarlyOpen { .. } => FRAME_EARLY_OPEN,
    };
    let mut payload = Vec::new();
    match frame {
        ControlFrame::Capabilities(capabilities) => {
            encode_varint(u64::from(capabilities.flags), &mut payload);
            payload.extend_from_slice(&capabilities.max_symbol.to_be_bytes());
            payload.extend_from_slice(&capabilities.max_span.to_be_bytes());
            payload.extend_from_slice(&capabilities.decoder_window.to_be_bytes());
            payload.push(capabilities.max_ack_ranges);
        }
        ControlFrame::Open(request) => {
            let start = payload.len();
            payload.resize(start + request.encoded_len(), 0);
            request
                .encode_into(&mut payload[start..])
                .expect("OPEN payload has exact capacity");
        }
        ControlFrame::Status(status) => payload.push(status.encode()),
        ControlFrame::Ack { contiguous, ranges } => {
            encode_varint(*contiguous, &mut payload);
            payload.push(u8::try_from(ranges.len()).expect("validated ACK range count"));
            for range in ranges {
                encode_varint(range.start, &mut payload);
                encode_varint(range.end, &mut payload);
            }
        }
        ControlFrame::MaxOffset(offset) | ControlFrame::Fin(offset) => {
            encode_varint(*offset, &mut payload);
        }
        ControlFrame::StreamData { offset, fin, data } => {
            encode_varint(*offset, &mut payload);
            payload.push(u8::from(*fin));
            payload.extend_from_slice(data);
        }
        ControlFrame::EarlyOpen {
            token,
            nonce,
            request,
            initial,
        } => {
            payload.push(u8::try_from(token.len()).expect("validated replay token length"));
            payload.extend_from_slice(token);
            payload.extend_from_slice(&nonce.to_be_bytes());
            let start = payload.len();
            payload.resize(start + request.encoded_len(), 0);
            request
                .encode_into(&mut payload[start..])
                .expect("EARLY_OPEN payload has exact capacity");
            payload.extend_from_slice(initial);
        }
    }
    output.push(kind);
    encode_varint(payload.len() as u64, output);
    output.extend_from_slice(&payload);
}

pub(crate) fn encode_source(
    symbol_id: u32,
    records: &[SourceRecord<'_>],
    output: &mut Vec<u8>,
) -> Result<(), CodecError> {
    let count = u8::try_from(records.len()).map_err(|_| CodecError::Limit)?;
    if count == 0 {
        return Err(CodecError::InvalidField);
    }
    output.push(SOURCE_DATAGRAM);
    output.extend_from_slice(&symbol_id.to_be_bytes());
    output.push(count);
    for record in records {
        if record.data.is_empty() {
            return Err(CodecError::InvalidField);
        }
        validate_wire_range(record.offset, record.data.len())?;
        encode_varint(record.flow_id, output);
        encode_varint(record.offset, output);
        output.push(u8::from(record.fin));
        encode_varint(record.data.len() as u64, output);
        output.extend_from_slice(record.data);
    }
    Ok(())
}

pub(crate) fn decode_source(
    input: &[u8],
    max_records: usize,
    max_symbol_bytes: usize,
) -> Result<SourceDatagram<'_>, CodecError> {
    let (source, consumed) = decode_source_inner(input, max_records, max_symbol_bytes)?;
    if consumed != input.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(source)
}

pub(crate) fn decode_source_padded(
    input: &[u8],
    max_records: usize,
    max_symbol_bytes: usize,
) -> Result<(SourceDatagram<'_>, usize), CodecError> {
    let (source, consumed) = decode_source_inner(input, max_records, max_symbol_bytes)?;
    if input[consumed..].iter().any(|byte| *byte != 0) {
        return Err(CodecError::TrailingBytes);
    }
    Ok((source, consumed))
}

fn decode_source_inner(
    input: &[u8],
    max_records: usize,
    max_symbol_bytes: usize,
) -> Result<(SourceDatagram<'_>, usize), CodecError> {
    if input.len() > max_symbol_bytes {
        return Err(CodecError::Limit);
    }
    let mut cursor = Cursor::new(input);
    if cursor.u8()? != SOURCE_DATAGRAM {
        return Err(CodecError::UnknownType);
    }
    let symbol_id = cursor.u32()?;
    let count = usize::from(cursor.u8()?);
    if count == 0 || count > max_records {
        return Err(CodecError::Limit);
    }
    let first_record = decode_source_record(&mut cursor)?;
    let remaining_start = cursor.offset;
    for _ in 1..count {
        decode_source_record(&mut cursor)?;
    }
    let consumed = cursor.offset;
    Ok((
        SourceDatagram {
            symbol_id,
            first_record,
            remaining_records: &input[remaining_start..consumed],
            record_count: count,
        },
        consumed,
    ))
}

fn decode_source_record<'a>(cursor: &mut Cursor<'a>) -> Result<SourceRecord<'a>, CodecError> {
    let flow_id = cursor.varint()?;
    let offset = cursor.varint()?;
    let flags = cursor.u8()?;
    if flags & !1 != 0 {
        return Err(CodecError::InvalidField);
    }
    let length = usize::try_from(cursor.varint()?).map_err(|_| CodecError::Limit)?;
    if length == 0 {
        return Err(CodecError::InvalidField);
    }
    validate_wire_range(offset, length)?;
    Ok(SourceRecord {
        flow_id,
        offset,
        fin: flags == 1,
        data: cursor.take(length)?,
    })
}

fn validate_wire_range(offset: u64, length: usize) -> Result<(), CodecError> {
    let length = u64::try_from(length).map_err(|_| CodecError::Limit)?;
    offset
        .checked_add(length)
        .filter(|end| *end <= MAX_WIRE_OFFSET)
        .map(|_| ())
        .ok_or(CodecError::InvalidField)
}

pub(crate) fn encode_repair(
    frame: RepairDatagram<'_>,
    output: &mut Vec<u8>,
) -> Result<(), CodecError> {
    if frame.span == 0
        || frame.span > MAX_REPAIR_SPAN
        || frame.symbol_size == 0
        || frame.coded.len() != usize::from(frame.symbol_size)
    {
        return Err(CodecError::InvalidField);
    }
    output.push(REPAIR_DATAGRAM);
    output.extend_from_slice(&frame.repair_id.to_be_bytes());
    output.extend_from_slice(&frame.first_symbol_id.to_be_bytes());
    output.extend_from_slice(&frame.span.to_be_bytes());
    output.extend_from_slice(&frame.symbol_size.to_be_bytes());
    output.extend_from_slice(&frame.seed.to_be_bytes());
    output.extend_from_slice(frame.coded);
    Ok(())
}

pub(crate) fn decode_repair(
    input: &[u8],
    max_symbol_bytes: usize,
) -> Result<RepairDatagram<'_>, CodecError> {
    let mut cursor = Cursor::new(input);
    if cursor.u8()? != REPAIR_DATAGRAM {
        return Err(CodecError::UnknownType);
    }
    let repair_id = cursor.u32()?;
    let first_symbol_id = cursor.u32()?;
    let span = cursor.u16()?;
    let symbol_size = cursor.u16()?;
    let seed = cursor.u32()?;
    if span == 0
        || span > MAX_REPAIR_SPAN
        || symbol_size == 0
        || usize::from(symbol_size) > max_symbol_bytes
    {
        return Err(CodecError::InvalidField);
    }
    let coded = cursor.take(usize::from(symbol_size))?;
    if !cursor.is_empty() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(RepairDatagram {
        repair_id,
        first_symbol_id,
        span,
        symbol_size,
        seed,
        coded,
    })
}

fn encode_varint(value: u64, output: &mut Vec<u8>) {
    match value {
        0..=63 => output.push(u8::try_from(value).expect("one-byte varint")),
        64..=16_383 => output.extend_from_slice(
            &(u16::try_from(value).expect("two-byte varint") | 0x4000).to_be_bytes(),
        ),
        16_384..=1_073_741_823 => {
            output.extend_from_slice(
                &(u32::try_from(value).expect("four-byte varint") | 0x8000_0000).to_be_bytes(),
            );
        }
        _ => output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

fn decode_varint(input: &[u8]) -> Result<(u64, usize), CodecError> {
    let first = *input.first().ok_or(CodecError::Truncated)?;
    let length = 1usize << usize::from(first >> 6);
    let bytes = input.get(..length).ok_or(CodecError::Truncated)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    let minimum = match length {
        1 => 0,
        2 => 64,
        4 => 16_384,
        8 => 1_073_741_824,
        _ => unreachable!(),
    };
    if value < minimum {
        return Err(CodecError::NonCanonical);
    }
    Ok((value, length))
}

struct Cursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn u8(&mut self) -> Result<u8, CodecError> {
        let value = *self.input.get(self.offset).ok_or(CodecError::Truncated)?;
        self.offset += 1;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, CodecError> {
        let bytes = self
            .input
            .get(self.offset..self.offset + 2)
            .ok_or(CodecError::Truncated)?;
        self.offset += 2;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, CodecError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, CodecError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(
            bytes.try_into().map_err(|_| CodecError::Truncated)?,
        ))
    }

    fn varint(&mut self) -> Result<u64, CodecError> {
        let (value, length) = decode_varint(&self.input[self.offset..])?;
        self.offset += length;
        Ok(value)
    }

    fn remaining(&mut self) -> &'a [u8] {
        let remaining = &self.input[self.offset..];
        self.offset = self.input.len();
        remaining
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let end = self.offset.checked_add(length).ok_or(CodecError::Limit)?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(CodecError::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.input.len()
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
        assert_eq!(remainder, []);
        pairs
            .iter()
            .map(|pair| {
                let text = core::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    #[test]
    fn committed_vectors_decode_and_reencode() {
        for line in include_str!("../tests/vectors/quicp.txt").lines() {
            if line.starts_with('#') {
                continue;
            }
            let Some((name, value)) = line.split_once(" = ") else {
                continue;
            };
            let bytes = hex(value);
            if name == "profile" {
                assert_eq!(bytes, QUICP_PROFILE, "{name}");
                continue;
            }
            if name.starts_with("invalid_repair") {
                assert!(decode_repair(&bytes, 1200).is_err(), "{name}");
                continue;
            }
            if name.starts_with("invalid_source") {
                assert!(decode_source(&bytes, 8, 1200).is_err(), "{name}");
                continue;
            }
            if name == "source" {
                let decoded = decode_source(&bytes, 8, 1200).unwrap();
                let mut encoded = Vec::new();
                let records = decoded.records().collect::<Result<Vec<_>, _>>().unwrap();
                encode_source(decoded.symbol_id, &records, &mut encoded).unwrap();
                assert_eq!(encoded, bytes, "{name}");
                continue;
            }
            if name == "repair" {
                let decoded = decode_repair(&bytes, 1200).unwrap();
                let mut encoded = Vec::new();
                encode_repair(decoded, &mut encoded).unwrap();
                assert_eq!(encoded, bytes, "{name}");
                continue;
            }
            if name.starts_with("invalid_") {
                assert!(decode_control(&bytes, 32, 1200).is_err(), "{name}");
                continue;
            }
            let (frame, consumed) =
                decode_control(&bytes, 32, 1200).unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(consumed, bytes.len(), "{name}");
            let mut encoded = Vec::new();
            encode_control(&frame, &mut encoded);
            assert_eq!(encoded, bytes, "{name}");
        }
    }

    #[test]
    fn rejects_noncanonical_and_excessive_ack_ranges() {
        assert_eq!(
            decode_control(&hex("054001"), 32, 1200),
            Err(CodecError::NonCanonical)
        );
        assert_eq!(
            decode_control(&hex("0406000140404080"), 0, 1200),
            Err(CodecError::Limit)
        );
    }

    #[test]
    fn capabilities_reject_every_reserved_flag() {
        for flags in 0..=u8::MAX {
            let frame = ControlFrame::Capabilities(Capabilities {
                flags,
                max_symbol: 1200,
                max_span: 16,
                decoder_window: 512,
                max_ack_ranges: 32,
            });
            let mut encoded = Vec::new();
            encode_control(&frame, &mut encoded);
            let decoded = decode_control(&encoded, 32, 1200);
            if flags & !CAPABILITY_MASK == 0 {
                assert_eq!(decoded, Ok((frame, encoded.len())));
            } else {
                assert_eq!(decoded, Err(CodecError::InvalidField));
            }
        }
    }

    #[test]
    fn recovered_source_accepts_only_zero_padding() {
        let source = hex("2000000001010000000468656c70");
        let decoded = decode_source(&source, 1, 1200).unwrap();
        let record = decoded.single_record().unwrap();
        assert_eq!(
            (decoded.symbol_id, record.flow_id, record.offset, record.fin),
            (1, 0, 0, false)
        );
        assert_eq!(record.data, b"help");
        assert_eq!(record.data.as_ptr(), source[source.len() - 4..].as_ptr());
        let mut padded = source.clone();
        padded.extend_from_slice(&[0, 0]);
        assert_eq!(
            decode_source(&padded, 8, 1200),
            Err(CodecError::TrailingBytes)
        );
        assert_eq!(
            decode_source_padded(&padded, 8, 1200)
                .expect("zero-padded recovered source")
                .0
                .single_record()
                .unwrap()
                .data,
            b"help"
        );
        *padded.last_mut().expect("padding") = 1;
        assert_eq!(
            decode_source_padded(&padded, 8, 1200),
            Err(CodecError::TrailingBytes)
        );
    }

    #[test]
    fn source_range_overflow_is_rejected_before_recovery() {
        let mut source = vec![SOURCE_DATAGRAM];
        source.extend_from_slice(&1u32.to_be_bytes());
        source.push(1);
        encode_varint(0, &mut source);
        encode_varint(MAX_WIRE_OFFSET, &mut source);
        source.push(0);
        encode_varint(1, &mut source);
        source.push(b'x');

        assert_eq!(
            decode_source(&source, 1, 1200),
            Err(CodecError::InvalidField)
        );
        assert_eq!(
            encode_source(
                1,
                &[SourceRecord {
                    flow_id: 0,
                    offset: MAX_WIRE_OFFSET,
                    fin: false,
                    data: b"x",
                }],
                &mut Vec::new(),
            ),
            Err(CodecError::InvalidField)
        );
    }

    #[test]
    fn source_view_validates_every_record_before_exposing_data() {
        let records = [
            SourceRecord {
                flow_id: 1,
                offset: 0,
                fin: false,
                data: b"first",
            },
            SourceRecord {
                flow_id: 2,
                offset: 64,
                fin: true,
                data: b"second",
            },
        ];
        let mut encoded = Vec::new();
        encode_source(7, &records, &mut encoded).unwrap();
        let decoded = decode_source(&encoded, 2, 1200).unwrap();
        assert_eq!(decoded.record_count(), 2);
        assert_eq!(decoded.single_record(), None);
        assert_eq!(
            decoded.records().collect::<Result<Vec<_>, _>>().unwrap(),
            records
        );
        for end in 0..encoded.len() {
            assert!(decode_source(&encoded[..end], 2, 1200).is_err());
            assert!(decode_source_padded(&encoded[..end], 2, 1200).is_err());
        }
        assert_eq!(decode_source(&encoded, 1, 1200), Err(CodecError::Limit));

        let canonical_len = encoded.len();
        encoded.extend_from_slice(&[0, 0]);
        let (padded, consumed) = decode_source_padded(&encoded, 2, 1200).unwrap();
        assert_eq!(consumed, canonical_len);
        assert_eq!(
            padded.records().collect::<Result<Vec<_>, _>>().unwrap(),
            records
        );

        // The second record's reserved flag must invalidate the entire symbol.
        encoded[canonical_len - records[1].data.len() - 2] = 2;
        assert_eq!(
            decode_source_padded(&encoded, 2, 1200),
            Err(CodecError::InvalidField)
        );
    }

    #[test]
    fn bounded_control_framing_handles_splits_and_concatenation() {
        for length in [1, 64, 16_384] {
            let data = vec![b'x'; length];
            let frame = ControlFrame::StreamData {
                offset: 7,
                fin: false,
                data: &data,
            };
            let mut encoded = Vec::new();
            encode_control(&frame, &mut encoded);
            let total = encoded.len();
            for end in 0..total {
                let target = control_frame_read_target(&encoded[..end], total).unwrap();
                assert!(target > end && target <= total);
                assert_eq!(
                    decode_control(&encoded[..end], 32, total),
                    Err(CodecError::Truncated)
                );
            }
            assert_eq!(control_frame_read_target(&encoded, total), Ok(total));
            assert_eq!(
                decode_control(&encoded, 32, total),
                Ok((frame.clone(), total))
            );
            encoded.extend_from_within(..);
            assert_eq!(control_frame_read_target(&encoded, total), Ok(total));
            assert_eq!(decode_control(&encoded, 32, total), Ok((frame, total)));
            assert_eq!(
                control_frame_read_target(&encoded, total - 1),
                Err(CodecError::Limit)
            );
        }

        for prefix in [hex("034001"), hex("0380000001"), hex("03c000000000000001")] {
            assert_eq!(
                control_frame_read_target(&prefix, 1200),
                Err(CodecError::NonCanonical)
            );
            assert_eq!(
                decode_control(&prefix, 32, 1200),
                Err(CodecError::NonCanonical)
            );
        }
        let mut oversized = vec![FRAME_STREAM_DATA];
        encode_varint(1 << 30, &mut oversized);
        assert_eq!(
            control_frame_read_target(&oversized, 1200),
            Err(CodecError::Limit)
        );
        assert_eq!(decode_control(&oversized, 32, 1200), Err(CodecError::Limit));
    }
}
