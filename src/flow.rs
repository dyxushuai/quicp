//! Established bidirectional flows and their bounded OPEN/STATUS exchange.
//!
//! The public types hide backend streams while preserving poll-based, runtime-neutral I/O.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::session::{
    ApplicationError, ApplicationProfile, ClientOpenGate, OpenDisposition, SessionError,
};
use crate::transport::ConnectionPermit;
use crate::wire::{MAX_OPEN_FRAME_BYTES, OpenRequest, OpenStatus};
use bytes::{Bytes, BytesMut};
use thiserror::Error;

#[cfg(feature = "runtime-tokio")]
#[path = "flow/tokio.rs"]
mod tokio_adapter;
#[cfg(feature = "runtime-tokio")]
pub use tokio_adapter::relay_bidirectional;

#[cfg(any(feature = "runtime-tokio", feature = "internal-bench"))]
pub(crate) const RELAY_BUFFER_BYTES: usize = 32 * 1024;

/// A bidirectional QUICP flow after the bounded OPEN/STATUS exchange.
///
/// The current implementation stores a `noq` stream internally. That backend detail is not the
/// QUICP wire contract and is kept behind this flow interface. The flow also retains the
/// connection lifetime needed by the backend while the application owns only the flow handle.
#[derive(Debug)]
pub struct QuicpFlow {
    _connection: noq::Connection,
    _lease: Option<Arc<ConnectionPermit>>,
    send: noq::SendStream,
    send_buffer: BytesMut,
    send_chunk: Option<Bytes>,
    deferred_write_error: Option<io::Error>,
    nodelay: bool,
    recv: noq::RecvStream,
    recv_buffer: Vec<u8>,
    flow_buffer_bytes: usize,
    recv_start: usize,
    recv_end: usize,
    recv_eof: bool,
}

impl QuicpFlow {
    fn new(
        connection: noq::Connection,
        lease: Option<Arc<ConnectionPermit>>,
        send: noq::SendStream,
        recv: noq::RecvStream,
        flow_buffer_bytes: usize,
        default_nodelay: bool,
    ) -> Self {
        Self {
            _connection: connection,
            _lease: lease,
            send,
            send_buffer: BytesMut::with_capacity(flow_buffer_bytes),
            send_chunk: None,
            deferred_write_error: None,
            nodelay: default_nodelay,
            recv,
            recv_buffer: vec![0; flow_buffer_bytes],
            flow_buffer_bytes,
            recv_start: 0,
            recv_end: 0,
            recv_eof: false,
        }
    }

    /// Opens one client flow and waits for the gateway's status byte.
    ///
    /// No application payload is written before `STATUS(ok)` is received.
    ///
    /// # Errors
    ///
    /// Returns an error when the QUICP flow cannot be opened, the OPEN header or status cannot
    /// be exchanged, or the gateway rejects the flow.
    #[cfg(feature = "internal-bench")]
    pub async fn open(
        connection: &noq::Connection,
        request: OpenRequest,
        current_policy_authorized: bool,
    ) -> Result<Self, FlowError> {
        Self::open_backend(
            connection,
            request,
            current_policy_authorized,
            None,
            RELAY_BUFFER_BYTES,
            true,
        )
        .await
    }

    pub(crate) async fn open_backend(
        connection: &noq::Connection,
        request: OpenRequest,
        current_policy_authorized: bool,
        lease: Option<Arc<ConnectionPermit>>,
        flow_buffer_bytes: usize,
        default_nodelay: bool,
    ) -> Result<Self, FlowError> {
        ApplicationProfile::admit_negotiated(connection, current_policy_authorized)?;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| FlowError::Open(Box::new(error)))?;
        let mut encoded = [0u8; MAX_OPEN_FRAME_BYTES];
        let encoded_length = request
            .encode_into(&mut encoded)
            .map_err(SessionError::from)?;
        send.write_all(&encoded[..encoded_length])
            .await
            .map_err(|error| FlowError::Write(Box::new(error)))?;

        let mut status = [0u8; 1];
        recv.read_exact(&mut status)
            .await
            .map_err(|error| FlowError::Read(Box::new(error)))?;
        let mut gate = ClientOpenGate::new();
        match gate.accept_status(status[0])? {
            OpenDisposition::Ready => Ok(Self::new(
                connection.clone(),
                lease,
                send,
                recv,
                flow_buffer_bytes,
                default_nodelay,
            )),
            OpenDisposition::Rejected(status) => Err(FlowError::Rejected(status)),
        }
    }

    /// Resets the backend stream for explicit flow-abort handling.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer has already closed the stream.
    pub fn reset(&mut self, error: ApplicationError) -> Result<(), FlowError> {
        self.send
            .reset(backend_error_code(error))
            .map_err(|error| FlowError::Reset(Box::new(error)))
    }

    /// Returns whether writes are sent without waiting for the flow buffer to fill.
    #[must_use]
    pub const fn nodelay(&self) -> bool {
        self.nodelay
    }

    /// Enables or disables TCP_NODELAY-like flow batching.
    ///
    /// The default is enabled so an idle small write is not held by QUICP's application buffer.
    /// Disabling it allows writes to accumulate up to the bounded flow buffer; callers should
    /// call [`Self::poll_flush`] (or use `AsyncWriteExt::flush`) at message boundaries.
    pub fn set_nodelay(&mut self, nodelay: bool) {
        self.nodelay = nodelay;
    }

    /// Attempts to read flow bytes without depending on a particular async runtime.
    pub fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.recv_start != self.recv_end {
            let length = (self.recv_end - self.recv_start).min(buf.len());
            buf[..length]
                .copy_from_slice(&self.recv_buffer[self.recv_start..self.recv_start + length]);
            self.recv_start += length;
            return Poll::Ready(Ok(length));
        }
        if self.recv_eof {
            return Poll::Ready(Ok(0));
        }
        let this = self.as_mut().get_mut();
        match this.recv.poll_read(cx, &mut this.recv_buffer) {
            Poll::Ready(Ok(length)) => {
                if length == 0 {
                    this.recv_eof = true;
                    Poll::Ready(Ok(0))
                } else {
                    this.recv_start = 0;
                    this.recv_end = length;
                    let copy = length.min(buf.len());
                    buf[..copy].copy_from_slice(&this.recv_buffer[..copy]);
                    this.recv_start = copy;
                    Poll::Ready(Ok(copy))
                }
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Writes flow bytes to the QUICP backend with TCP-like no-delay semantics by default.
    ///
    /// At most the configured flow-buffer size is accepted per call. When [`Self::nodelay`] is
    /// enabled, the copied chunk is immediately pushed to the backend; otherwise it is held until
    /// the bounded buffer fills or the caller flushes it.
    pub fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if let Some(error) = self.deferred_write_error.take() {
            return Poll::Ready(Err(error));
        }
        loop {
            let must_drain = self.send_chunk.is_some()
                || (self.nodelay && !self.send_buffer.is_empty())
                || (!self.nodelay && self.send_buffer.len() == self.flow_buffer_bytes);
            if must_drain {
                match self.as_mut().poll_send_buffer(cx) {
                    Poll::Ready(Ok(())) => continue,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            let available = self.flow_buffer_bytes - self.send_buffer.len();
            let length = available.min(buf.len());
            self.send_buffer.extend_from_slice(&buf[..length]);
            if self.nodelay {
                match self.as_mut().poll_send_buffer(cx) {
                    Poll::Ready(Ok(())) | Poll::Pending => {}
                    Poll::Ready(Err(error)) => {
                        self.send_chunk = None;
                        self.send_buffer.clear();
                        self.deferred_write_error = Some(error);
                    }
                }
            }
            return Poll::Ready(Ok(length));
        }
    }

    /// Flushes buffered flow bytes.
    pub fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.as_mut().poll_send_buffer(cx)
    }

    /// Flushes buffered bytes and half-closes the QUICP send side.
    pub fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_send_buffer(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        let this = self.as_mut().get_mut();
        Poll::Ready(
            this.send
                .finish()
                .map_err(noq::WriteError::from)
                .map_err(Into::into),
        )
    }
}

impl QuicpFlow {
    fn poll_send_buffer(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(error) = this.deferred_write_error.take() {
            return Poll::Ready(Err(error));
        }
        if this.send_chunk.is_none() && !this.send_buffer.is_empty() {
            this.send_chunk = Some(this.send_buffer.split().freeze());
        }
        while let Some(chunk) = this.send_chunk.as_ref() {
            let length = chunk.len();
            let result = {
                let chunks = std::slice::from_mut(this.send_chunk.as_mut().expect("chunk"));
                let mut chunks = chunks;
                let future = this.send.write_many_chunks(&mut chunks);
                let mut future = std::pin::pin!(future);
                future.as_mut().poll(cx)
            };
            match result {
                Poll::Ready(Ok(written)) if written > 0 => {
                    if written == length {
                        this.send_chunk = None;
                    }
                }
                Poll::Ready(Ok(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "QUICP stream accepted no buffered bytes",
                    )));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// A server-side flow whose OPEN has been parsed but not yet admitted.
#[derive(Debug)]
pub struct PendingFlow {
    connection: noq::Connection,
    lease: Option<Arc<ConnectionPermit>>,
    request: OpenRequest,
    send: noq::SendStream,
    recv: noq::RecvStream,
    flow_buffer_bytes: usize,
    default_nodelay: bool,
}

impl PendingFlow {
    #[must_use]
    /// Returns the validated OPEN request awaiting a server decision.
    pub const fn request(&self) -> &OpenRequest {
        &self.request
    }

    /// Sends `STATUS(ok)` and promotes this flow to a byte stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the status cannot be delivered.
    pub async fn accept(mut self) -> Result<QuicpFlow, FlowError> {
        self.send
            .write_all(&[OpenStatus::Ok.encode()])
            .await
            .map_err(|error| FlowError::Write(Box::new(error)))?;
        Ok(QuicpFlow::new(
            self.connection,
            self.lease,
            self.send,
            self.recv,
            self.flow_buffer_bytes,
            self.default_nodelay,
        ))
    }

    /// Sends a terminal status and closes the stream without exposing payload bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the status or stream finish cannot be delivered.
    pub async fn reject(mut self, status: OpenStatus) -> Result<(), FlowError> {
        if status == OpenStatus::Ok {
            return Err(FlowError::InvalidRejectStatus);
        }
        self.send
            .write_all(&[status.encode()])
            .await
            .map_err(|error| FlowError::Write(Box::new(error)))?;
        self.send
            .finish()
            .map_err(noq::WriteError::from)
            .map_err(|error| FlowError::Write(Box::new(error)))?;
        Ok(())
    }
}

/// Accepts the next client-initiated flow and parses its bounded OPEN header.
///
/// # Errors
///
/// Returns an error when no bidirectional stream can be accepted or the OPEN header is invalid.
#[cfg(feature = "internal-bench")]
pub async fn accept_flow(
    connection: &noq::Connection,
    current_policy_authorized: bool,
) -> Result<PendingFlow, FlowError> {
    accept_flow_backend(
        connection,
        current_policy_authorized,
        None,
        RELAY_BUFFER_BYTES,
        true,
    )
    .await
}

pub(crate) async fn accept_flow_backend(
    connection: &noq::Connection,
    current_policy_authorized: bool,
    lease: Option<Arc<ConnectionPermit>>,
    flow_buffer_bytes: usize,
    default_nodelay: bool,
) -> Result<PendingFlow, FlowError> {
    ApplicationProfile::admit_negotiated(connection, current_policy_authorized)?;
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|error| FlowError::Accept(Box::new(error)))?;
    let request = match read_open(&mut recv).await {
        Ok(request) => request,
        Err(error) if error.is_protocol_violation() => {
            let code = backend_error_code(ApplicationError::FlowProtocol);
            let _ = send.reset(code);
            let _ = recv.stop(code);
            return Err(error);
        }
        Err(error) => return Err(error),
    };
    Ok(PendingFlow {
        connection: connection.clone(),
        lease,
        request,
        send,
        recv,
        flow_buffer_bytes,
        default_nodelay,
    })
}

async fn read_open(recv: &mut noq::RecvStream) -> Result<OpenRequest, FlowError> {
    let mut first = [0u8; 1];
    recv.read_exact(&mut first)
        .await
        .map_err(|error| FlowError::Read(Box::new(error)))?;
    let host_len = usize::from(first[0]);
    if host_len == 0 {
        return Err(SessionError::Wire(crate::wire::WireError::InvalidHostLength).into());
    }
    let encoded_length = host_len + 3;
    if encoded_length > MAX_OPEN_FRAME_BYTES {
        return Err(SessionError::Wire(crate::wire::WireError::InvalidHost).into());
    }
    let mut encoded = [0u8; MAX_OPEN_FRAME_BYTES];
    encoded[0] = first[0];
    recv.read_exact(&mut encoded[1..encoded_length])
        .await
        .map_err(|error| FlowError::Read(Box::new(error)))?;
    let (request, consumed) =
        OpenRequest::decode(&encoded[..encoded_length]).map_err(SessionError::from)?;
    debug_assert_eq!(consumed, encoded_length);
    Ok(request)
}

pub(crate) fn backend_error_code(error: ApplicationError) -> noq::VarInt {
    #[allow(clippy::cast_possible_truncation)]
    let code = error.code() as u32;
    noq::VarInt::from_u32(code)
}

/// Flow opening, acceptance, I/O, reset, and session-protocol errors.
#[derive(Debug, Error)]
pub enum FlowError {
    /// Opening a backend bidirectional stream failed.
    #[error("opening QUICP flow: {0}")]
    Open(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// Accepting a backend bidirectional stream failed.
    #[error("accepting QUICP flow: {0}")]
    Accept(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// Reading flow bytes failed.
    #[error("reading QUICP flow: {0}")]
    Read(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// Writing flow bytes failed.
    #[error("writing QUICP flow: {0}")]
    Write(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// Resetting the flow failed.
    #[error("resetting QUICP flow: {0}")]
    Reset(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The peer rejected the OPEN request with a protocol status.
    #[error("flow status rejected: {0:?}")]
    Rejected(OpenStatus),
    /// A caller tried to reject a flow with the success status.
    #[error("flow status OK cannot be used for rejection")]
    InvalidRejectStatus,
    /// The bounded OPEN/STATUS exchange failed.
    #[error(transparent)]
    Session(#[from] SessionError),
}

impl FlowError {
    fn is_protocol_violation(&self) -> bool {
        matches!(self, Self::Session(SessionError::Wire(_)))
            || matches!(
                self,
                Self::Read(error)
                    if matches!(error.downcast_ref(), Some(noq::ReadExactError::FinishedEarly(_)))
            )
    }
}
