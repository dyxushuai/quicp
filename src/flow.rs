use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use thiserror::Error;
#[cfg(feature = "runtime-tokio")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::session::{
    ApplicationError, ApplicationProfile, ClientOpenGate, OpenDisposition, SessionError,
};
use crate::wire::{OpenRequest, OpenStatus};

const RELAY_BUFFER_BYTES: usize = 32 * 1024;

/// A bidirectional QUICP flow after the bounded OPEN/STATUS exchange.
///
/// The current implementation stores a `noq` stream internally. That backend detail is not the
/// QUICP wire contract and is kept behind this flow interface.
#[derive(Debug)]
pub struct QuicpFlow {
    send: noq::SendStream,
    send_buffer: BytesMut,
    send_chunk: Option<Bytes>,
    recv: noq::RecvStream,
    recv_buffer: Vec<u8>,
    recv_start: usize,
    recv_end: usize,
    recv_eof: bool,
}

impl QuicpFlow {
    fn new(send: noq::SendStream, recv: noq::RecvStream) -> Self {
        Self {
            send,
            send_buffer: BytesMut::with_capacity(RELAY_BUFFER_BYTES),
            send_chunk: None,
            recv,
            recv_buffer: vec![0; RELAY_BUFFER_BYTES],
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
    pub async fn open(
        connection: &noq::Connection,
        request: OpenRequest,
    ) -> Result<Self, FlowError> {
        ApplicationProfile::admit_negotiated(connection, true)?;
        let (mut send, mut recv) = connection.open_bi().await.map_err(FlowError::Open)?;
        send.write_all(&request.encode())
            .await
            .map_err(FlowError::Write)?;

        let mut status = [0u8; 1];
        recv.read_exact(&mut status)
            .await
            .map_err(FlowError::Read)?;
        let mut gate = ClientOpenGate::new();
        match gate.accept_status(status[0])? {
            OpenDisposition::Ready => Ok(Self::new(send, recv)),
            OpenDisposition::Rejected(status) => Err(FlowError::Rejected(status)),
        }
    }

    /// Resets the backend stream for explicit flow-abort handling.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer has already closed the stream.
    pub fn reset(&mut self, error: ApplicationError) -> Result<(), noq::ClosedStream> {
        self.send.reset(backend_error_code(error))
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

    /// Attempts to buffer flow bytes without depending on a particular async runtime.
    pub fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.send_chunk.is_some() || self.send_buffer.len() == RELAY_BUFFER_BYTES {
            match self.as_mut().poll_send_buffer(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let available = RELAY_BUFFER_BYTES - self.send_buffer.len();
        let length = available.min(buf.len());
        self.send_buffer.extend_from_slice(&buf[..length]);
        Poll::Ready(Ok(length))
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

#[cfg(feature = "runtime-tokio")]
impl AsyncRead for QuicpFlow {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let read = std::task::ready!(QuicpFlow::poll_read(
            self.as_mut(),
            cx,
            buf.initialize_unfilled()
        ))?;
        buf.advance(read);
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "runtime-tokio")]
impl AsyncWrite for QuicpFlow {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        QuicpFlow::poll_write(self, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        QuicpFlow::poll_flush(self, cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        QuicpFlow::poll_shutdown(self, cx)
    }
}

impl QuicpFlow {
    fn poll_send_buffer(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
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
    request: OpenRequest,
    send: noq::SendStream,
    recv: noq::RecvStream,
}

impl PendingFlow {
    #[must_use]
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
            .map_err(FlowError::Write)?;
        Ok(QuicpFlow::new(self.send, self.recv))
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
            .map_err(FlowError::Write)?;
        self.send
            .finish()
            .map_err(noq::WriteError::from)
            .map_err(FlowError::Write)?;
        Ok(())
    }
}

/// Accepts the next client-initiated flow and parses its bounded OPEN header.
///
/// # Errors
///
/// Returns an error when no bidirectional stream can be accepted or the OPEN header is invalid.
pub async fn accept_flow(connection: &noq::Connection) -> Result<PendingFlow, FlowError> {
    ApplicationProfile::admit_negotiated(connection, true)?;
    let (mut send, mut recv) = connection.accept_bi().await.map_err(FlowError::Accept)?;
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
        request,
        send,
        recv,
    })
}

async fn read_open(recv: &mut noq::RecvStream) -> Result<OpenRequest, FlowError> {
    let mut first = [0u8; 1];
    recv.read_exact(&mut first).await.map_err(FlowError::Read)?;
    let host_len = usize::from(first[0]);
    if host_len == 0 {
        return Err(SessionError::Wire(crate::wire::WireError::InvalidHostLength).into());
    }
    let mut encoded = vec![0u8; host_len + 3];
    encoded[0] = first[0];
    recv.read_exact(&mut encoded[1..])
        .await
        .map_err(FlowError::Read)?;
    let (request, consumed) = OpenRequest::decode(&encoded).map_err(SessionError::from)?;
    debug_assert_eq!(consumed, encoded.len());
    Ok(request)
}

fn backend_error_code(error: ApplicationError) -> noq::VarInt {
    #[allow(clippy::cast_possible_truncation)]
    let code = error.code() as u32;
    noq::VarInt::from_u32(code)
}

#[derive(Debug, Error)]
pub enum FlowError {
    #[error("opening QUICP flow: {0}")]
    Open(#[source] noq::ConnectionError),
    #[error("accepting QUICP flow: {0}")]
    Accept(#[source] noq::ConnectionError),
    #[error("reading QUICP flow: {0}")]
    Read(#[source] noq::ReadExactError),
    #[error("writing QUICP flow: {0}")]
    Write(#[source] noq::WriteError),
    #[error("flow status rejected: {0:?}")]
    Rejected(OpenStatus),
    #[error("flow status OK cannot be used for rejection")]
    InvalidRejectStatus,
    #[error(transparent)]
    Session(#[from] SessionError),
}

impl FlowError {
    fn is_protocol_violation(&self) -> bool {
        matches!(
            self,
            Self::Session(SessionError::Wire(_))
                | Self::Read(noq::ReadExactError::FinishedEarly(_))
        )
    }
}

/// Relays two Tokio byte streams with bounded internal buffers and half-close handling.
///
/// This is the flow seam used by a future smoltcp adapter and the current QUICP backend; neither
/// side is buffered in an unbounded application queue.
///
/// # Errors
///
/// Returns the first I/O error reported by either stream.
#[cfg(feature = "runtime-tokio")]
pub async fn relay_bidirectional<A, B>(left: &mut A, right: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional_with_sizes(left, right, RELAY_BUFFER_BYTES, RELAY_BUFFER_BYTES)
        .await
}
