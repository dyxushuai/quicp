//! Tokio integration for the runtime-neutral QUICP flow.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{QuicpFlow, RELAY_BUFFER_BYTES};

impl AsyncRead for QuicpFlow {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let read = std::task::ready!(QuicpFlow::poll_read(
            self.as_mut(),
            cx,
            buf.initialize_unfilled(),
        ))?;
        buf.advance(read);
        Poll::Ready(Ok(()))
    }
}

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

/// Relays two Tokio byte streams with bounded internal buffers and half-close handling.
///
/// # Errors
///
/// Returns the first I/O error reported by either stream.
pub async fn relay_bidirectional<A, B>(left: &mut A, right: &mut B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional_with_sizes(left, right, RELAY_BUFFER_BYTES, RELAY_BUFFER_BYTES)
        .await
}
