//! Established bidirectional flows and their bounded OPEN/STATUS exchange.
//!
//! The public types hide backend streams while preserving poll-based, runtime-neutral I/O.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};

use crate::config::RecoveryMode;
use crate::recovery::{
    AckRanges, ConnectionRecovery, Reassembler, RecoveryCharge, RecoveryError,
    RecoveryMemoryBudget, ReplayBuffer, replay_chunk_limit,
};
use crate::session::{
    ApplicationError, ReplayAdmission, ReplayToken, SessionError, admit_negotiated,
};
use crate::transport::ConnectionPermit;
use crate::wire::{
    CodecError, ControlFrame, MAX_OPEN_FRAME_BYTES, MAX_WIRE_OFFSET, OpenRequest, OpenStatus,
    decode_control, encode_control,
};
use thiserror::Error;

#[cfg(feature = "runtime-tokio")]
#[path = "flow/tokio.rs"]
mod tokio_adapter;
#[cfg(feature = "runtime-tokio")]
pub use tokio_adapter::relay_bidirectional;

#[cfg(feature = "runtime-tokio")]
pub(crate) const RELAY_BUFFER_BYTES: usize = 32 * 1024;

const CONTROL_DECODE_BATCH: usize = 128;
const FLOW_TASK_TURN_BUDGET: usize = 32;
const CONTROL_READ_CHUNK: usize = 4 * 1024;
const LOGICAL_ACK_THRESHOLD: u32 = 16;
const LOGICAL_ACK_DELAY: Duration = Duration::from_millis(1);
const MAX_EARLY_OPEN_OVERHEAD: usize = 512;

#[derive(Debug)]
struct Outbound {
    offset: u64,
    bytes: Bytes,
}

#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
struct FlowShared {
    outbound: VecDeque<Outbound>,
    retained_bytes: usize,
    retained_chunks: usize,
    replay_limit: usize,
    replay_chunk_limit: usize,
    next_send_offset: u64,
    receive: Reassembler,
    receive_final_offset: Option<u64>,
    receive_window: u64,
    max_receive_offset: u64,
    credit_dirty: bool,
    received: AckRanges,
    ack_pending: u32,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    task_waker: Option<Waker>,
    flush_target: Option<u64>,
    flushed_offset: u64,
    peer_max_offset: u64,
    shutdown_target: Option<u64>,
    shutdown_done: bool,
    reset: Option<u64>,
    locally_reset: bool,
    handle_dropped: bool,
    task_stopped: bool,
    error: Option<(io::ErrorKind, String)>,
}

/// Shared bounded state between a TCP-like handle and its private control task.
#[derive(Debug)]
pub(crate) struct FlowState(Mutex<FlowShared>);

impl FlowState {
    fn new(
        recovery: crate::config::RecoveryConfig,
        memory_budget: Arc<RecoveryMemoryBudget>,
        max_ack_ranges: usize,
        initial_send_offset: u64,
    ) -> Arc<Self> {
        let receive_window = u64::from(recovery.reassembly_buffer_bytes);
        let replay_limit = usize::try_from(recovery.replay_buffer_bytes)
            .expect("validated replay buffer fits usize");
        Arc::new(Self(Mutex::new(FlowShared {
            outbound: VecDeque::new(),
            retained_bytes: 0,
            retained_chunks: 0,
            replay_limit,
            replay_chunk_limit: replay_chunk_limit(replay_limit),
            next_send_offset: initial_send_offset,
            receive: Reassembler::with_budget(
                usize::try_from(recovery.reassembly_buffer_bytes)
                    .expect("validated reassembly buffer fits usize"),
                memory_budget,
            ),
            receive_final_offset: None,
            receive_window,
            max_receive_offset: receive_window,
            credit_dirty: true,
            received: AckRanges::new(max_ack_ranges),
            ack_pending: 0,
            read_waker: None,
            write_waker: None,
            task_waker: None,
            flush_target: None,
            flushed_offset: initial_send_offset,
            peer_max_offset: 0,
            shutdown_target: None,
            shutdown_done: false,
            reset: None,
            locally_reset: false,
            handle_dropped: false,
            task_stopped: false,
            error: None,
        })))
    }

    pub(crate) fn insert_bytes(
        &self,
        offset: u64,
        bytes: Bytes,
        fin: bool,
    ) -> Result<(), RecoveryError> {
        self.insert_bytes_with_reservation(offset, bytes, fin, None)
    }

    pub(crate) fn insert_bytes_precharged(
        &self,
        offset: u64,
        bytes: Bytes,
        fin: bool,
        charge: RecoveryCharge,
    ) -> Result<(), RecoveryError> {
        self.insert_bytes_with_reservation(offset, bytes, fin, Some(charge))
    }

    fn insert_bytes_with_reservation(
        &self,
        offset: u64,
        bytes: Bytes,
        fin: bool,
        charge: Option<RecoveryCharge>,
    ) -> Result<(), RecoveryError> {
        let end = offset
            .checked_add(u64::try_from(bytes.len()).map_err(|_| RecoveryError::OffsetOverflow)?)
            .ok_or(RecoveryError::OffsetOverflow)?;
        let mut state = lock(&self.0);
        if end > state.max_receive_offset {
            return Err(RecoveryError::FlowControl);
        }
        state.received.validate_insert(&(offset..end))?;
        if let Some(charge) = charge {
            state
                .receive
                .insert_record_precharged(offset, bytes, fin, charge)?;
        } else {
            state.receive.insert_record(offset, bytes, fin)?;
        }
        if fin {
            state.receive_final_offset = Some(end);
        }
        state
            .received
            .insert(offset..end)
            .expect("validated ACK insertion");
        state.ack_pending = state.ack_pending.saturating_add(1);
        wake(&mut state.read_waker);
        if state.ack_pending == 1 || state.ack_pending >= LOGICAL_ACK_THRESHOLD {
            wake(&mut state.task_waker);
        }
        Ok(())
    }

    fn set_final_offset(&self, offset: u64) -> Result<(), RecoveryError> {
        let mut state = lock(&self.0);
        if offset > state.max_receive_offset {
            return Err(RecoveryError::FlowControl);
        }
        state.receive.set_final_offset(offset)?;
        state.receive_final_offset = Some(offset);
        state.ack_pending = state.ack_pending.saturating_add(1);
        wake(&mut state.read_waker);
        wake(&mut state.task_waker);
        Ok(())
    }

    fn read(&self, output: &mut [u8], waker: &Waker) -> io::Result<Option<usize>> {
        let mut state = lock(&self.0);
        if let Some((kind, message)) = state.error.as_ref() {
            return Err(io::Error::new(*kind, message.clone()));
        }
        let read = state.receive.read(output);
        if read != 0 {
            let maximum = state
                .receive
                .next_offset()
                .saturating_add(state.receive_window)
                .min(MAX_WIRE_OFFSET);
            if maximum > state.max_receive_offset {
                state.max_receive_offset = maximum;
                state.credit_dirty = true;
                wake(&mut state.task_waker);
            }
        }
        if read != 0 || state.receive.is_finished() {
            Ok(Some(read))
        } else {
            state.read_waker = Some(waker.clone());
            Ok(None)
        }
    }

    fn enqueue(&self, bytes: &Bytes, waker: &Waker) -> io::Result<Option<u64>> {
        let mut state = lock(&self.0);
        if !enqueue_ready(&mut state, bytes.len(), waker)? {
            return Ok(None);
        }
        let offset = state.next_send_offset;
        state.next_send_offset = offset
            .checked_add(u64::try_from(bytes.len()).expect("bounded flow chunk fits u64"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "flow offset overflow"))?;
        state.retained_bytes += bytes.len();
        state.retained_chunks += 1;
        state.outbound.push_back(Outbound {
            offset,
            bytes: bytes.clone(),
        });
        wake(&mut state.task_waker);
        Ok(Some(state.next_send_offset))
    }

    fn can_enqueue(&self, length: usize, waker: &Waker) -> io::Result<bool> {
        enqueue_ready(&mut lock(&self.0), length, waker)
    }

    fn request_flush(&self, waker: &Waker) -> io::Result<bool> {
        let mut state = lock(&self.0);
        if let Some((kind, message)) = state.error.as_ref() {
            return Err(io::Error::new(*kind, message.clone()));
        }
        let target = state.next_send_offset;
        state.flush_target = Some(state.flush_target.unwrap_or(0).max(target));
        if state.flushed_offset >= target {
            Ok(true)
        } else {
            state.write_waker = Some(waker.clone());
            wake(&mut state.task_waker);
            Ok(false)
        }
    }

    fn request_shutdown(&self, waker: &Waker) -> io::Result<bool> {
        let mut state = lock(&self.0);
        if let Some((kind, message)) = state.error.as_ref() {
            return Err(io::Error::new(*kind, message.clone()));
        }
        let target = state.next_send_offset;
        state.shutdown_target.get_or_insert(target);
        if state.shutdown_done {
            Ok(true)
        } else {
            state.write_waker = Some(waker.clone());
            wake(&mut state.task_waker);
            Ok(false)
        }
    }

    fn request_reset(&self, error: ApplicationError) -> bool {
        let mut state = lock(&self.0);
        if state.locally_reset {
            return true;
        }
        if state.task_stopped || state.error.is_some() {
            return false;
        }
        state.locally_reset = true;
        state.reset = Some(error.code());
        let discarded_bytes = state.outbound.iter().map(|item| item.bytes.len()).sum();
        state.retained_bytes = state
            .retained_bytes
            .checked_sub(discarded_bytes)
            .expect("outbound bytes are retained");
        state.retained_chunks = state
            .retained_chunks
            .checked_sub(state.outbound.len())
            .expect("outbound chunks are retained");
        state.outbound.clear();
        state.error = Some((
            io::ErrorKind::ConnectionAborted,
            "QUICP flow was reset".into(),
        ));
        wake(&mut state.read_waker);
        wake(&mut state.write_waker);
        wake(&mut state.task_waker);
        true
    }

    pub(crate) fn reject_protocol(&self) {
        let _ = self.request_reset(ApplicationError::FlowProtocol);
    }

    pub(crate) fn wake_task(&self) {
        wake(&mut lock(&self.0).task_waker);
    }

    fn fail(&self, error: impl std::fmt::Display) {
        self.fail_with_kind(io::ErrorKind::ConnectionAborted, error);
    }

    fn fail_with_kind(&self, kind: io::ErrorKind, error: impl std::fmt::Display) {
        let mut state = lock(&self.0);
        if state.error.is_none() {
            state.error = Some((kind, error.to_string()));
        }
        wake(&mut state.read_waker);
        wake(&mut state.write_waker);
    }

    fn drop_handle(&self) {
        let mut state = lock(&self.0);
        state.handle_dropped = true;
        wake(&mut state.task_waker);
    }

    fn discard_retained(&self) {
        let mut state = lock(&self.0);
        state.outbound.clear();
        state.retained_bytes = 0;
        state.retained_chunks = 0;
        wake(&mut state.write_waker);
    }

    fn mark_task_stopped(&self) {
        let mut state = lock(&self.0);
        state.task_stopped = true;
        wake(&mut state.read_waker);
        wake(&mut state.write_waker);
    }
}

/// A bidirectional QUICP flow after the bounded OPEN/STATUS exchange.
#[derive(Debug)]
pub struct QuicpFlow {
    _connection: noq::Connection,
    _lease: Option<Arc<ConnectionPermit>>,
    send_buffer: BytesMut,
    nodelay: bool,
    flow_buffer_bytes: usize,
    state: Arc<FlowState>,
}

impl Drop for QuicpFlow {
    fn drop(&mut self) {
        self.state.drop_handle();
    }
}

impl QuicpFlow {
    fn new(
        connection: noq::Connection,
        lease: Option<Arc<ConnectionPermit>>,
        send: noq::SendStream,
        recv: noq::RecvStream,
        flow_buffer_bytes: usize,
        default_nodelay: bool,
        recovery: &Arc<ConnectionRecovery>,
    ) -> Self {
        Self::new_with_send_offset(
            connection,
            lease,
            send,
            recv,
            flow_buffer_bytes,
            default_nodelay,
            recovery,
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_send_offset(
        connection: noq::Connection,
        lease: Option<Arc<ConnectionPermit>>,
        send: noq::SendStream,
        recv: noq::RecvStream,
        flow_buffer_bytes: usize,
        default_nodelay: bool,
        recovery: &Arc<ConnectionRecovery>,
        initial_send_offset: u64,
    ) -> Self {
        let state = FlowState::new(
            recovery.config(),
            recovery.memory_budget(),
            recovery.max_ack_ranges(),
            initial_send_offset,
        );
        Self::new_with_state(
            connection,
            lease,
            send,
            recv,
            flow_buffer_bytes,
            default_nodelay,
            recovery,
            state,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_with_state(
        connection: noq::Connection,
        lease: Option<Arc<ConnectionPermit>>,
        send: noq::SendStream,
        recv: noq::RecvStream,
        flow_buffer_bytes: usize,
        default_nodelay: bool,
        recovery: &Arc<ConnectionRecovery>,
        state: Arc<FlowState>,
    ) -> Self {
        let flow_id = u64::from(send.id());
        recovery.register_flow(flow_id, &state);
        recovery.spawn(Box::pin(FlowTask::new(
            send,
            recv,
            Arc::clone(&state),
            Arc::clone(recovery),
        )));
        Self {
            _connection: connection,
            _lease: lease,
            send_buffer: BytesMut::new(),
            nodelay: default_nodelay,
            flow_buffer_bytes,
            state,
        }
    }

    pub(crate) async fn open_backend(
        connection: &noq::Connection,
        request: OpenRequest,
        current_policy_authorized: bool,
        lease: Option<Arc<ConnectionPermit>>,
        flow_buffer_bytes: usize,
        default_nodelay: bool,
        recovery: Arc<ConnectionRecovery>,
    ) -> Result<Self, FlowError> {
        admit_negotiated(connection, current_policy_authorized)?;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| FlowError::Open(Box::new(error)))?;
        write_control(
            &mut send,
            &ControlFrame::Capabilities(recovery.capabilities()),
        )
        .await?;
        write_control(&mut send, &ControlFrame::Open(request)).await?;
        match read_admission_control(&mut recv, recovery.max_ack_ranges()).await? {
            ControlFrame::Capabilities(capabilities)
                if recovery.negotiate_capabilities(capabilities) => {}
            _ => return Err(FlowError::Session(SessionError::InvalidState)),
        }
        let ControlFrame::Status(status) =
            read_admission_control(&mut recv, recovery.max_ack_ranges()).await?
        else {
            return Err(FlowError::Session(SessionError::InvalidState));
        };
        if status == OpenStatus::Ok {
            Ok(Self::new(
                connection.clone(),
                lease,
                send,
                recv,
                flow_buffer_bytes,
                default_nodelay,
                &recovery,
            ))
        } else {
            Err(FlowError::Rejected(status))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn open_replay_safe_backend(
        connection: &noq::Connection,
        token: &ReplayToken,
        nonce: u64,
        request: OpenRequest,
        initial: Bytes,
        current_policy_authorized: bool,
        lease: Option<Arc<ConnectionPermit>>,
        flow_buffer_bytes: usize,
        default_nodelay: bool,
        recovery: Arc<ConnectionRecovery>,
    ) -> Result<Self, FlowError> {
        if !current_policy_authorized || initial.is_empty() || initial.len() > flow_buffer_bytes {
            return Err(FlowError::Session(SessionError::PolicyRejected));
        }
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| FlowError::Open(Box::new(error)))?;
        write_control(
            &mut send,
            &ControlFrame::Capabilities(recovery.capabilities()),
        )
        .await?;
        write_control(
            &mut send,
            &ControlFrame::EarlyOpen {
                token: token.as_bytes(),
                nonce,
                request,
                initial: &initial,
            },
        )
        .await?;
        match read_admission_control(&mut recv, recovery.max_ack_ranges()).await? {
            ControlFrame::Capabilities(capabilities)
                if recovery.negotiate_capabilities(capabilities) => {}
            _ => return Err(FlowError::Session(SessionError::InvalidState)),
        }
        let ControlFrame::Status(status) =
            read_admission_control(&mut recv, recovery.max_ack_ranges()).await?
        else {
            return Err(FlowError::Session(SessionError::InvalidState));
        };
        if status == OpenStatus::Ok {
            Ok(Self::new_with_send_offset(
                connection.clone(),
                lease,
                send,
                recv,
                flow_buffer_bytes,
                default_nodelay,
                &recovery,
                u64::try_from(initial.len())
                    .map_err(|_| FlowError::Session(SessionError::InvalidState))?,
            ))
        } else {
            Err(FlowError::Rejected(status))
        }
    }

    pub(crate) async fn write_all_initial(&mut self, mut bytes: &[u8]) -> Result<(), FlowError> {
        while !bytes.is_empty() {
            let written = std::future::poll_fn(|cx| Pin::new(&mut *self).poll_write(cx, bytes))
                .await
                .map_err(|error| FlowError::Write(Box::new(error)))?;
            if written == 0 {
                return Err(FlowError::Write(Box::new(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "QUICP flow accepted zero initial bytes",
                ))));
            }
            bytes = &bytes[written..];
        }
        std::future::poll_fn(|cx| Pin::new(&mut *self).poll_flush(cx))
            .await
            .map_err(|error| FlowError::Write(Box::new(error)))
    }

    /// Resets this logical flow.
    ///
    /// # Errors
    ///
    /// Returns an error when the peer has already closed the stream.
    pub fn reset(&mut self, error: ApplicationError) -> Result<(), FlowError> {
        if self.state.request_reset(error) {
            Ok(())
        } else {
            Err(FlowError::Reset(Box::new(io::Error::new(
                io::ErrorKind::NotConnected,
                "QUICP flow task is no longer active",
            ))))
        }
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
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.state.read(buf, cx.waker()) {
            Ok(Some(read)) => Poll::Ready(Ok(read)),
            Ok(None) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    /// Writes flow bytes to the QUICP backend with TCP-like no-delay semantics by default.
    ///
    /// At most the configured flow-buffer size is accepted per call. When [`Self::nodelay`] is
    /// enabled, the copied chunk is immediately pushed to the backend; otherwise it is held until
    /// the bounded buffer fills or the caller flushes it.
    pub fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        poll_buffered_write(
            &mut this.send_buffer,
            this.nodelay,
            this.flow_buffer_bytes,
            &this.state,
            cx,
            buf,
        )
    }

    /// Flushes buffered flow bytes.
    pub fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_send_buffer(cx) {
            Poll::Ready(Ok(())) => match self.state.request_flush(cx.waker()) {
                Ok(true) => Poll::Ready(Ok(())),
                Ok(false) => Poll::Pending,
                Err(error) => Poll::Ready(Err(error)),
            },
            result => result,
        }
    }

    /// Flushes buffered bytes and half-closes the QUICP send side.
    pub fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_send_buffer(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        match self.state.request_shutdown(cx.waker()) {
            Ok(true) => Poll::Ready(Ok(())),
            Ok(false) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl QuicpFlow {
    fn poll_send_buffer(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_send_buffer(&mut this.send_buffer, &this.state, cx)
    }
}

fn poll_buffered_write(
    send_buffer: &mut BytesMut,
    nodelay: bool,
    flow_buffer_bytes: usize,
    state: &FlowState,
    cx: &mut Context<'_>,
    buf: &[u8],
) -> Poll<io::Result<usize>> {
    if buf.is_empty() {
        return Poll::Ready(Ok(0));
    }
    if (nodelay && !send_buffer.is_empty()) || send_buffer.len() == flow_buffer_bytes {
        match poll_send_buffer(send_buffer, state, cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
    }

    let available = flow_buffer_bytes - send_buffer.len();
    let length = available.min(buf.len());
    if !nodelay
        && send_buffer.len() + length == flow_buffer_bytes
        && !state.can_enqueue(flow_buffer_bytes, cx.waker())?
    {
        return Poll::Pending;
    }
    send_buffer.extend_from_slice(&buf[..length]);
    if (nodelay || send_buffer.len() == flow_buffer_bytes)
        && let Poll::Ready(Err(error)) = poll_send_buffer(send_buffer, state, cx)
    {
        return Poll::Ready(Err(error));
    }
    Poll::Ready(Ok(length))
}

fn poll_send_buffer(
    send_buffer: &mut BytesMut,
    state: &FlowState,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    if send_buffer.is_empty() {
        return Poll::Ready(Ok(()));
    }
    let chunk = std::mem::take(send_buffer).freeze();
    match state.enqueue(&chunk, cx.waker()) {
        Ok(Some(_)) => Poll::Ready(Ok(())),
        Ok(None) => {
            *send_buffer = chunk
                .try_into_mut()
                .unwrap_or_else(|chunk| BytesMut::from(chunk.as_ref()));
            Poll::Pending
        }
        Err(error) => {
            *send_buffer = chunk
                .try_into_mut()
                .unwrap_or_else(|chunk| BytesMut::from(chunk.as_ref()));
            Poll::Ready(Err(error))
        }
    }
}

fn enqueue_ready(state: &mut FlowShared, length: usize, waker: &Waker) -> io::Result<bool> {
    if let Some((kind, message)) = state.error.as_ref() {
        return Err(io::Error::new(*kind, message.clone()));
    }
    if state.shutdown_target.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "QUICP flow is shut down",
        ));
    }
    if state.retained_bytes.saturating_add(length) > state.replay_limit
        || state.retained_chunks >= state.replay_chunk_limit
    {
        state.write_waker = Some(waker.clone());
        Ok(false)
    } else {
        Ok(true)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayStage {
    Repair,
    SourceReplay,
    ReliableFallback,
}

struct FlowTask {
    send: noq::SendStream,
    recv: noq::RecvStream,
    state: Arc<FlowState>,
    recovery: Arc<ConnectionRecovery>,
    replay: ReplayBuffer,
    ack_timer: Option<Pin<Box<dyn noq::AsyncTimer>>>,
    wire_queue: VecDeque<(Bytes, Option<u64>, Option<u64>)>,
    wire_current: Option<(Bytes, Option<u64>, Option<u64>)>,
    pending_ack: Option<(u64, Vec<core::ops::Range<u64>>)>,
    pending_credit: Option<u64>,
    input: BytesMut,
    scratch: Vec<u8>,
    max_input: usize,
    datagram_enabled: bool,
    replay_stage: ReplayStage,
    replay_cursor: Option<u64>,
    replay_timer: Option<Pin<Box<dyn noq::AsyncTimer>>>,
    fin_queued: bool,
    send_finished: bool,
    acked_receive_offset: u64,
}

impl FlowTask {
    fn new(
        send: noq::SendStream,
        recv: noq::RecvStream,
        state: Arc<FlowState>,
        recovery: Arc<ConnectionRecovery>,
    ) -> Self {
        let config = recovery.config();
        let datagram_enabled = config.mode == RecoveryMode::Adaptive;
        let max_input =
            control_input_limit(recovery.max_stream_payload(), recovery.max_ack_ranges());
        Self {
            send,
            recv,
            state,
            recovery,
            replay: ReplayBuffer::new(
                usize::try_from(config.replay_buffer_bytes)
                    .expect("validated replay buffer fits usize"),
            ),
            ack_timer: None,
            wire_queue: VecDeque::new(),
            wire_current: None,
            pending_ack: None,
            pending_credit: None,
            input: BytesMut::new(),
            scratch: vec![0; max_input.clamp(1, CONTROL_READ_CHUNK)],
            max_input,
            datagram_enabled,
            replay_stage: ReplayStage::Repair,
            replay_cursor: None,
            replay_timer: None,
            fin_queued: false,
            send_finished: false,
            acked_receive_offset: 0,
        }
    }

    fn queue_control(&mut self, frame: &ControlFrame<'_>) {
        let mut encoded = Vec::new();
        encode_control(frame, &mut encoded);
        self.wire_queue
            .push_back((Bytes::from(encoded), None, None));
    }

    fn queue_pending_feedback(&mut self, cx: &mut Context<'_>) {
        let ack_pending = lock(&self.state.0).ack_pending;
        let ack_due = if ack_pending == 0 || ack_pending >= LOGICAL_ACK_THRESHOLD {
            ack_pending != 0
        } else {
            let timer = self.ack_timer.get_or_insert_with(|| {
                self.recovery
                    .new_timer(self.recovery.now() + LOGICAL_ACK_DELAY)
            });
            timer.as_mut().poll(cx).is_ready()
        };
        if ack_pending == 0 || ack_due {
            self.ack_timer = None;
        }
        let (ack, credit) = {
            let mut state = lock(&self.state.0);
            let ack = (ack_due && state.ack_pending != 0).then(|| {
                state.ack_pending = 0;
                (
                    state.received.contiguous(),
                    state.received.ranges().to_vec(),
                )
            });
            let credit = state.credit_dirty.then(|| {
                state.credit_dirty = false;
                state.max_receive_offset
            });
            (ack, credit)
        };
        if let Some((contiguous, ranges)) = ack {
            self.pending_ack = Some((contiguous, ranges));
        }
        if let Some(maximum) = credit {
            self.pending_credit = Some(maximum);
        }
    }

    fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), FlowTaskError>> {
        let mut input = std::mem::take(&mut self.input).freeze();
        let mut hit_limit = true;
        for _ in 0..CONTROL_DECODE_BATCH {
            match decode_control(&input, self.recovery.max_ack_ranges()) {
                Ok((frame, consumed)) => {
                    self.apply_control(frame)?;
                    input.advance(consumed);
                }
                Err(CodecError::Truncated) => {
                    hit_limit = false;
                    break;
                }
                Err(error) => return Poll::Ready(Err(FlowTaskError::Codec(error))),
            }
        }
        if hit_limit {
            self.input = input
                .try_into_mut()
                .unwrap_or_else(|input| BytesMut::from(input.as_ref()));
            return Poll::Ready(Ok(()));
        }
        self.input = input
            .try_into_mut()
            .unwrap_or_else(|input| BytesMut::from(input.as_ref()));

        let remaining = self.max_input.saturating_sub(self.input.len());
        if remaining == 0 {
            return Poll::Ready(Err(FlowTaskError::ControlLimit));
        }
        let read_capacity = remaining.min(self.scratch.len());
        match self.recv.poll_read(cx, &mut self.scratch[..read_capacity]) {
            Poll::Ready(Ok(0)) => {
                let has_fin = lock(&self.state.0).receive.has_final_offset();
                if has_fin {
                    Poll::Pending
                } else {
                    Poll::Ready(Err(FlowTaskError::FinishedEarly))
                }
            }
            Poll::Ready(Ok(read)) => {
                self.input.extend_from_slice(&self.scratch[..read]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(noq::ReadError::Reset(code))) => Poll::Ready(Err(
                FlowTaskError::PeerReset(ApplicationError::from_peer_code(u64::from(code))),
            )),
            Poll::Ready(Err(error)) => Poll::Ready(Err(FlowTaskError::Read(error))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn apply_control(&mut self, frame: ControlFrame<'_>) -> Result<(), FlowTaskError> {
        match frame {
            ControlFrame::Ack { contiguous, ranges } => {
                let sent_offset = lock(&self.state.0).next_send_offset;
                let ack = AckRanges::from_wire(
                    contiguous,
                    ranges,
                    self.recovery.max_ack_ranges(),
                    sent_offset,
                )?;
                let (released_bytes, released_chunks) = self.replay.acknowledge(&ack);
                if released_bytes != 0 {
                    self.recovery.record_delivery(released_bytes);
                    let mut state = lock(&self.state.0);
                    state.retained_bytes = state
                        .retained_bytes
                        .checked_sub(released_bytes)
                        .expect("acknowledged bytes are retained");
                    state.retained_chunks = state
                        .retained_chunks
                        .checked_sub(released_chunks)
                        .expect("acknowledged chunks are retained");
                    wake(&mut state.write_waker);
                    drop(state);
                    self.replay_stage = ReplayStage::Repair;
                    self.replay_cursor = None;
                    self.restart_replay_timer();
                }
                if self.replay.bytes() == 0 {
                    self.replay_stage = ReplayStage::Repair;
                    self.replay_cursor = None;
                    self.replay_timer = None;
                }
            }
            ControlFrame::MaxOffset(maximum) => {
                let mut state = lock(&self.state.0);
                if maximum < state.peer_max_offset {
                    return Err(RecoveryError::InvalidRange.into());
                }
                state.peer_max_offset = maximum;
                wake(&mut state.task_waker);
            }
            ControlFrame::Fin(offset) => self.state.set_final_offset(offset)?,
            ControlFrame::StreamData { offset, fin, data } => {
                if data.len() > self.recovery.max_stream_payload() {
                    return Err(FlowTaskError::Codec(CodecError::Limit));
                }
                self.state
                    .insert_bytes(offset, Bytes::copy_from_slice(data), fin)?;
            }
            ControlFrame::Capabilities(_)
            | ControlFrame::Open(_)
            | ControlFrame::Status(_)
            | ControlFrame::EarlyOpen { .. } => return Err(FlowTaskError::UnexpectedControl),
        }
        Ok(())
    }

    fn take_outbound(&self) -> Option<Outbound> {
        lock(&self.state.0).outbound.pop_front()
    }

    fn process_outbound(&mut self, cx: &mut Context<'_>) -> Result<bool, FlowTaskError> {
        if self.datagram_enabled && !self.recovery.datagram_enabled() {
            self.datagram_enabled = false;
        }
        let Some(mut outbound) = self.take_outbound() else {
            return Ok(false);
        };
        let peer_max_offset = lock(&self.state.0).peer_max_offset;
        if outbound.offset >= peer_max_offset {
            lock(&self.state.0).outbound.push_front(outbound);
            return Ok(false);
        }
        let credit = usize::try_from(peer_max_offset - outbound.offset).unwrap_or(usize::MAX);
        let max_source_payload = self.recovery.max_source_payload();
        if self.datagram_enabled && max_source_payload == 0 {
            if self.recovery.adaptive_required() {
                return Err(FlowTaskError::Datagram(noq::SendDatagramError::TooLarge));
            }
            self.datagram_enabled = false;
        }
        let payload_limit = if self.datagram_enabled {
            max_source_payload
        } else {
            self.recovery.max_stream_payload()
        };
        let send_length = payload_limit.min(credit).min(outbound.bytes.len());
        if outbound.bytes.len() > send_length {
            let remaining_offset = outbound
                .offset
                .checked_add(u64::try_from(send_length).expect("source payload fits u64"))
                .ok_or(RecoveryError::OffsetOverflow)?;
            let mut state = lock(&self.state.0);
            if state.retained_chunks >= state.replay_chunk_limit {
                state.outbound.push_front(outbound);
                return Ok(false);
            }
            let remaining = outbound.bytes.split_off(send_length);
            state.retained_chunks += 1;
            state.outbound.push_front(Outbound {
                offset: remaining_offset,
                bytes: remaining,
            });
        }
        let end = outbound
            .offset
            .checked_add(u64::try_from(outbound.bytes.len()).expect("bounded flow chunk fits u64"))
            .ok_or(RecoveryError::OffsetOverflow)?;
        let flushed_to_backend = if self.datagram_enabled {
            match self.recovery.send_source(
                u64::from(self.send.id()),
                outbound.offset,
                &outbound.bytes,
                false,
                cx.waker(),
            ) {
                Ok(true) => {
                    self.replay.retain(outbound.offset, outbound.bytes)?;
                    self.arm_replay_timer();
                    true
                }
                Ok(false) => {
                    lock(&self.state.0).outbound.push_front(outbound);
                    return Ok(false);
                }
                Err(
                    error @ (noq::SendDatagramError::UnsupportedByPeer
                    | noq::SendDatagramError::Disabled
                    | noq::SendDatagramError::TooLarge),
                ) => {
                    if self.recovery.adaptive_required() {
                        return Err(FlowTaskError::Datagram(error));
                    }
                    self.datagram_enabled = false;
                    self.replay
                        .retain(outbound.offset, outbound.bytes.clone())?;
                    self.queue_stream_data(outbound.offset, &outbound.bytes, false, end);
                    self.recovery.record_fallback();
                    false
                }
                Err(noq::SendDatagramError::ConnectionLost(error)) => {
                    return Err(FlowTaskError::Connection(error));
                }
            }
        } else {
            self.replay
                .retain(outbound.offset, outbound.bytes.clone())?;
            self.queue_stream_data(outbound.offset, &outbound.bytes, false, end);
            self.recovery.record_fallback();
            false
        };
        if flushed_to_backend {
            let mut state = lock(&self.state.0);
            if state.flush_target.is_some_and(|target| end >= target) && state.outbound.is_empty() {
                state.flushed_offset = end;
                wake(&mut state.write_waker);
            }
        }
        Ok(true)
    }

    fn queue_stream_data(&mut self, offset: u64, data: &[u8], fin: bool, flushed_offset: u64) {
        let mut encoded = Vec::new();
        encode_control(
            &ControlFrame::StreamData { offset, fin, data },
            &mut encoded,
        );
        self.wire_queue
            .push_back((Bytes::from(encoded), Some(flushed_offset), None));
    }

    fn arm_replay_timer(&mut self) {
        if self.replay_timer.is_none() {
            self.replay_timer = Some(
                self.recovery
                    .new_timer(self.recovery.now() + self.recovery.replay_delay()),
            );
        }
    }

    fn restart_replay_timer(&mut self) {
        let deadline = self.recovery.now() + self.recovery.replay_delay();
        if let Some(timer) = self.replay_timer.as_mut() {
            timer.as_mut().reset(deadline);
        } else if self.replay.bytes() != 0 && self.datagram_enabled {
            self.replay_timer = Some(self.recovery.new_timer(deadline));
        }
    }

    fn poll_replay(&mut self, cx: &mut Context<'_>) -> Result<bool, FlowTaskError> {
        if self.datagram_enabled && !self.recovery.datagram_enabled() {
            self.datagram_enabled = false;
        }
        let Some(timer) = self.replay_timer.as_mut() else {
            return Ok(false);
        };
        if timer.as_mut().poll(cx).is_pending() {
            return Ok(false);
        }
        if self.replay.bytes() == 0 {
            self.replay_timer = None;
            self.replay_stage = ReplayStage::Repair;
            self.replay_cursor = None;
            return Ok(true);
        }
        if self.replay_stage == ReplayStage::Repair && self.datagram_enabled {
            let outstanding = self.replay.len();
            let repair_budget = self.recovery.take_repair_budget(outstanding);
            if repair_budget == 0 {
                self.replay_stage = ReplayStage::SourceReplay;
                timer
                    .as_mut()
                    .reset(self.recovery.now() + self.recovery.replay_delay());
                return Ok(true);
            }
            match self.recovery.send_tail_repairs(repair_budget, cx.waker()) {
                Ok(sent) if sent != 0 => {
                    self.replay_stage = ReplayStage::SourceReplay;
                    timer
                        .as_mut()
                        .reset(self.recovery.now() + self.recovery.replay_delay());
                    return Ok(true);
                }
                Ok(_) => {}
                Err(
                    _error @ (noq::SendDatagramError::UnsupportedByPeer
                    | noq::SendDatagramError::Disabled
                    | noq::SendDatagramError::TooLarge),
                ) if !self.recovery.adaptive_required() => {
                    self.datagram_enabled = false;
                }
                Err(error) => return Err(FlowTaskError::Datagram(error)),
            }
        }
        if self.replay_stage != ReplayStage::ReliableFallback && self.datagram_enabled {
            if let Some((offset, bytes)) = self.replay.next_chunk_after(self.replay_cursor) {
                if !self
                    .recovery
                    .send_source(u64::from(self.send.id()), offset, &bytes, false, cx.waker())
                    .map_err(FlowTaskError::Datagram)?
                {
                    return Ok(false);
                }
                self.recovery.record_replay();
                self.replay_cursor = Some(offset);
                return Ok(true);
            }
            self.replay_stage = ReplayStage::ReliableFallback;
            self.replay_cursor = None;
            timer
                .as_mut()
                .reset(self.recovery.now() + self.recovery.replay_delay());
            return Ok(true);
        }
        if self.wire_current.is_some() || !self.wire_queue.is_empty() {
            return Ok(false);
        }
        if let Some((offset, bytes)) = self.replay.next_chunk_after(self.replay_cursor) {
            let end = offset
                .checked_add(u64::try_from(bytes.len()).expect("bounded replay chunk fits u64"))
                .ok_or(RecoveryError::OffsetOverflow)?;
            self.queue_stream_data(offset, &bytes, false, end);
            self.recovery.record_fallback();
            self.replay_cursor = Some(offset);
            return Ok(true);
        }
        self.datagram_enabled = false;
        self.replay_stage = ReplayStage::Repair;
        self.replay_cursor = None;
        self.replay_timer = None;
        Ok(true)
    }

    fn poll_wire(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), FlowTaskError>> {
        loop {
            if self.wire_current.is_none() {
                self.wire_current = self.wire_queue.pop_front();
                if self.wire_current.is_none() {
                    if let Some((contiguous, ranges)) = self.pending_ack.take() {
                        let mut encoded = Vec::new();
                        encode_control(&ControlFrame::Ack { contiguous, ranges }, &mut encoded);
                        self.wire_queue
                            .push_back((Bytes::from(encoded), None, Some(contiguous)));
                    } else if let Some(maximum) = self.pending_credit.take() {
                        self.queue_control(&ControlFrame::MaxOffset(maximum));
                    }
                    self.wire_current = self.wire_queue.pop_front();
                }
            }
            let Some((current, _, _)) = self.wire_current.as_mut() else {
                return Poll::Ready(Ok(()));
            };
            let before = current.len();
            let result = {
                let chunks = std::slice::from_mut(current);
                let mut chunks = chunks;
                let future = self.send.write_many_chunks(&mut chunks);
                let mut future = std::pin::pin!(future);
                future.as_mut().poll(cx)
            };
            match result {
                Poll::Ready(Ok(written)) if written != 0 => {
                    if written == before {
                        let (_, flushed_offset, acked_offset) =
                            self.wire_current.take().expect("current frame");
                        if let Some(flushed_offset) = flushed_offset {
                            let mut state = lock(&self.state.0);
                            state.flushed_offset = state.flushed_offset.max(flushed_offset);
                            wake(&mut state.write_waker);
                        }
                        if let Some(acked_offset) = acked_offset {
                            lock(&self.state.0)
                                .receive
                                .acknowledge_consumed(acked_offset);
                            self.acked_receive_offset = self.acked_receive_offset.max(acked_offset);
                        }
                    }
                }
                Poll::Ready(Ok(_)) => return Poll::Ready(Err(FlowTaskError::WriteZero)),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(FlowTaskError::Write(error))),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn queue_terminal_frames(&mut self) {
        let shutdown = lock(&self.state.0).shutdown_target;
        if let Some(final_offset) = shutdown
            && !self.fin_queued
            && lock(&self.state.0).outbound.is_empty()
        {
            if self.replay.bytes() == 0 {
                self.queue_control(&ControlFrame::Fin(final_offset));
                self.fin_queued = true;
            } else if self.datagram_enabled {
                self.arm_replay_timer();
            }
        }
    }

    fn finish_send_if_ready(&mut self) -> Result<(), FlowTaskError> {
        if self.fin_queued
            && self.wire_current.is_none()
            && self.wire_queue.is_empty()
            && self.pending_ack.is_none()
            && self.pending_credit.is_none()
        {
            let mut state = lock(&self.state.0);
            if !state.shutdown_done {
                state.shutdown_done = true;
                wake(&mut state.write_waker);
            }
            if !self.send_finished && final_ack_written(&state, self.acked_receive_offset) {
                drop(state);
                self.send.finish().map_err(FlowTaskError::Finish)?;
                self.send_finished = true;
            }
        }
        Ok(())
    }

    fn fail_task(&mut self, error: FlowTaskError) {
        if error.is_protocol_violation() {
            let code = backend_error_code(ApplicationError::FlowProtocol);
            let _ = self.send.reset(code);
            let _ = self.recv.stop(code);
        }
        let kind = if matches!(error, FlowTaskError::PeerReset(_)) {
            io::ErrorKind::ConnectionReset
        } else {
            io::ErrorKind::ConnectionAborted
        };
        self.state.fail_with_kind(kind, error);
    }
}

fn control_input_limit(max_stream_payload: usize, max_ack_ranges: usize) -> usize {
    max_stream_payload
        .saturating_add(16)
        .max(max_ack_ranges.saturating_mul(16).saturating_add(16))
}

fn final_ack_written(state: &FlowShared, acked_receive_offset: u64) -> bool {
    state.receive_final_offset.is_some_and(|final_offset| {
        state.received.contiguous() == final_offset && acked_receive_offset >= final_offset
    }) && state.ack_pending == 0
}

impl Future for FlowTask {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let (reset, handle_dropped) = {
            let mut state = lock(&self.state.0);
            if state
                .task_waker
                .as_ref()
                .is_none_or(|registered| !registered.will_wake(cx.waker()))
            {
                state.task_waker = Some(cx.waker().clone());
            }
            (state.reset.take(), state.handle_dropped)
        };
        if let Some(code) = reset {
            let code = noq::VarInt::from_u64(code).expect("application error code is bounded");
            let _ = self.send.reset(code);
            let _ = self.recv.stop(code);
            return Poll::Ready(());
        }
        if handle_dropped {
            return Poll::Ready(());
        }
        let mut made_progress = false;
        for turn in 0..FLOW_TASK_TURN_BUDGET {
            match self.poll_receive(cx) {
                Poll::Ready(Ok(())) => made_progress = true,
                Poll::Ready(Err(error)) => {
                    self.fail_task(error);
                    return Poll::Ready(());
                }
                Poll::Pending => {}
            }
            self.queue_pending_feedback(cx);
            match self.process_outbound(cx) {
                Ok(progress) => made_progress |= progress,
                Err(error) => {
                    self.fail_task(error);
                    return Poll::Ready(());
                }
            }
            match self.poll_replay(cx) {
                Ok(progress) => made_progress |= progress,
                Err(error) => {
                    self.fail_task(error);
                    return Poll::Ready(());
                }
            }
            self.queue_terminal_frames();
            match self.poll_wire(cx) {
                Poll::Ready(Ok(())) | Poll::Pending => {}
                Poll::Ready(Err(error)) => {
                    self.fail_task(error);
                    return Poll::Ready(());
                }
            }
            if let Err(error) = self.finish_send_if_ready() {
                self.fail_task(error);
                return Poll::Ready(());
            }
            if !made_progress {
                break;
            }
            if turn + 1 == FLOW_TASK_TURN_BUDGET {
                cx.waker().wake_by_ref();
            }
            made_progress = false;
        }
        Poll::Pending
    }
}

impl Drop for FlowTask {
    fn drop(&mut self) {
        self.state.discard_retained();
        if self.recovery.runtime_stopped() {
            self.state.fail("QUICP host runtime stopped");
        }
        self.state.mark_task_stopped();
        self.recovery.unregister_flow(u64::from(self.send.id()));
    }
}

#[derive(Debug, Error)]
enum FlowTaskError {
    #[error("invalid QUICP control frame: {0}")]
    Codec(CodecError),
    #[error("QUICP control stream finished before FIN")]
    FinishedEarly,
    #[error("QUICP control frame exceeds the negotiated limit")]
    ControlLimit,
    #[error("unexpected post-admission QUICP control frame")]
    UnexpectedControl,
    #[error(
        "peer reset QUICP flow with {error:?} ({code})",
        error = .0,
        code = .0.code()
    )]
    PeerReset(ApplicationError),
    #[error("reading QUICP control stream: {0}")]
    Read(noq::ReadError),
    #[error("writing QUICP control stream: {0}")]
    Write(noq::WriteError),
    #[error("finishing QUICP control stream: {0}")]
    Finish(noq::ClosedStream),
    #[error("QUICP control stream accepted zero bytes")]
    WriteZero,
    #[error("QUICP DATAGRAM failed: {0}")]
    Datagram(noq::SendDatagramError),
    #[error("QUICP connection failed: {0}")]
    Connection(noq::ConnectionError),
    #[error(transparent)]
    Recovery(#[from] RecoveryError),
}

impl FlowTaskError {
    fn is_protocol_violation(&self) -> bool {
        matches!(
            self,
            Self::Codec(_)
                | Self::FinishedEarly
                | Self::ControlLimit
                | Self::UnexpectedControl
                | Self::Recovery(
                    RecoveryError::OffsetOverflow
                        | RecoveryError::InvalidRange
                        | RecoveryError::RangeCapacity
                        | RecoveryError::FlowControl
                        | RecoveryError::ContradictoryOverlap
                        | RecoveryError::FinalOffset
                )
        )
    }
}

fn wake(waker: &mut Option<Waker>) {
    if let Some(waker) = waker.take() {
        waker.wake();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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
    recovery: Arc<ConnectionRecovery>,
    initial: Bytes,
    initial_charge: Option<RecoveryCharge>,
}

impl PendingFlow {
    #[cfg(all(
        test,
        feature = "runtime-tokio",
        any(target_os = "linux", target_os = "macos", windows)
    ))]
    pub(crate) fn flow_id_for_test(&self) -> u64 {
        u64::from(self.send.id())
    }

    #[must_use]
    /// Returns the validated OPEN request awaiting a server decision.
    pub const fn request(&self) -> &OpenRequest {
        &self.request
    }

    /// Returns replay-safe initial bytes received with `EARLY_OPEN`.
    #[must_use]
    pub fn initial_data(&self) -> &[u8] {
        &self.initial
    }

    /// Sends `STATUS(ok)` and promotes this flow to a byte stream.
    ///
    /// # Errors
    ///
    /// Returns an error when initial bytes cannot be committed within the recovery budget or the
    /// status cannot be delivered.
    pub async fn accept(mut self) -> Result<QuicpFlow, FlowError> {
        let state = FlowState::new(
            self.recovery.config(),
            self.recovery.memory_budget(),
            self.recovery.max_ack_ranges(),
            0,
        );
        if !self.initial.is_empty() {
            let charge = self
                .initial_charge
                .take()
                .ok_or_else(|| FlowError::Accept(Box::new(RecoveryError::Capacity)))?;
            state
                .insert_bytes_precharged(0, std::mem::take(&mut self.initial), false, charge)
                .map_err(|error| FlowError::Accept(Box::new(error)))?;
        }
        write_control(
            &mut self.send,
            &ControlFrame::Capabilities(self.recovery.capabilities()),
        )
        .await?;
        write_control(&mut self.send, &ControlFrame::Status(OpenStatus::Ok)).await?;
        Ok(QuicpFlow::new_with_state(
            self.connection,
            self.lease,
            self.send,
            self.recv,
            self.flow_buffer_bytes,
            self.default_nodelay,
            &self.recovery,
            state,
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
        write_control(
            &mut self.send,
            &ControlFrame::Capabilities(self.recovery.capabilities()),
        )
        .await?;
        write_control(&mut self.send, &ControlFrame::Status(status)).await?;
        self.send
            .finish()
            .map_err(noq::WriteError::from)
            .map_err(|error| FlowError::Write(Box::new(error)))?;
        Ok(())
    }
}

pub(crate) async fn accept_flow_backend(
    connection: &noq::Connection,
    current_policy_authorized: bool,
    lease: Option<Arc<ConnectionPermit>>,
    flow_buffer_bytes: usize,
    default_nodelay: bool,
    recovery: Arc<ConnectionRecovery>,
) -> Result<PendingFlow, FlowError> {
    connection
        .authenticated()
        .await
        .map_err(|error| FlowError::Accept(Box::new(error)))?;
    admit_negotiated(connection, current_policy_authorized)?;
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|error| FlowError::Accept(Box::new(error)))?;
    let admission = async {
        match read_admission_control(&mut recv, recovery.max_ack_ranges()).await? {
            ControlFrame::Capabilities(capabilities)
                if recovery.negotiate_capabilities(capabilities) => {}
            _ => return Err(FlowError::Session(SessionError::InvalidState)),
        }
        match read_admission_control(&mut recv, recovery.max_ack_ranges()).await? {
            ControlFrame::Open(request) => Ok(request),
            _ => Err(FlowError::Session(SessionError::InvalidState)),
        }
    };
    let request = match admission.await {
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
        recovery,
        initial: Bytes::new(),
        initial_charge: None,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn accept_replay_safe_backend<F>(
    connection: &noq::Connection,
    admission: &ReplayAdmission,
    now_seconds: F,
    current_policy_authorized: bool,
    lease: Option<Arc<ConnectionPermit>>,
    flow_buffer_bytes: usize,
    default_nodelay: bool,
    recovery: Arc<ConnectionRecovery>,
) -> Result<PendingFlow, FlowError>
where
    F: FnOnce() -> u64 + Send,
{
    if !current_policy_authorized {
        return Err(FlowError::Session(SessionError::PolicyRejected));
    }
    let (send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|error| FlowError::Accept(Box::new(error)))?;
    match read_admission_control(&mut recv, recovery.max_ack_ranges()).await? {
        ControlFrame::Capabilities(capabilities)
            if recovery.negotiate_capabilities(capabilities) => {}
        _ => return Err(FlowError::Session(SessionError::InvalidState)),
    }
    let opening =
        read_open_control(&mut recv, recovery.max_ack_ranges(), flow_buffer_bytes).await?;
    let (request, initial, initial_charge) = match opening {
        Opening::Ordinary(request) => {
            connection
                .authenticated()
                .await
                .map_err(|error| FlowError::Accept(Box::new(error)))?;
            (request, Bytes::new(), None)
        }
        Opening::Early(early) => {
            if early.initial.len() > flow_buffer_bytes {
                recovery.record_early_rejected();
                return Err(FlowError::Session(SessionError::InvalidState));
            }
            let token = ReplayToken::from_bytes(&early.token).inspect_err(|_| {
                recovery.record_early_rejected();
            })?;
            let capabilities = recovery.capability_fingerprint().ok_or_else(|| {
                recovery.record_early_rejected();
                FlowError::Session(SessionError::InvalidState)
            })?;
            if let Err(error) = admit_negotiated(connection, current_policy_authorized) {
                match error {
                    SessionError::PeerUnauthenticated => {
                        connection.authenticated().await.map_err(|error| {
                            recovery.record_early_rejected();
                            FlowError::Accept(Box::new(error))
                        })?;
                        admit_negotiated(connection, current_policy_authorized).inspect_err(
                            |_| {
                                recovery.record_early_rejected();
                            },
                        )?;
                    }
                    error => {
                        recovery.record_early_rejected();
                        return Err(error.into());
                    }
                }
            }
            let charge = RecoveryCharge::reserve(recovery.memory_budget(), early.initial.len())
                .inspect_err(|_| recovery.record_early_rejected())
                .map_err(|error| FlowError::Accept(Box::new(error)))?;
            admission
                .admit(&token, early.nonce, now_seconds(), capabilities)
                .inspect_err(|_| {
                    recovery.record_early_rejected();
                })?;
            recovery.record_early_accepted();
            (early.request, early.initial, Some(charge))
        }
    };
    Ok(PendingFlow {
        connection: connection.clone(),
        lease,
        request,
        send,
        recv,
        flow_buffer_bytes,
        default_nodelay,
        recovery,
        initial,
        initial_charge,
    })
}

async fn write_control(
    send: &mut noq::SendStream,
    frame: &ControlFrame<'_>,
) -> Result<(), FlowError> {
    let mut encoded = Vec::with_capacity(MAX_OPEN_FRAME_BYTES + 16);
    encode_control(frame, &mut encoded);
    send.write_all(&encoded)
        .await
        .map_err(|error| FlowError::Write(Box::new(error)))
}

async fn read_admission_control(
    recv: &mut noq::RecvStream,
    max_ack_ranges: usize,
) -> Result<ControlFrame<'static>, FlowError> {
    let encoded = read_control_bytes(recv, MAX_OPEN_FRAME_BYTES + 16).await?;
    let (frame, consumed) = decode_control(&encoded, max_ack_ranges)
        .map_err(|_| FlowError::Session(SessionError::InvalidState))?;
    debug_assert_eq!(consumed, encoded.len());
    match frame {
        ControlFrame::Capabilities(value) => Ok(ControlFrame::Capabilities(value)),
        ControlFrame::Open(value) => Ok(ControlFrame::Open(value)),
        ControlFrame::Status(value) => Ok(ControlFrame::Status(value)),
        _ => Err(FlowError::Session(SessionError::InvalidState)),
    }
}

struct EarlyOpenOwned {
    token: Vec<u8>,
    nonce: u64,
    request: OpenRequest,
    initial: Bytes,
}

enum Opening {
    Ordinary(OpenRequest),
    Early(EarlyOpenOwned),
}

async fn read_open_control(
    recv: &mut noq::RecvStream,
    max_ack_ranges: usize,
    flow_buffer_bytes: usize,
) -> Result<Opening, FlowError> {
    let max_frame_bytes = early_open_frame_limit(flow_buffer_bytes)
        .ok_or(FlowError::Session(SessionError::InvalidState))?;
    let encoded = read_control_bytes(recv, max_frame_bytes).await?;
    let (frame, consumed) = decode_control(&encoded, max_ack_ranges)
        .map_err(|_| FlowError::Session(SessionError::InvalidState))?;
    if consumed != encoded.len() {
        return Err(FlowError::Session(SessionError::InvalidState));
    }
    match frame {
        ControlFrame::Open(request) => Ok(Opening::Ordinary(request)),
        ControlFrame::EarlyOpen {
            token,
            nonce,
            request,
            initial,
        } => Ok(Opening::Early(EarlyOpenOwned {
            token: token.to_vec(),
            nonce,
            request,
            initial: Bytes::copy_from_slice(initial),
        })),
        _ => Err(FlowError::Session(SessionError::InvalidState)),
    }
}

fn early_open_frame_limit(flow_buffer_bytes: usize) -> Option<usize> {
    flow_buffer_bytes.checked_add(MAX_EARLY_OPEN_OVERHEAD)
}

async fn read_control_bytes(
    recv: &mut noq::RecvStream,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, FlowError> {
    let mut prefix = [0u8; 9];
    recv.read_exact(&mut prefix[..2])
        .await
        .map_err(|error| FlowError::Read(Box::new(error)))?;
    let length_bytes = 1usize << usize::from(prefix[1] >> 6);
    let header = 1 + length_bytes;
    if length_bytes > 1 {
        recv.read_exact(&mut prefix[2..header])
            .await
            .map_err(|error| FlowError::Read(Box::new(error)))?;
    }
    let mut length = u64::from(prefix[1] & 0x3f);
    for byte in &prefix[2..header] {
        length = (length << 8) | u64::from(*byte);
    }
    let length =
        usize::try_from(length).map_err(|_| FlowError::Session(SessionError::InvalidState))?;
    let total = header
        .checked_add(length)
        .filter(|total| *total <= max_frame_bytes)
        .ok_or(FlowError::Session(SessionError::InvalidState))?;
    let mut encoded = vec![0; total];
    encoded[..header].copy_from_slice(&prefix[..header]);
    recv.read_exact(&mut encoded[header..])
        .await
        .map_err(|error| FlowError::Read(Box::new(error)))?;
    Ok(encoded)
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
    /// A replay-safe attempt failed token or replay admission.
    #[error(transparent)]
    Replay(#[from] crate::ReplayTokenError),
}

#[cfg(test)]
mod state_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn test_state() -> Arc<FlowState> {
        let recovery = crate::config::RecoveryConfig::default();
        FlowState::new(
            recovery,
            Arc::new(RecoveryMemoryBudget::new(u32::MAX)),
            usize::from(recovery.max_ack_ranges),
            0,
        )
    }

    #[test]
    fn full_delayed_buffer_is_enqueued_by_the_completing_write() {
        let state = test_state();
        let mut send_buffer = BytesMut::new();
        let mut cx = Context::from_waker(Waker::noop());

        {
            let mut shared = lock(&state.0);
            shared.retained_bytes = shared.replay_limit;
        }
        assert!(matches!(
            poll_buffered_write(&mut send_buffer, false, 4, &state, &mut cx, b"full"),
            Poll::Pending
        ));
        assert!(send_buffer.is_empty());
        lock(&state.0).retained_bytes = 0;

        assert!(matches!(
            poll_buffered_write(&mut send_buffer, false, 4, &state, &mut cx, b"full"),
            Poll::Ready(Ok(4))
        ));
        assert!(send_buffer.is_empty());
        assert_eq!(
            lock(&state.0).outbound.front().unwrap().bytes,
            Bytes::from_static(b"full")
        );
    }

    #[test]
    fn nodelay_write_surfaces_known_terminal_states() {
        let mut cx = Context::from_waker(Waker::noop());

        let reset = test_state();
        assert!(reset.request_reset(ApplicationError::FlowAbort));
        let mut reset_buffer = BytesMut::new();
        let Poll::Ready(Err(error)) =
            poll_buffered_write(&mut reset_buffer, true, 4, &reset, &mut cx, b"x")
        else {
            panic!("reset write succeeded");
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);

        let shutdown = test_state();
        assert!(matches!(
            shutdown.request_shutdown(Waker::noop()),
            Ok(false)
        ));
        let mut shutdown_buffer = BytesMut::new();
        let Poll::Ready(Err(error)) =
            poll_buffered_write(&mut shutdown_buffer, true, 4, &shutdown, &mut cx, b"x")
        else {
            panic!("shutdown write succeeded");
        };
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);

        let failed = test_state();
        failed.fail("task failed");
        let mut failed_buffer = BytesMut::new();
        let Poll::Ready(Err(error)) =
            poll_buffered_write(&mut failed_buffer, true, 4, &failed, &mut cx, b"x")
        else {
            panic!("failed-task write succeeded");
        };
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[test]
    fn crossed_fin_gap_waits_for_contiguous_data_and_written_ack() {
        let state = test_state();
        state
            .insert_bytes(4, Bytes::from_static(b"tail"), false)
            .unwrap();
        state.set_final_offset(8).unwrap();
        lock(&state.0).ack_pending = 0;
        assert!(!final_ack_written(&lock(&state.0), 8));

        state
            .insert_bytes(0, Bytes::from_static(b"head"), false)
            .unwrap();
        assert!(!final_ack_written(&lock(&state.0), 8));
        lock(&state.0).ack_pending = 0;
        assert!(final_ack_written(&lock(&state.0), 8));
    }

    #[test]
    fn control_limit_uses_negotiated_payload_not_local_write_buffer() {
        let peer_stream_payload = 4096;
        let limit = control_input_limit(peer_stream_payload, 32);
        let mut stream = Vec::new();
        encode_control(
            &ControlFrame::StreamData {
                offset: MAX_WIRE_OFFSET,
                fin: false,
                data: &vec![0; peer_stream_payload],
            },
            &mut stream,
        );
        assert!(stream.len() <= limit);
        assert!(limit > 64, "a smaller local write buffer is irrelevant");

        let mut ack = Vec::new();
        let base = MAX_WIRE_OFFSET - 65;
        let ranges = (0..32)
            .map(|index| {
                let start = base + index * 2 + 1;
                core::ops::Range {
                    start,
                    end: start + 1,
                }
            })
            .collect::<Vec<_>>();
        encode_control(
            &ControlFrame::Ack {
                contiguous: base,
                ranges,
            },
            &mut ack,
        );
        assert!(ack.len() <= control_input_limit(1, 32));
    }

    #[test]
    fn reset_is_terminal_and_discards_pending_writes() {
        let recovery = crate::config::RecoveryConfig::default();
        let state = FlowState::new(
            recovery,
            Arc::new(RecoveryMemoryBudget::new(u32::MAX)),
            usize::from(recovery.max_ack_ranges),
            0,
        );
        let waker = Waker::noop();
        assert!(
            state
                .enqueue(&Bytes::from_static(b"pending"), waker)
                .unwrap()
                .is_some()
        );
        assert!(state.request_reset(ApplicationError::FlowAbort));
        let shared = lock(&state.0);
        assert!(shared.outbound.is_empty());
        assert_eq!(shared.retained_bytes, 0);
        assert_eq!(shared.retained_chunks, 0);
        drop(shared);
        assert_eq!(
            state
                .enqueue(&Bytes::from_static(b"later"), waker)
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionAborted
        );
    }

    #[test]
    fn stopped_task_rejects_a_new_reset_request() {
        let state = test_state();
        state.mark_task_stopped();
        assert!(!state.request_reset(ApplicationError::FlowAbort));
    }

    #[test]
    fn rejected_source_does_not_partially_mutate_reassembly() {
        let recovery = crate::config::RecoveryConfig::default();
        let state = FlowState::new(
            recovery,
            Arc::new(RecoveryMemoryBudget::new(u32::MAX)),
            1,
            0,
        );
        state
            .insert_bytes(4, Bytes::from_static(b"a"), false)
            .unwrap();
        assert_eq!(
            state.insert_bytes(8, Bytes::from_static(b"b"), false),
            Err(RecoveryError::RangeCapacity)
        );
        let shared = lock(&state.0);
        assert_eq!(shared.receive.buffered_bytes(), 1);
        let ranges = shared.received.ranges();
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], 4..5);
    }

    #[test]
    fn source_wakes_ack_task_only_for_timer_and_threshold() {
        let recovery = crate::config::RecoveryConfig::default();
        let state = FlowState::new(
            recovery,
            Arc::new(RecoveryMemoryBudget::new(u32::MAX)),
            usize::from(recovery.max_ack_ranges),
            0,
        );
        let wake_counter = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wake_counter));
        lock(&state.0).task_waker = Some(waker.clone());
        state
            .insert_bytes(0, Bytes::from_static(b"a"), false)
            .unwrap();
        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 1);

        lock(&state.0).task_waker = Some(waker);
        for offset in 1..u64::from(LOGICAL_ACK_THRESHOLD) {
            state
                .insert_bytes(offset, Bytes::from_static(b"a"), false)
                .unwrap();
        }
        assert_eq!(wake_counter.0.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn flow_bounds_retained_record_metadata() {
        let recovery = crate::config::RecoveryConfig {
            replay_buffer_bytes: 512,
            ..crate::config::RecoveryConfig::default()
        };
        let state = FlowState::new(
            recovery,
            Arc::new(RecoveryMemoryBudget::new(u32::MAX)),
            usize::from(recovery.max_ack_ranges),
            0,
        );
        let waker = Waker::noop();
        for _ in 0..replay_chunk_limit(512) {
            assert!(
                state
                    .enqueue(&Bytes::from_static(b"x"), waker)
                    .unwrap()
                    .is_some()
            );
        }
        assert!(
            state
                .enqueue(&Bytes::from_static(b"x"), waker)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn final_offset_cannot_exceed_receive_credit() {
        let recovery = crate::config::RecoveryConfig::default();
        let state = FlowState::new(
            recovery,
            Arc::new(RecoveryMemoryBudget::new(u32::MAX)),
            usize::from(recovery.max_ack_ranges),
            0,
        );
        let maximum = lock(&state.0).max_receive_offset;
        assert_eq!(
            state.set_final_offset(maximum + 1),
            Err(RecoveryError::FlowControl)
        );
    }
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

#[cfg(test)]
mod tests {
    use super::{MAX_EARLY_OPEN_OVERHEAD, early_open_frame_limit};

    #[test]
    fn early_open_limit_is_bound_to_the_configured_flow_buffer() {
        assert_eq!(
            early_open_frame_limit(1024),
            Some(1024 + MAX_EARLY_OPEN_OVERHEAD)
        );
        assert_eq!(early_open_frame_limit(usize::MAX), None);
    }
}
