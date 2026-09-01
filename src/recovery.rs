//! Bounded logical ACK, replay, and ordered reassembly state for QUICP/2.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::mem::size_of;
use std::ops::{Bound, Range};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

use bytes::Bytes;
use thiserror::Error;

use crate::config::{RecoveryConfig, RecoveryMode};
use crate::fec::{Decoder, FecError, RecoveredBatch, SourceStatus, repair_symbol};
use crate::flow::FlowState;
use crate::wire::{
    Capabilities, MAX_WIRE_OFFSET, REPAIR_DATAGRAM, REPAIR_DATAGRAM_HEADER_BYTES, RepairDatagram,
    SOURCE_DATAGRAM, SOURCE_RECORD_MAX_OVERHEAD, SourceRecord, decode_repair, decode_source,
    decode_source_single, encode_repair, encode_source,
};

const PRE_OPEN_TTL: Duration = Duration::from_secs(1);
const DRIVER_SEND_BATCH: u8 = 32;
const MAX_SOURCE_RECORDS: usize = 32;

const fn repair_seed(first_symbol_id: u32) -> u32 {
    first_symbol_id
}

fn repair_budget(
    lost: u64,
    sent: u64,
    delivered: bool,
    replayed: bool,
    burst: u32,
    outstanding: usize,
    max_span: usize,
) -> usize {
    if lost == 0 {
        return 0;
    }
    let outstanding_u64 = u64::try_from(outstanding).unwrap_or(u64::MAX);
    let budget = lost
        .saturating_mul(outstanding_u64)
        .div_ceil(sent.max(1))
        .max(1)
        .saturating_add(u64::from(burst.saturating_sub(1).min(2)))
        .saturating_add(u64::from(!delivered))
        .saturating_add(u64::from(replayed));
    usize::try_from(budget)
        .unwrap_or(usize::MAX)
        .min(outstanding)
        .min(max_span)
}

const fn repair_span_is_negotiated(span: u16, max_span: u16) -> bool {
    span <= max_span
}

/// QUICP/2 recovery counters and gauges for one connection.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecoverySnapshot {
    /// Source DATAGRAMs sent by the backend.
    pub source_sent: u64,
    /// Valid source DATAGRAMs received from the peer.
    pub source_received: u64,
    /// Repair DATAGRAMs sent by the backend.
    pub repair_sent: u64,
    /// Source symbols reconstructed from repair DATAGRAMs.
    pub recovered: u64,
    /// Source records retransmitted after a logical ACK timeout.
    pub replayed: u64,
    /// Source records moved to reliable `STREAM_DATA` fallback.
    pub fallback: u64,
    /// Malformed, over-limit, or unrouteable DATAGRAMs dropped before delivery.
    pub dropped: u64,
    /// Replay-safe early opens admitted before application exposure.
    pub early_accepted: u64,
    /// Replay-safe early opens rejected before application exposure.
    pub early_rejected: u64,
    /// Latest sampled aggregate packets lost on the outbound QUIC paths.
    pub path_lost_packets: u64,
    /// Largest RTT in the latest bounded primary/backup sample, in microseconds.
    pub max_path_rtt_micros: u64,
    /// DATAGRAMs waiting for backend send capacity.
    pub queued_datagrams: u64,
    /// Bytes retained in the bounded source coding window.
    pub retained_source_bytes: u64,
}

#[derive(Debug, Default)]
struct RecoveryCounters {
    source_sent: AtomicU64,
    source_received: AtomicU64,
    repair_sent: AtomicU64,
    recovered: AtomicU64,
    replayed: AtomicU64,
    fallback: AtomicU64,
    dropped: AtomicU64,
    early_accepted: AtomicU64,
    early_rejected: AtomicU64,
}

#[derive(Debug)]
pub(crate) struct RecoveryMemoryBudget {
    used: AtomicU64,
    limit: u64,
}

impl RecoveryMemoryBudget {
    pub(crate) const fn new(limit: u32) -> Self {
        Self {
            used: AtomicU64::new(0),
            limit: limit as u64,
        }
    }

    pub(crate) fn try_reserve(&self, bytes: usize) -> bool {
        let Ok(bytes) = u64::try_from(bytes) else {
            return false;
        };
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let Some(next) = used.checked_add(bytes).filter(|next| *next <= self.limit) else {
                return false;
            };
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(observed) => used = observed,
            }
        }
    }

    pub(crate) fn release(&self, bytes: usize) {
        let bytes = u64::try_from(bytes).expect("reserved byte count fits u64");
        let previous = self.used.fetch_sub(bytes, Ordering::AcqRel);
        debug_assert!(previous >= bytes);
    }

    #[cfg(test)]
    pub(crate) fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub(crate) struct RecoveryCharge {
    budget: Arc<RecoveryMemoryBudget>,
    bytes: usize,
}

impl RecoveryCharge {
    pub(crate) fn reserve(
        budget: Arc<RecoveryMemoryBudget>,
        bytes: usize,
    ) -> Result<Self, RecoveryError> {
        if !budget.try_reserve(bytes) {
            return Err(RecoveryError::Capacity);
        }
        Ok(Self { budget, bytes })
    }

    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn belongs_to(&self, budget: &Arc<RecoveryMemoryBudget>) -> bool {
        Arc::ptr_eq(&self.budget, budget)
    }

    pub(crate) fn grow(&mut self, bytes: usize) -> Result<(), RecoveryError> {
        if bytes <= self.bytes {
            return Ok(());
        }
        let additional = bytes - self.bytes;
        if !self.budget.try_reserve(additional) {
            return Err(RecoveryError::Capacity);
        }
        self.bytes = bytes;
        Ok(())
    }

    pub(crate) fn shrink(&mut self, bytes: usize) {
        assert!(
            bytes <= self.bytes,
            "charge shrink cannot grow a reservation"
        );
        self.budget.release(self.bytes - bytes);
        self.bytes = bytes;
    }

    pub(crate) fn split(&mut self, bytes: usize) -> Result<Self, RecoveryError> {
        if bytes > self.bytes {
            return Err(RecoveryError::Capacity);
        }
        self.bytes -= bytes;
        Ok(Self {
            budget: Arc::clone(&self.budget),
            bytes,
        })
    }

    pub(crate) fn transfer(&mut self, bytes: usize) -> Result<(), RecoveryError> {
        if bytes > self.bytes {
            return Err(RecoveryError::Capacity);
        }
        self.bytes -= bytes;
        Ok(())
    }
}

impl Drop for RecoveryCharge {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
}

#[derive(Debug)]
struct PreOpenRecord {
    offset: u64,
    fin: bool,
    data: Bytes,
    charge: RecoveryCharge,
    expires_at: Instant,
}

#[derive(Debug)]
struct PendingSourceRecord {
    flow: Option<Arc<FlowState>>,
    flow_id: u64,
    offset: u64,
    fin: bool,
    data: Bytes,
    retained_bytes: usize,
    charge: Option<RecoveryCharge>,
}

#[derive(Debug)]
enum OutboundDatagram {
    Source { symbol_id: u32, bytes: Bytes },
    Repair(Bytes),
}

impl OutboundDatagram {
    fn bytes(&self) -> Bytes {
        match self {
            Self::Source { bytes, .. } | Self::Repair(bytes) => bytes.clone(),
        }
    }
}

#[derive(Debug)]
struct DatagramQueue {
    pending: VecDeque<OutboundDatagram>,
    capacity: usize,
    driver_waker: Option<Waker>,
    producer_waiters: VecDeque<Waker>,
}

struct DriverCloseGuard {
    backend: noq::Connection,
    armed: bool,
}

impl Drop for DriverCloseGuard {
    fn drop(&mut self) {
        if self.armed {
            self.backend
                .close(0u32.into(), b"QUICP DATAGRAM driver stopped");
        }
    }
}

enum DriverEvent {
    Received(Result<Bytes, noq::ConnectionError>),
    Sent(OutboundDatagram, Result<(), noq::SendDatagramError>),
    OwnerDropped,
}

type DatagramSendFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), noq::SendDatagramError>> + Send + 'a>>;

#[derive(Debug)]
pub(crate) struct ConnectionRecovery {
    backend: noq::Connection,
    runtime: Arc<dyn noq::Runtime>,
    runtime_shutdown: Option<Arc<AtomicBool>>,
    memory_budget: Arc<RecoveryMemoryBudget>,
    flows: Mutex<HashMap<u64, Weak<FlowState>>>,
    negotiated: OnceLock<Capabilities>,
    pre_open: Mutex<HashMap<u64, Vec<PreOpenRecord>>>,
    pre_open_count: AtomicU32,
    decoder: Mutex<Decoder>,
    sources: Mutex<VecDeque<(u32, Bytes)>>,
    datagrams: Mutex<DatagramQueue>,
    datagram_enabled: AtomicBool,
    config: RecoveryConfig,
    max_symbol_bytes: usize,
    next_symbol: AtomicU32,
    next_repair: AtomicU32,
    observed_lost_packets: AtomicU64,
    observed_tx_datagrams: AtomicU64,
    delivered_bytes: AtomicU64,
    observed_delivered_bytes: AtomicU64,
    observed_replays: AtomicU64,
    loss_burst: AtomicU32,
    sampled_path_lost_packets: AtomicU64,
    sampled_max_path_rtt_micros: AtomicU64,
    queued_datagrams: AtomicU32,
    retained_source_bytes: AtomicU64,
    counters: RecoveryCounters,
}

impl ConnectionRecovery {
    pub(crate) fn start(
        backend: noq::Connection,
        runtime: &Arc<dyn noq::Runtime>,
        runtime_shutdown: Option<Arc<AtomicBool>>,
        memory_budget: Arc<RecoveryMemoryBudget>,
        config: RecoveryConfig,
        max_symbol_bytes: usize,
    ) -> Arc<Self> {
        let state = Arc::new(Self {
            backend,
            runtime: Arc::clone(runtime),
            runtime_shutdown,
            memory_budget: Arc::clone(&memory_budget),
            flows: Mutex::new(HashMap::new()),
            negotiated: OnceLock::new(),
            pre_open: Mutex::new(HashMap::new()),
            pre_open_count: AtomicU32::new(0),
            decoder: Mutex::new(Decoder::with_budget(
                usize::from(config.decoder_window),
                usize::from(config.decoder_window),
                max_symbol_bytes,
                memory_budget,
            )),
            sources: Mutex::new(VecDeque::with_capacity(usize::from(config.max_repair_span))),
            datagrams: Mutex::new(DatagramQueue {
                pending: VecDeque::with_capacity(usize::from(config.decoder_window)),
                capacity: usize::from(config.decoder_window),
                driver_waker: None,
                producer_waiters: VecDeque::with_capacity(usize::from(config.decoder_window)),
            }),
            datagram_enabled: AtomicBool::new(config.mode == RecoveryMode::Adaptive),
            config,
            max_symbol_bytes,
            next_symbol: AtomicU32::new(0),
            next_repair: AtomicU32::new(0),
            observed_lost_packets: AtomicU64::new(0),
            observed_tx_datagrams: AtomicU64::new(0),
            delivered_bytes: AtomicU64::new(0),
            observed_delivered_bytes: AtomicU64::new(0),
            observed_replays: AtomicU64::new(0),
            loss_burst: AtomicU32::new(0),
            sampled_path_lost_packets: AtomicU64::new(0),
            sampled_max_path_rtt_micros: AtomicU64::new(0),
            queued_datagrams: AtomicU32::new(0),
            retained_source_bytes: AtomicU64::new(0),
            counters: RecoveryCounters::default(),
        });
        let driver = Arc::downgrade(&state);
        let backend = state.backend.clone();
        let budget = usize::from(state.config.work_budget);
        runtime.spawn(Box::pin(run_datagram_driver(driver, backend, budget)));
        state
    }

    pub(crate) fn runtime_stopped(&self) -> bool {
        self.runtime_shutdown
            .as_ref()
            .is_some_and(|stopped| stopped.load(Ordering::Acquire))
    }

    pub(crate) fn register_flow(&self, flow_id: u64, flow: &Arc<FlowState>) {
        let records = {
            let mut flows = lock(&self.flows);
            let mut pre_open = lock(&self.pre_open);
            flows.insert(flow_id, Arc::downgrade(flow));
            let records = pre_open.remove(&flow_id).unwrap_or_default();
            self.pre_open_count.fetch_sub(
                u32::try_from(records.len()).expect("pre-open capacity fits u32"),
                Ordering::Relaxed,
            );
            records
        };
        let now = self.now();
        for record in records {
            if record.expires_at <= now {
                self.drop_datagram();
                continue;
            }
            if let Err(error) =
                flow.insert_bytes_precharged(record.offset, record.data, record.fin, record.charge)
            {
                if !matches!(
                    error,
                    RecoveryError::Capacity | RecoveryError::RangeCapacity
                ) {
                    flow.reject_protocol();
                }
                self.drop_datagram();
            }
        }
    }

    pub(crate) fn unregister_flow(&self, flow_id: u64) {
        lock(&self.flows).remove(&flow_id);
    }

    #[cfg(all(
        test,
        feature = "runtime-tokio",
        any(target_os = "linux", target_os = "macos", windows)
    ))]
    pub(crate) fn registered_flow_count(&self) -> usize {
        lock(&self.flows).len()
    }

    #[cfg(all(
        test,
        feature = "runtime-tokio",
        any(target_os = "linux", target_os = "macos", windows)
    ))]
    pub(crate) fn receive_for_test(&self, datagram: &Bytes) {
        self.receive(datagram);
    }

    #[cfg(all(
        test,
        feature = "runtime-tokio",
        any(target_os = "linux", target_os = "macos", windows)
    ))]
    pub(crate) fn decoder_state_for_test(&self) -> (usize, usize) {
        lock(&self.decoder).state_counts()
    }

    #[cfg(all(
        test,
        feature = "runtime-tokio",
        any(target_os = "linux", target_os = "macos", windows)
    ))]
    pub(crate) fn memory_used_for_test(&self) -> u64 {
        self.memory_budget.used()
    }

    #[cfg(all(
        test,
        feature = "runtime-tokio",
        any(target_os = "linux", target_os = "macos", windows)
    ))]
    pub(crate) fn pre_open_data_pointer_for_test(&self, flow_id: u64) -> Option<usize> {
        lock(&self.pre_open)
            .get(&flow_id)
            .and_then(|records| records.first())
            .map(|record| record.data.as_ptr() as usize)
    }

    pub(crate) fn spawn(
        &self,
        future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    ) {
        self.runtime.spawn(future);
    }

    pub(crate) fn new_timer(
        &self,
        deadline: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn noq::AsyncTimer>> {
        self.runtime.new_timer(deadline)
    }

    pub(crate) fn now(&self) -> std::time::Instant {
        self.runtime.now()
    }

    pub(crate) fn config(&self) -> RecoveryConfig {
        self.config
    }

    pub(crate) fn memory_budget(&self) -> Arc<RecoveryMemoryBudget> {
        Arc::clone(&self.memory_budget)
    }

    pub(crate) fn capabilities(&self) -> Capabilities {
        Capabilities {
            max_symbol: u16::try_from(self.max_symbol_bytes.max(64))
                .expect("validated symbol size"),
            max_span: self.config.max_repair_span,
            decoder_window: self.config.decoder_window,
            max_ack_ranges: self.config.max_ack_ranges,
            ..Capabilities::local(self.config.mode == RecoveryMode::Adaptive)
        }
    }

    pub(crate) fn negotiate_capabilities(&self, peer: Capabilities) -> bool {
        let local = self.capabilities();
        let negotiated = local.intersect(peer);
        if self.config.require_adaptive && !negotiated.supports_adaptive() {
            return false;
        }
        let current = *self.negotiated.get_or_init(|| negotiated);
        if current != negotiated {
            return false;
        }
        if !current.supports_adaptive() {
            self.disable_datagrams();
        }
        true
    }

    fn active_capabilities(&self) -> Capabilities {
        self.negotiated
            .get()
            .copied()
            .unwrap_or_else(|| self.capabilities())
    }

    pub(crate) fn capability_fingerprint(&self) -> Option<u64> {
        self.negotiated.get().map(|capabilities| {
            (u64::from(capabilities.flags) << 56)
                | (u64::from(capabilities.max_symbol) << 40)
                | (u64::from(capabilities.max_span) << 24)
                | (u64::from(capabilities.decoder_window) << 8)
                | u64::from(capabilities.max_ack_ranges)
        })
    }

    pub(crate) fn max_ack_ranges(&self) -> usize {
        usize::from(self.active_capabilities().max_ack_ranges)
    }

    pub(crate) fn max_source_payload(&self) -> usize {
        let negotiated = usize::from(self.active_capabilities().max_symbol);
        self.backend
            .max_datagram_size()
            .map_or(self.max_symbol_bytes.min(negotiated), |maximum| {
                self.max_symbol_bytes
                    .min(negotiated)
                    .min(maximum.saturating_sub(REPAIR_DATAGRAM_HEADER_BYTES))
            })
            .saturating_sub(SOURCE_RECORD_MAX_OVERHEAD)
    }

    pub(crate) fn max_stream_payload(&self) -> usize {
        self.max_symbol_bytes
            .min(usize::from(self.active_capabilities().max_symbol))
            .saturating_sub(REPAIR_DATAGRAM_HEADER_BYTES)
            .saturating_sub(SOURCE_RECORD_MAX_OVERHEAD)
            .max(1)
    }

    pub(crate) fn adaptive_required(&self) -> bool {
        self.config.require_adaptive
    }

    pub(crate) fn datagram_enabled(&self) -> bool {
        self.datagram_enabled.load(Ordering::Acquire)
    }

    pub(crate) fn replay_delay(&self) -> Duration {
        let max_rtt = [noq::PathId::ZERO, noq::PathId::ZERO.saturating_add(1u32)]
            .into_iter()
            .filter_map(|path| self.backend.path_stats(path))
            .map(|stats| stats.rtt)
            .max();
        self.sampled_max_path_rtt_micros.store(
            max_rtt.map_or(0, |rtt| u64::try_from(rtt.as_micros()).unwrap_or(u64::MAX)),
            Ordering::Relaxed,
        );
        max_rtt.map_or(Duration::from_millis(50), |rtt| {
            rtt.saturating_mul(2).max(Duration::from_millis(50))
        })
    }

    pub(crate) fn take_repair_budget(&self, outstanding: usize) -> usize {
        let stats = self.backend.stats();
        let lost = stats.lost_packets;
        self.sampled_path_lost_packets
            .store(lost, Ordering::Relaxed);
        let previous = self.observed_lost_packets.swap(lost, Ordering::Relaxed);
        let lost = lost.saturating_sub(previous);
        let sent = stats.udp_tx.datagrams;
        let sent = sent.saturating_sub(self.observed_tx_datagrams.swap(sent, Ordering::Relaxed));
        let delivered = self.delivered_bytes.load(Ordering::Relaxed);
        let delivered = delivered.saturating_sub(
            self.observed_delivered_bytes
                .swap(delivered, Ordering::Relaxed),
        );
        let replayed = self.counters.replayed.load(Ordering::Relaxed);
        let replayed =
            replayed.saturating_sub(self.observed_replays.swap(replayed, Ordering::Relaxed));
        if lost == 0 {
            self.loss_burst.store(0, Ordering::Relaxed);
            return 0;
        }
        let burst = self
            .loss_burst
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        repair_budget(
            lost,
            sent,
            delivered != 0,
            replayed != 0,
            burst,
            outstanding,
            usize::from(self.active_capabilities().max_span),
        )
    }

    pub(crate) fn send_source(
        &self,
        flow_id: u64,
        offset: u64,
        data: &Bytes,
        fin: bool,
        waker: &Waker,
    ) -> Result<bool, noq::SendDatagramError> {
        if !self.datagram_enabled() {
            return Err(noq::SendDatagramError::Disabled);
        }
        let mut datagrams = lock(&self.datagrams);
        if !self.datagram_enabled() {
            return Err(noq::SendDatagramError::Disabled);
        }
        if datagrams.pending.len() == datagrams.capacity {
            register_producer(&mut datagrams, waker);
            return Ok(false);
        }
        let symbol_id = self.next_symbol.fetch_add(1, Ordering::Relaxed);
        let record = SourceRecord {
            flow_id,
            offset,
            fin,
            data,
        };
        let mut encoded = Vec::with_capacity(data.len().saturating_add(24));
        encode_source(symbol_id, &[record], &mut encoded).expect("validated source record");
        datagrams.pending.push_back(OutboundDatagram::Source {
            symbol_id,
            bytes: Bytes::from(encoded),
        });
        self.queued_datagrams.fetch_add(1, Ordering::Relaxed);
        wake(&mut datagrams.driver_waker);
        Ok(true)
    }

    pub(crate) fn send_tail_repairs(
        &self,
        limit: usize,
        waker: &Waker,
    ) -> Result<usize, noq::SendDatagramError> {
        if !self.datagram_enabled() {
            return Err(noq::SendDatagramError::Disabled);
        }
        let available = {
            let mut datagrams = lock(&self.datagrams);
            if !self.datagram_enabled() {
                return Err(noq::SendDatagramError::Disabled);
            }
            let available = datagrams.capacity - datagrams.pending.len();
            if available == 0 {
                register_producer(&mut datagrams, waker);
            }
            available
        };
        let limit = limit.min(available);
        if limit == 0 {
            return Ok(0);
        }
        let (first, payloads) = {
            let sources = lock(&self.sources);
            if sources.len() < 2 {
                return Ok(0);
            }
            let span = usize::from(self.active_capabilities().max_span).min(sources.len());
            let window = sources.iter().skip(sources.len() - span);
            let first = window.clone().next().expect("repair source").0;
            let payloads = window.map(|(_, bytes)| bytes.clone()).collect::<Vec<_>>();
            (first, payloads)
        };
        let mut sent = 0;
        for _ in 0..limit {
            let repair_id = self.next_repair.fetch_add(1, Ordering::Relaxed);
            let seed = repair_seed(first);
            let coded =
                repair_symbol(first, repair_id, seed, &payloads).expect("validated source window");
            let frame = RepairDatagram {
                repair_id,
                first_symbol_id: first,
                span: u16::try_from(payloads.len()).expect("bounded repair span"),
                symbol_size: u16::try_from(coded.len()).expect("bounded symbol size"),
                seed,
                coded: &coded,
            };
            let mut encoded = Vec::with_capacity(coded.len().saturating_add(17));
            encode_repair(frame, &mut encoded).expect("validated repair frame");
            let mut datagrams = lock(&self.datagrams);
            if !self.datagram_enabled() {
                return Err(noq::SendDatagramError::Disabled);
            }
            if datagrams.pending.len() == datagrams.capacity {
                register_producer(&mut datagrams, waker);
                break;
            }
            datagrams
                .pending
                .push_back(OutboundDatagram::Repair(Bytes::from(encoded)));
            self.queued_datagrams.fetch_add(1, Ordering::Relaxed);
            wake(&mut datagrams.driver_waker);
            sent += 1;
        }
        Ok(sent)
    }

    fn take_datagram(&self, waker: &Waker) -> Option<OutboundDatagram> {
        let mut datagrams = lock(&self.datagrams);
        if let Some(datagram) = datagrams.pending.pop_front() {
            self.queued_datagrams.fetch_sub(1, Ordering::Relaxed);
            let producer = (datagrams.pending.len() <= datagrams.capacity / 2)
                .then(|| datagrams.producer_waiters.pop_front())
                .flatten();
            drop(datagrams);
            if let Some(producer) = producer {
                producer.wake();
            }
            return Some(datagram);
        }
        if datagrams
            .driver_waker
            .as_ref()
            .is_none_or(|registered| !registered.will_wake(waker))
        {
            datagrams.driver_waker = Some(waker.clone());
        }
        None
    }

    fn record_sent(&self, datagram: OutboundDatagram) {
        match datagram {
            OutboundDatagram::Source { symbol_id, bytes } => {
                self.counters.source_sent.fetch_add(1, Ordering::Relaxed);
                if !self.datagram_enabled() {
                    return;
                }
                let mut sources = lock(&self.sources);
                self.retained_source_bytes.fetch_add(
                    u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
                sources.push_back((symbol_id, bytes));
                if sources.len() > usize::from(self.active_capabilities().max_span)
                    && let Some((_, removed)) = sources.pop_front()
                {
                    self.retained_source_bytes.fetch_sub(
                        u64::try_from(removed.len()).unwrap_or(u64::MAX),
                        Ordering::Relaxed,
                    );
                }
            }
            OutboundDatagram::Repair(_) => {
                self.counters.repair_sent.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn handle_send_error(&self, error: &noq::SendDatagramError) -> bool {
        match error {
            noq::SendDatagramError::UnsupportedByPeer
            | noq::SendDatagramError::Disabled
            | noq::SendDatagramError::TooLarge
                if !self.adaptive_required() =>
            {
                self.disable_datagrams();
                false
            }
            noq::SendDatagramError::ConnectionLost(_) => false,
            _ => true,
        }
    }

    fn disable_datagrams(&self) {
        self.datagram_enabled.store(false, Ordering::Release);
        let mut datagrams = lock(&self.datagrams);
        datagrams.pending.clear();
        self.queued_datagrams.store(0, Ordering::Relaxed);
        drop(datagrams);
        let mut sources = lock(&self.sources);
        sources.clear();
        self.retained_source_bytes.store(0, Ordering::Relaxed);
        drop(sources);
        let flows = lock(&self.flows);
        for flow in flows.values().filter_map(Weak::upgrade) {
            flow.wake_task();
        }
    }

    pub(crate) fn record_replay(&self) {
        self.counters.replayed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_delivery(&self, bytes: usize) {
        self.delivered_bytes
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    pub(crate) fn record_fallback(&self) {
        self.counters.fallback.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_early_accepted(&self) {
        self.counters.early_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_early_rejected(&self) {
        self.counters.early_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> RecoverySnapshot {
        RecoverySnapshot {
            source_sent: self.counters.source_sent.load(Ordering::Relaxed),
            source_received: self.counters.source_received.load(Ordering::Relaxed),
            repair_sent: self.counters.repair_sent.load(Ordering::Relaxed),
            recovered: self.counters.recovered.load(Ordering::Relaxed),
            replayed: self.counters.replayed.load(Ordering::Relaxed),
            fallback: self.counters.fallback.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
            early_accepted: self.counters.early_accepted.load(Ordering::Relaxed),
            early_rejected: self.counters.early_rejected.load(Ordering::Relaxed),
            path_lost_packets: self.sampled_path_lost_packets.load(Ordering::Relaxed),
            max_path_rtt_micros: self.sampled_max_path_rtt_micros.load(Ordering::Relaxed),
            queued_datagrams: u64::from(self.queued_datagrams.load(Ordering::Relaxed)),
            retained_source_bytes: self.retained_source_bytes.load(Ordering::Relaxed),
        }
    }

    fn receive(&self, datagram: &Bytes) {
        match datagram.first().copied() {
            Some(SOURCE_DATAGRAM) => self.receive_source(datagram),
            Some(REPAIR_DATAGRAM) => {
                let Ok(repair) = decode_repair(datagram, self.max_symbol_bytes) else {
                    self.drop_datagram();
                    return;
                };
                if !repair_span_is_negotiated(repair.span, self.active_capabilities().max_span) {
                    self.drop_datagram();
                    return;
                }
                let recovered = lock(&self.decoder).add_repair(
                    repair.first_symbol_id,
                    repair.span,
                    repair.repair_id,
                    repair.seed,
                    repair.coded,
                    usize::from(self.config.work_budget) * self.max_symbol_bytes,
                );
                let recovered = match recovered {
                    Ok(recovered) => recovered,
                    Err(FecError::RowCapacity) => {
                        self.backend.close(
                            crate::flow::backend_error_code(crate::ApplicationError::FlowProtocol),
                            b"QUICP decoder row capacity exhausted",
                        );
                        return;
                    }
                    Err(_) => {
                        self.drop_datagram();
                        return;
                    }
                };
                self.dispatch_recovered(recovered);
            }
            _ => self.drop_datagram(),
        }
    }

    fn receive_source(&self, datagram: &Bytes) {
        let retained_bytes = self.max_symbol_bytes + REPAIR_DATAGRAM_HEADER_BYTES;
        if datagram.get(5) == Some(&1) {
            let Ok((symbol_id, flow_id, offset, fin, data)) =
                decode_source_single(datagram, self.max_symbol_bytes)
            else {
                self.drop_datagram();
                return;
            };
            let mut record = [PendingSourceRecord {
                flow: None,
                flow_id,
                offset,
                fin,
                retained_bytes,
                data: datagram.slice(data),
                charge: None,
            }];
            self.accept_source(symbol_id, datagram.clone(), &mut record);
            return;
        }
        let Some(record_count) = datagram
            .get(5)
            .copied()
            .map(usize::from)
            .filter(|count| (2..=MAX_SOURCE_RECORDS).contains(count))
        else {
            self.drop_datagram();
            return;
        };
        let Some(dispatch_bytes) = record_count
            .checked_mul(size_of::<SourceRecord<'static>>() + size_of::<PendingSourceRecord>())
            .and_then(|bytes| bytes.checked_add(datagram.len()))
        else {
            self.drop_datagram();
            return;
        };
        let Ok(mut dispatch_charge) =
            RecoveryCharge::reserve(Arc::clone(&self.memory_budget), dispatch_bytes)
        else {
            self.drop_datagram();
            return;
        };
        let Ok(source) = decode_source(datagram, MAX_SOURCE_RECORDS, self.max_symbol_bytes) else {
            self.drop_datagram();
            return;
        };
        if source.records.capacity() != record_count {
            self.drop_datagram();
            return;
        }
        let symbol_id = source.symbol_id;
        let mut records = Vec::with_capacity(record_count);
        if records.capacity() != record_count {
            self.drop_datagram();
            return;
        }
        for record in source.records {
            let mut storage = Vec::with_capacity(record.data.len());
            if storage.capacity() != record.data.len() {
                self.drop_datagram();
                return;
            }
            storage.extend_from_slice(record.data);
            let retained_bytes = storage.capacity();
            let Ok(charge) = dispatch_charge.split(retained_bytes) else {
                self.drop_datagram();
                return;
            };
            records.push(PendingSourceRecord {
                flow: None,
                flow_id: record.flow_id,
                offset: record.offset,
                fin: record.fin,
                data: Bytes::from(storage),
                retained_bytes,
                charge: Some(charge),
            });
        }
        self.accept_source(symbol_id, datagram.clone(), &mut records);
    }

    fn accept_source(&self, symbol_id: u32, datagram: Bytes, records: &mut [PendingSourceRecord]) {
        match lock(&self.decoder).source_status(symbol_id, &datagram) {
            Ok(SourceStatus::Duplicate) => return,
            Ok(SourceStatus::New) => {}
            Err(_) => {
                self.drop_datagram();
                return;
            }
        }
        if !self.reserve_source_records(records) {
            self.drop_datagram();
            return;
        }
        let recovered = {
            let mut decoder = lock(&self.decoder);
            match decoder.source_status(symbol_id, &datagram) {
                Ok(SourceStatus::Duplicate) => {
                    self.release_source_reservations(records);
                    return;
                }
                Ok(SourceStatus::New) => decoder.add_source(
                    symbol_id,
                    datagram,
                    usize::from(self.config.work_budget) * self.max_symbol_bytes,
                ),
                Err(error) => Err(error),
            }
        };
        let Ok(recovered) = recovered else {
            self.release_source_reservations(records);
            self.drop_datagram();
            return;
        };
        self.counters
            .source_received
            .fetch_add(1, Ordering::Relaxed);
        self.dispatch_reserved_source(records);
        self.dispatch_recovered(recovered);
    }

    fn reserve_source_records(&self, records: &mut [PendingSourceRecord]) -> bool {
        let limit = u32::from(self.config.pre_open_symbols);
        let flows = lock(&self.flows);
        let mut pre_open = lock(&self.pre_open);
        let removed = prune_pre_open(&mut pre_open, self.now());
        if removed != 0 {
            self.pre_open_count.fetch_sub(removed, Ordering::Relaxed);
            self.counters
                .dropped
                .fetch_add(u64::from(removed), Ordering::Relaxed);
        }
        for record in records.iter_mut() {
            record.flow = flows.get(&record.flow_id).and_then(Weak::upgrade);
        }
        let needed = u32::try_from(
            records
                .iter()
                .filter(|record| record.flow.is_none())
                .count(),
        )
        .expect("source record count fits u32");
        if !reserve_bounded(&self.pre_open_count, limit, needed) {
            return false;
        }
        let bytes = records
            .iter()
            .filter(|record| record.charge.is_none())
            .try_fold(0usize, |bytes, record| {
                bytes.checked_add(if record.flow.is_none() {
                    record.data.len()
                } else {
                    record.retained_bytes
                })
            });
        let Some(bytes) = bytes else {
            self.pre_open_count.fetch_sub(needed, Ordering::Relaxed);
            return false;
        };
        let Ok(mut charge) = RecoveryCharge::reserve(Arc::clone(&self.memory_budget), bytes) else {
            self.pre_open_count.fetch_sub(needed, Ordering::Relaxed);
            return false;
        };
        for record in records.iter_mut().filter(|record| record.charge.is_none()) {
            let retained_bytes = if record.flow.is_none() {
                let mut storage = Vec::with_capacity(record.data.len());
                if storage.capacity() != record.data.len() {
                    self.pre_open_count.fetch_sub(needed, Ordering::Relaxed);
                    return false;
                }
                storage.extend_from_slice(&record.data);
                record.data = Bytes::from(storage);
                record.data.len()
            } else {
                record.retained_bytes
            };
            let Ok(record_charge) = charge.split(retained_bytes) else {
                self.pre_open_count.fetch_sub(needed, Ordering::Relaxed);
                return false;
            };
            record.retained_bytes = retained_bytes;
            record.charge = Some(record_charge);
        }
        true
    }

    fn release_source_reservations(&self, records: &[PendingSourceRecord]) {
        let reserved = u32::try_from(
            records
                .iter()
                .filter(|record| record.flow.is_none())
                .count(),
        )
        .expect("source record count fits u32");
        self.pre_open_count.fetch_sub(reserved, Ordering::Relaxed);
    }

    fn dispatch_reserved_source(&self, records: &mut [PendingSourceRecord]) {
        for record in records {
            let flow = if let Some(flow) = record.flow.take() {
                flow
            } else {
                let flows = lock(&self.flows);
                let mut pre_open = lock(&self.pre_open);
                let Some(flow) = flows.get(&record.flow_id).and_then(Weak::upgrade) else {
                    pre_open
                        .entry(record.flow_id)
                        .or_default()
                        .push(PreOpenRecord {
                            offset: record.offset,
                            fin: record.fin,
                            data: std::mem::take(&mut record.data),
                            charge: record.charge.take().expect("source record is charged"),
                            expires_at: self.now() + PRE_OPEN_TTL,
                        });
                    continue;
                };
                self.pre_open_count.fetch_sub(1, Ordering::Relaxed);
                flow
            };
            if let Err(error) = flow.insert_bytes_precharged(
                record.offset,
                std::mem::take(&mut record.data),
                record.fin,
                record.charge.take().expect("source record is charged"),
            ) {
                if !matches!(
                    error,
                    RecoveryError::Capacity | RecoveryError::RangeCapacity
                ) {
                    flow.reject_protocol();
                }
                self.drop_datagram();
            }
        }
    }

    fn dispatch_recovered(&self, mut recovered: RecoveredBatch) {
        if recovered.is_empty() {
            return;
        }
        let dispatch_bytes = recovered
            .iter()
            .try_fold(0usize, |bytes, source| {
                bytes.checked_add(source.bytes.len())
            })
            .and_then(|bytes| {
                bytes.checked_add(MAX_SOURCE_RECORDS.saturating_mul(
                    size_of::<SourceRecord<'static>>() + size_of::<PendingSourceRecord>(),
                ))
            });
        if dispatch_bytes.is_none_or(|bytes| recovered.reserve_dispatch(bytes).is_err()) {
            self.drop_datagram();
            return;
        }
        while let Some(source) = recovered.pop() {
            let Ok(decoded) =
                decode_source(&source.bytes, MAX_SOURCE_RECORDS, self.max_symbol_bytes)
            else {
                self.drop_datagram();
                continue;
            };
            if decoded.records.capacity() != decoded.records.len() {
                self.drop_datagram();
                continue;
            }
            let mut records = Vec::with_capacity(decoded.records.len());
            if records.capacity() != decoded.records.len() {
                self.drop_datagram();
                continue;
            }
            let mut allocation_failed = false;
            for record in decoded.records {
                let mut storage = Vec::with_capacity(record.data.len());
                if storage.capacity() != record.data.len() {
                    allocation_failed = true;
                    break;
                }
                storage.extend_from_slice(record.data);
                let retained_bytes = storage.capacity();
                let Ok(charge) = recovered.take_dispatch_charge(retained_bytes) else {
                    allocation_failed = true;
                    break;
                };
                records.push(PendingSourceRecord {
                    flow: None,
                    flow_id: record.flow_id,
                    offset: record.offset,
                    fin: record.fin,
                    data: Bytes::from(storage),
                    retained_bytes,
                    charge: Some(charge),
                });
            }
            if allocation_failed {
                self.drop_datagram();
                continue;
            }
            if !self.reserve_source_records(&mut records) {
                self.drop_datagram();
                continue;
            }
            let Ok(source_charge) = recovered.take_retained_charge(source.retained_bytes) else {
                self.release_source_reservations(&records);
                self.drop_datagram();
                continue;
            };
            if lock(&self.decoder)
                .commit_recovered_precharged(source.symbol_id, source.bytes, source_charge)
                .is_err()
            {
                self.release_source_reservations(&records);
                self.drop_datagram();
                continue;
            }
            self.counters.recovered.fetch_add(1, Ordering::Relaxed);
            self.dispatch_reserved_source(&mut records);
        }
    }

    fn drop_datagram(&self) {
        self.counters.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

async fn run_datagram_driver(
    driver: Weak<ConnectionRecovery>,
    backend: noq::Connection,
    budget: usize,
) {
    let mut close_guard = DriverCloseGuard {
        backend: backend.clone(),
        armed: true,
    };
    let mut read = Box::pin(backend.read_datagram());
    let mut sending: Option<(OutboundDatagram, DatagramSendFuture<'_>)> = None;
    let mut remaining = budget;
    let mut send_streak = 0u8;
    let mut send_credit = backend.datagram_send_buffer_space();
    loop {
        let event = std::future::poll_fn(|cx| {
            let Some(state) = driver.upgrade() else {
                return Poll::Ready(DriverEvent::OwnerDropped);
            };
            if send_streak >= DRIVER_SEND_BATCH
                && let Poll::Ready(result) = read.as_mut().poll(cx)
            {
                return Poll::Ready(DriverEvent::Received(result));
            }
            if sending.is_none()
                && let Some(datagram) = state.take_datagram(cx.waker())
            {
                let bytes = datagram.bytes();
                if send_credit >= bytes.len() {
                    let length = bytes.len();
                    let result = backend.send_datagram(bytes);
                    if result.is_ok() {
                        send_credit -= length;
                    }
                    return Poll::Ready(DriverEvent::Sent(datagram, result));
                }
                sending = Some((datagram, Box::pin(backend.send_datagram_wait(bytes))));
            }
            let sent = sending
                .as_mut()
                .and_then(|(_, future)| match future.as_mut().poll(cx) {
                    Poll::Ready(result) => Some(result),
                    Poll::Pending => None,
                });
            if let Some(result) = sent {
                if result.is_ok() {
                    send_credit = backend.datagram_send_buffer_space();
                }
                let (datagram, _) = sending.take().expect("completed DATAGRAM send");
                return Poll::Ready(DriverEvent::Sent(datagram, result));
            }
            read.as_mut().poll(cx).map(DriverEvent::Received)
        })
        .await;

        match event {
            DriverEvent::Received(Ok(datagram)) => {
                send_streak = 0;
                read = Box::pin(backend.read_datagram());
                let Some(state) = driver.upgrade() else {
                    break;
                };
                state.receive(&datagram);
            }
            DriverEvent::Sent(datagram, Ok(())) => {
                send_streak = send_streak.saturating_add(1);
                if let Some(state) = driver.upgrade() {
                    state.record_sent(datagram);
                } else {
                    break;
                }
            }
            DriverEvent::Sent(_, Err(error)) => {
                let Some(state) = driver.upgrade() else {
                    break;
                };
                if state.handle_send_error(&error) {
                    return;
                }
                close_guard.armed = false;
                return;
            }
            DriverEvent::Received(Err(_)) | DriverEvent::OwnerDropped => break,
        }
        remaining -= 1;
        if remaining == 0 {
            // Let flow tasks emit logical ACKs during sustained DATAGRAM input.
            let mut yielded = false;
            std::future::poll_fn(|cx| {
                if std::mem::replace(&mut yielded, true) {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await;
            remaining = budget;
        }
    }
    close_guard.armed = false;
}

impl Drop for ConnectionRecovery {
    fn drop(&mut self) {
        self.backend.close(0u32.into(), b"QUICP owner dropped");
    }
}

fn prune_pre_open(records: &mut HashMap<u64, Vec<PreOpenRecord>>, now: Instant) -> u32 {
    let before = records.values().map(Vec::len).sum::<usize>();
    records.retain(|_, flow| {
        flow.retain(|record| record.expires_at > now);
        !flow.is_empty()
    });
    let after = records.values().map(Vec::len).sum::<usize>();
    u32::try_from(before - after).expect("pre-open capacity fits u32")
}

impl From<FecError> for RecoveryError {
    fn from(_: FecError) -> Self {
        Self::Capacity
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn wake(waker: &mut Option<Waker>) {
    if let Some(waker) = waker.take() {
        waker.wake();
    }
}

fn register_producer(datagrams: &mut DatagramQueue, waker: &Waker) {
    if datagrams
        .producer_waiters
        .iter()
        .any(|registered| registered.will_wake(waker))
        || datagrams.producer_waiters.len() == datagrams.capacity
    {
        return;
    }
    datagrams.producer_waiters.push_back(waker.clone());
}

fn reserve_bounded(counter: &AtomicU32, limit: u32, amount: u32) -> bool {
    if amount == 0 {
        return true;
    }
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let Some(next) = current.checked_add(amount) else {
            return false;
        };
        if next > limit {
            return false;
        }
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum RecoveryError {
    #[error("logical offset overflow")]
    OffsetOverflow,
    #[error("logical range is invalid")]
    InvalidRange,
    #[error("logical range capacity is exhausted")]
    RangeCapacity,
    #[error("logical flow-control credit was exceeded")]
    FlowControl,
    #[error("bounded recovery storage is exhausted")]
    Capacity,
    #[error("overlapping flow bytes contradict retained data")]
    ContradictoryOverlap,
    #[error("final offset contradicts flow state")]
    FinalOffset,
}

#[derive(Clone, Debug)]
pub(crate) struct AckRanges {
    contiguous: u64,
    ranges: Vec<Range<u64>>,
    max_ranges: usize,
}

impl AckRanges {
    pub(crate) fn new(max_ranges: usize) -> Self {
        Self {
            contiguous: 0,
            ranges: Vec::with_capacity(max_ranges),
            max_ranges,
        }
    }

    pub(crate) fn contiguous(&self) -> u64 {
        self.contiguous
    }

    pub(crate) fn ranges(&self) -> &[Range<u64>] {
        &self.ranges
    }

    pub(crate) fn from_wire(
        contiguous: u64,
        ranges: Vec<Range<u64>>,
        max_ranges: usize,
        sent_offset: u64,
    ) -> Result<Self, RecoveryError> {
        if contiguous > sent_offset || ranges.len() > max_ranges {
            return Err(RecoveryError::InvalidRange);
        }
        let mut ack = Self::new(max_ranges);
        ack.contiguous = contiguous;
        for range in ranges {
            if range.end > sent_offset {
                return Err(RecoveryError::InvalidRange);
            }
            ack.insert(range)?;
        }
        Ok(ack)
    }

    pub(crate) fn insert(&mut self, range: Range<u64>) -> Result<(), RecoveryError> {
        self.validate_insert(&range)?;
        if range.end <= self.contiguous {
            return Ok(());
        }
        let mut merged = range.start.max(self.contiguous)..range.end;
        let first = self
            .ranges
            .partition_point(|current| current.end < merged.start);
        let mut last = first;
        while last < self.ranges.len() && self.ranges[last].start <= merged.end {
            merged.start = merged.start.min(self.ranges[last].start);
            merged.end = merged.end.max(self.ranges[last].end);
            last += 1;
        }
        if first == last {
            self.ranges.insert(first, merged);
        } else {
            self.ranges[first] = merged;
            self.ranges.drain(first + 1..last);
        }
        while self
            .ranges
            .first()
            .is_some_and(|range| range.start <= self.contiguous)
        {
            let first = self.ranges.remove(0);
            self.contiguous = self.contiguous.max(first.end);
        }
        Ok(())
    }

    pub(crate) fn validate_insert(&self, range: &Range<u64>) -> Result<(), RecoveryError> {
        validate_range(range)?;
        if range.end <= self.contiguous || self.ranges.len() < self.max_ranges {
            return Ok(());
        }
        let start = range.start.max(self.contiguous);
        if self
            .ranges
            .iter()
            .any(|current| current.end >= start && current.start <= range.end)
        {
            Ok(())
        } else {
            Err(RecoveryError::RangeCapacity)
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ReplayBuffer {
    chunks: BTreeMap<u64, Bytes>,
    bytes: usize,
    max_bytes: usize,
    max_chunks: usize,
}

impl ReplayBuffer {
    pub(crate) fn new(max_bytes: usize) -> Self {
        Self {
            chunks: BTreeMap::new(),
            bytes: 0,
            max_bytes,
            max_chunks: replay_chunk_limit(max_bytes),
        }
    }

    pub(crate) fn retain(&mut self, offset: u64, bytes: Bytes) -> Result<(), RecoveryError> {
        let end = checked_end(offset, bytes.len())?;
        if bytes.is_empty()
            || self.bytes.saturating_add(bytes.len()) > self.max_bytes
            || self.chunks.len() >= self.max_chunks
        {
            return Err(RecoveryError::Capacity);
        }
        if self
            .chunks
            .range(..end)
            .next_back()
            .is_some_and(|(start, chunk)| {
                checked_end(*start, chunk.len()).unwrap_or(MAX_WIRE_OFFSET) > offset
            })
        {
            return Err(RecoveryError::ContradictoryOverlap);
        }
        self.bytes += bytes.len();
        self.chunks.insert(offset, bytes);
        Ok(())
    }

    pub(crate) fn acknowledge(&mut self, ack: &AckRanges) -> (usize, usize) {
        let before = self.bytes;
        let before_chunks = self.chunks.len();
        self.chunks.retain(|offset, bytes| {
            let end = checked_end(*offset, bytes.len()).unwrap_or(MAX_WIRE_OFFSET);
            let covered = end <= ack.contiguous
                || ack
                    .ranges
                    .iter()
                    .any(|range| *offset >= range.start && end <= range.end);
            if covered {
                self.bytes -= bytes.len();
            }
            !covered
        });
        (before - self.bytes, before_chunks - self.chunks.len())
    }

    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn len(&self) -> usize {
        self.chunks.len()
    }

    #[cfg(test)]
    pub(crate) fn chunks(&self) -> impl Iterator<Item = (u64, Bytes)> + '_ {
        self.chunks
            .iter()
            .map(|(offset, bytes)| (*offset, bytes.clone()))
    }

    pub(crate) fn next_chunk_after(&self, last_offset: Option<u64>) -> Option<(u64, Bytes)> {
        let start = last_offset.map_or(Bound::Unbounded, Bound::Excluded);
        self.chunks
            .range((start, Bound::Unbounded))
            .next()
            .map(|(offset, bytes)| (*offset, bytes.clone()))
    }
}

pub(crate) fn replay_chunk_limit(max_bytes: usize) -> usize {
    max_bytes.div_ceil(64).max(8)
}

#[derive(Debug)]
struct BufferedChunk {
    bytes: Bytes,
    _charge: RecoveryCharge,
}

#[derive(Debug)]
pub(crate) struct Reassembler {
    chunks: BTreeMap<u64, BufferedChunk>,
    next_offset: u64,
    acknowledged_offset: u64,
    final_offset: Option<u64>,
    bytes: usize,
    max_bytes: usize,
    max_chunks: usize,
    memory_budget: Arc<RecoveryMemoryBudget>,
}

impl Reassembler {
    #[cfg(any(test, fuzzing))]
    pub(crate) fn new(max_bytes: usize) -> Self {
        let limit = u32::try_from(max_bytes).unwrap_or(u32::MAX);
        Self::with_budget(max_bytes, Arc::new(RecoveryMemoryBudget::new(limit)))
    }

    pub(crate) fn with_budget(max_bytes: usize, memory_budget: Arc<RecoveryMemoryBudget>) -> Self {
        Self {
            chunks: BTreeMap::new(),
            next_offset: 0,
            acknowledged_offset: 0,
            final_offset: None,
            bytes: 0,
            max_bytes,
            max_chunks: max_bytes.div_ceil(64).max(8),
            memory_budget,
        }
    }

    pub(crate) fn reserve(&self, bytes: usize) -> Result<RecoveryCharge, RecoveryError> {
        RecoveryCharge::reserve(Arc::clone(&self.memory_budget), bytes)
    }

    #[cfg(test)]
    pub(crate) const fn buffered_bytes(&self) -> usize {
        self.bytes
    }

    #[cfg(test)]
    pub(crate) fn insert(&mut self, offset: u64, bytes: Bytes) -> Result<(), RecoveryError> {
        self.insert_record(offset, bytes, false)
    }

    pub(crate) fn insert_record(
        &mut self,
        offset: u64,
        bytes: Bytes,
        fin: bool,
    ) -> Result<(), RecoveryError> {
        let charge = self.reserve(0)?;
        self.insert_record_with_reservation(offset, bytes, fin, charge, false)
    }

    #[cfg(test)]
    pub(crate) fn insert_record_with_charge(
        &mut self,
        offset: u64,
        bytes: Bytes,
        fin: bool,
        retained_bytes: usize,
    ) -> Result<(), RecoveryError> {
        let charge = RecoveryCharge::reserve(Arc::clone(&self.memory_budget), retained_bytes)?;
        self.insert_record_precharged(offset, bytes, fin, charge)
    }

    pub(crate) fn insert_record_precharged(
        &mut self,
        offset: u64,
        bytes: Bytes,
        fin: bool,
        charge: RecoveryCharge,
    ) -> Result<(), RecoveryError> {
        self.insert_record_with_reservation(offset, bytes, fin, charge, true)
    }

    fn insert_record_with_reservation(
        &mut self,
        mut offset: u64,
        mut bytes: Bytes,
        fin: bool,
        mut charge: RecoveryCharge,
        precharged: bool,
    ) -> Result<(), RecoveryError> {
        let retained_bytes = bytes.len();
        if !charge.belongs_to(&self.memory_budget)
            || (precharged && charge.bytes() < retained_bytes)
        {
            return Err(RecoveryError::Capacity);
        }
        let end = checked_end(offset, bytes.len())?;
        if bytes.is_empty() {
            return Err(RecoveryError::InvalidRange);
        }
        if let Some(final_offset) = self.final_offset
            && end > final_offset
        {
            return Err(RecoveryError::FinalOffset);
        }
        if fin
            && (self
                .final_offset
                .is_some_and(|final_offset| final_offset != end)
                || end < self.next_offset
                || self.chunks.iter().any(|(offset, chunk)| {
                    checked_end(*offset, chunk.bytes.len()).unwrap_or(MAX_WIRE_OFFSET) > end
                }))
        {
            return Err(RecoveryError::FinalOffset);
        }
        if end <= self.next_offset {
            self.validate_consumed_overlap(offset, end, &bytes)?;
            if fin {
                self.set_final_offset(end)?;
            }
            return Ok(());
        }
        if offset < self.next_offset {
            self.validate_consumed_overlap(offset, self.next_offset, &bytes)?;
            let consumed = usize::try_from(self.next_offset - offset)
                .map_err(|_| RecoveryError::OffsetOverflow)?;
            bytes = bytes.slice(consumed..);
            offset = self.next_offset;
        }
        let overlaps =
            self.chunks
                .range(..end)
                .next_back()
                .is_some_and(|(existing_offset, existing)| {
                    checked_end(*existing_offset, existing.bytes.len()).unwrap_or(MAX_WIRE_OFFSET)
                        > offset
                });
        if overlaps {
            return self.insert_overlapping_record(offset, end, &bytes, fin, charge);
        }
        if self.bytes.saturating_add(bytes.len()) > self.max_bytes {
            return Err(RecoveryError::Capacity);
        }
        if self.chunks.len() >= self.max_chunks {
            return Err(RecoveryError::Capacity);
        }
        if !precharged {
            charge.grow(retained_bytes)?;
        }
        self.bytes += bytes.len();
        self.chunks.insert(
            offset,
            BufferedChunk {
                bytes,
                _charge: charge,
            },
        );
        if fin {
            self.final_offset = Some(end);
        }
        Ok(())
    }

    fn validate_consumed_overlap(
        &self,
        offset: u64,
        end: u64,
        bytes: &[u8],
    ) -> Result<(), RecoveryError> {
        for (existing_offset, existing) in self.chunks.range(..end) {
            let existing_end = checked_end(*existing_offset, existing.bytes.len())?;
            let overlap_start = offset.max(*existing_offset);
            let overlap_end = end.min(existing_end);
            if overlap_start >= overlap_end {
                continue;
            }
            let incoming_start = usize::try_from(overlap_start - offset)
                .map_err(|_| RecoveryError::OffsetOverflow)?;
            let incoming_end =
                usize::try_from(overlap_end - offset).map_err(|_| RecoveryError::OffsetOverflow)?;
            let existing_start = usize::try_from(overlap_start - *existing_offset)
                .map_err(|_| RecoveryError::OffsetOverflow)?;
            let existing_end = existing_start + (incoming_end - incoming_start);
            if bytes[incoming_start..incoming_end] != existing.bytes[existing_start..existing_end] {
                return Err(RecoveryError::ContradictoryOverlap);
            }
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keeping validation, reservation, and mutation in one auditable transaction"
    )]
    fn insert_overlapping_record(
        &mut self,
        offset: u64,
        end: u64,
        bytes: &Bytes,
        fin: bool,
        _incoming_charge: RecoveryCharge,
    ) -> Result<(), RecoveryError> {
        let mut gap_count = 0usize;
        let mut added = 0usize;
        let mut cursor = offset;
        for (existing_offset, existing) in self.chunks.range(..end) {
            let existing_end = checked_end(*existing_offset, existing.bytes.len())?;
            if existing_end <= offset {
                continue;
            }
            let overlap_start = offset.max(*existing_offset);
            let overlap_end = end.min(existing_end);
            if cursor < overlap_start {
                gap_count = gap_count.checked_add(1).ok_or(RecoveryError::Capacity)?;
                added = added
                    .checked_add(
                        usize::try_from(overlap_start - cursor)
                            .map_err(|_| RecoveryError::OffsetOverflow)?,
                    )
                    .ok_or(RecoveryError::Capacity)?;
            }
            let incoming_start = usize::try_from(overlap_start - offset)
                .map_err(|_| RecoveryError::OffsetOverflow)?;
            let incoming_end =
                usize::try_from(overlap_end - offset).map_err(|_| RecoveryError::OffsetOverflow)?;
            let existing_start = usize::try_from(overlap_start - *existing_offset)
                .map_err(|_| RecoveryError::OffsetOverflow)?;
            let existing_end = existing_start + (incoming_end - incoming_start);
            if bytes[incoming_start..incoming_end] != existing.bytes[existing_start..existing_end] {
                return Err(RecoveryError::ContradictoryOverlap);
            }
            cursor = cursor.max(overlap_end);
        }
        if cursor < end {
            gap_count = gap_count.checked_add(1).ok_or(RecoveryError::Capacity)?;
            added = added
                .checked_add(
                    usize::try_from(end - cursor).map_err(|_| RecoveryError::OffsetOverflow)?,
                )
                .ok_or(RecoveryError::Capacity)?;
        }
        if gap_count == 0 {
            if fin {
                self.set_final_offset(end)?;
            }
            return Ok(());
        }
        if self.bytes.saturating_add(added) > self.max_bytes
            || self.chunks.len().saturating_add(gap_count) > self.max_chunks
        {
            return Err(RecoveryError::Capacity);
        }
        let gap_metadata = gap_count
            .checked_mul(size_of::<Range<u64>>())
            .ok_or(RecoveryError::Capacity)?;
        let mut scratch = RecoveryCharge::reserve(
            Arc::clone(&self.memory_budget),
            added
                .checked_add(gap_metadata)
                .ok_or(RecoveryError::Capacity)?,
        )?;
        let mut gaps = Vec::with_capacity(gap_count);
        if gaps.capacity() != gap_count {
            return Err(RecoveryError::Capacity);
        }
        cursor = offset;
        for (existing_offset, existing) in self.chunks.range(..end) {
            let existing_end = checked_end(*existing_offset, existing.bytes.len())?;
            if existing_end <= offset {
                continue;
            }
            let overlap_start = offset.max(*existing_offset);
            let overlap_end = end.min(existing_end);
            if cursor < overlap_start {
                gaps.push(cursor..overlap_start);
            }
            cursor = cursor.max(overlap_end);
        }
        if cursor < end {
            gaps.push(cursor..end);
        }
        for gap in gaps {
            let start =
                usize::try_from(gap.start - offset).map_err(|_| RecoveryError::OffsetOverflow)?;
            let end =
                usize::try_from(gap.end - offset).map_err(|_| RecoveryError::OffsetOverflow)?;
            let mut storage = Vec::with_capacity(end - start);
            if storage.capacity() != end - start {
                return Err(RecoveryError::Capacity);
            }
            storage.extend_from_slice(&bytes[start..end]);
            let charge = scratch.split(storage.capacity())?;
            let data = Bytes::from(storage);
            self.chunks.insert(
                gap.start,
                BufferedChunk {
                    bytes: data,
                    _charge: charge,
                },
            );
        }
        self.bytes += added;
        if fin {
            self.final_offset = Some(end);
        }
        Ok(())
    }

    pub(crate) fn set_final_offset(&mut self, final_offset: u64) -> Result<(), RecoveryError> {
        if final_offset > MAX_WIRE_OFFSET
            || self
                .final_offset
                .is_some_and(|current| current != final_offset)
            || final_offset < self.next_offset
            || self.chunks.iter().any(|(offset, chunk)| {
                checked_end(*offset, chunk.bytes.len()).unwrap_or(MAX_WIRE_OFFSET) > final_offset
            })
        {
            return Err(RecoveryError::FinalOffset);
        }
        self.final_offset = Some(final_offset);
        Ok(())
    }

    pub(crate) fn read(&mut self, output: &mut [u8]) -> usize {
        let mut written = 0;
        while written < output.len() {
            let candidate =
                self.chunks
                    .range(..=self.next_offset)
                    .next_back()
                    .and_then(|(offset, chunk)| {
                        let end = checked_end(*offset, chunk.bytes.len()).ok()?;
                        (end > self.next_offset).then_some(*offset)
                    });
            let Some(offset) = candidate else {
                break;
            };
            let (count, end) = {
                let chunk = &self.chunks[&offset];
                let start = usize::try_from(self.next_offset - offset)
                    .expect("validated chunk offset fits usize");
                let count = (chunk.bytes.len() - start).min(output.len() - written);
                output[written..written + count]
                    .copy_from_slice(&chunk.bytes[start..start + count]);
                (
                    count,
                    checked_end(offset, chunk.bytes.len()).expect("retained chunk is validated"),
                )
            };
            written += count;
            self.next_offset += count as u64;
            self.bytes -= count;
            if end <= self.next_offset && end <= self.acknowledged_offset {
                self.chunks.remove(&offset);
            }
        }
        written
    }

    pub(crate) fn acknowledge_consumed(&mut self, contiguous: u64) {
        self.acknowledged_offset = self.acknowledged_offset.max(contiguous);
        let release_before = self.acknowledged_offset.min(self.next_offset);
        self.chunks.retain(|offset, chunk| {
            let remove =
                checked_end(*offset, chunk.bytes.len()).is_ok_and(|end| end <= release_before);
            !remove
        });
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.final_offset == Some(self.next_offset)
    }

    pub(crate) fn next_offset(&self) -> u64 {
        self.next_offset
    }

    pub(crate) fn has_final_offset(&self) -> bool {
        self.final_offset.is_some()
    }
}

fn checked_end(offset: u64, length: usize) -> Result<u64, RecoveryError> {
    let length = u64::try_from(length).map_err(|_| RecoveryError::OffsetOverflow)?;
    let end = offset
        .checked_add(length)
        .filter(|end| *end <= MAX_WIRE_OFFSET)
        .ok_or(RecoveryError::OffsetOverflow)?;
    Ok(end)
}

fn validate_range(range: &Range<u64>) -> Result<(), RecoveryError> {
    if range.start >= range.end || range.end > MAX_WIRE_OFFSET {
        Err(RecoveryError::InvalidRange)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_budget_uses_loss_signals_and_caps_output() {
        assert_eq!(repair_budget(0, 0, false, true, u32::MAX, 8, 8), 0);
        assert_eq!(repair_budget(1, 4, true, false, 1, 8, 8), 2);
        assert_eq!(repair_budget(1, 4, false, true, 3, 8, 8), 6);
        assert_eq!(repair_budget(1, 4, false, true, 3, 8, 3), 3);
        assert_eq!(repair_budget(1, 4, false, true, 3, 1, 8), 1);
    }

    #[test]
    fn repair_span_cannot_exceed_the_negotiated_limit() {
        assert!(repair_span_is_negotiated(8, 8));
        assert!(!repair_span_is_negotiated(9, 8));
    }

    #[test]
    fn ack_ranges_merge_and_release_replay() {
        let mut ack = AckRanges::new(4);
        ack.insert(4..8).unwrap();
        ack.insert(0..4).unwrap();
        assert_eq!(ack.contiguous(), 8);
        assert_eq!(ack.ranges(), []);

        let mut replay = ReplayBuffer::new(16);
        replay.retain(0, Bytes::from_static(b"abcd")).unwrap();
        replay.retain(4, Bytes::from_static(b"efgh")).unwrap();
        assert_eq!(replay.acknowledge(&ack), (8, 2));
        assert_eq!(replay.bytes(), 0);
    }

    #[test]
    fn selective_ack_retains_only_the_residual_gap() {
        let ack = AckRanges::from_wire(4, std::iter::once(8..12).collect(), 4, 12).unwrap();
        let mut replay = ReplayBuffer::new(12);
        replay.retain(0, Bytes::from_static(b"abcd")).unwrap();
        replay.retain(4, Bytes::from_static(b"efgh")).unwrap();
        replay.retain(8, Bytes::from_static(b"ijkl")).unwrap();
        assert_eq!(replay.acknowledge(&ack), (8, 2));
        assert_eq!(
            replay.chunks().collect::<Vec<_>>(),
            [(4, Bytes::from_static(b"efgh"))]
        );
    }

    #[test]
    fn replay_iteration_resumes_after_the_last_queued_chunk() {
        let mut replay = ReplayBuffer::new(12);
        replay.retain(0, Bytes::from_static(b"aaaa")).unwrap();
        replay.retain(4, Bytes::from_static(b"bbbb")).unwrap();
        replay.retain(8, Bytes::from_static(b"cccc")).unwrap();

        assert_eq!(
            replay.next_chunk_after(Some(4)).map(|(offset, _)| offset),
            Some(8)
        );
    }

    #[test]
    fn replay_buffer_bounds_fragment_metadata() {
        let mut replay = ReplayBuffer::new(512);
        let limit = replay_chunk_limit(512);
        for offset in 0..limit {
            replay
                .retain(offset as u64, Bytes::from_static(b"x"))
                .unwrap();
        }
        assert_eq!(
            replay.retain(limit as u64, Bytes::from_static(b"x")),
            Err(RecoveryError::Capacity)
        );
        assert_eq!(replay.bytes(), limit);
        assert_eq!(replay.len(), limit);

        let mut ack = AckRanges::new(1);
        ack.insert(0..1).unwrap();
        assert_eq!(replay.acknowledge(&ack), (1, 1));
        replay
            .retain(limit as u64, Bytes::from_static(b"x"))
            .unwrap();
    }

    #[test]
    fn ack_capacity_failure_does_not_mutate_ranges() {
        let mut ack = AckRanges::new(1);
        ack.insert(4..8).unwrap();
        let before = ack.clone();
        assert_eq!(ack.insert(12..16), Err(RecoveryError::RangeCapacity));
        assert_eq!(ack.contiguous(), before.contiguous());
        assert_eq!(ack.ranges(), before.ranges());
    }

    #[test]
    fn reassembler_is_ordered_and_fin_waits_for_gap() {
        let mut reassembler = Reassembler::new(16);
        reassembler.insert(4, Bytes::from_static(b"efgh")).unwrap();
        reassembler.set_final_offset(8).unwrap();
        assert!(!reassembler.is_finished());
        reassembler.insert(0, Bytes::from_static(b"abcd")).unwrap();
        let mut output = [0; 8];
        assert_eq!(reassembler.read(&mut output), 8);
        assert_eq!(&output, b"abcdefgh");
        assert!(reassembler.is_finished());
    }

    #[test]
    fn one_flow_gap_does_not_block_another_flow() {
        let mut blocked = Reassembler::new(16);
        blocked.insert(4, Bytes::from_static(b"gap!")).unwrap();
        let mut ready = Reassembler::new(16);
        ready.insert(0, Bytes::from_static(b"ready")).unwrap();
        let mut output = [0; 5];
        assert_eq!(blocked.read(&mut output), 0);
        assert_eq!(ready.read(&mut output), 5);
        assert_eq!(&output, b"ready");
    }

    #[test]
    fn contradictory_overlap_and_limits_fail_closed() {
        let mut reassembler = Reassembler::new(4);
        reassembler.insert(0, Bytes::from_static(b"abcd")).unwrap();
        assert_eq!(
            reassembler.insert(0, Bytes::from_static(b"abce")),
            Err(RecoveryError::ContradictoryOverlap)
        );
        assert_eq!(
            reassembler.insert(MAX_WIRE_OFFSET, Bytes::from_static(b"x")),
            Err(RecoveryError::OffsetOverflow)
        );
    }

    #[test]
    fn identical_overlap_is_deduplicated_and_can_add_fin() {
        let budget = Arc::new(RecoveryMemoryBudget::new(22));
        let mut reassembler = Reassembler::with_budget(16, budget);
        reassembler
            .insert_record(2, Bytes::from_static(b"cdef"), false)
            .unwrap();
        reassembler
            .insert_record(0, Bytes::from_static(b"abcd"), false)
            .unwrap();
        reassembler
            .insert_record(2, Bytes::from_static(b"cdef"), true)
            .unwrap();

        let mut output = [0; 6];
        assert_eq!(reassembler.read(&mut output), 6);
        assert_eq!(&output, b"abcdef");
        assert!(reassembler.is_finished());
    }

    #[test]
    fn overlapping_gap_copy_budget_is_exact_and_failure_is_atomic() {
        let exact = u32::try_from(4 + 4 + 2 + size_of::<Range<u64>>()).unwrap();
        let budget = Arc::new(RecoveryMemoryBudget::new(exact));
        let mut reassembler = Reassembler::with_budget(16, Arc::clone(&budget));
        reassembler
            .insert_record(2, Bytes::from_static(b"cdef"), false)
            .unwrap();
        reassembler
            .insert_record_with_charge(0, Bytes::from_static(b"abcd"), false, 4)
            .unwrap();
        assert_eq!(reassembler.buffered_bytes(), 6);
        drop(reassembler);
        assert_eq!(budget.used(), 0);

        let budget = Arc::new(RecoveryMemoryBudget::new(exact - 1));
        let mut reassembler = Reassembler::with_budget(16, Arc::clone(&budget));
        reassembler
            .insert_record(2, Bytes::from_static(b"cdef"), false)
            .unwrap();
        assert_eq!(
            reassembler.insert_record_with_charge(0, Bytes::from_static(b"abcd"), false, 4),
            Err(RecoveryError::Capacity)
        );
        assert_eq!(reassembler.buffered_bytes(), 4);
        assert_eq!(budget.used(), 4);
        drop(reassembler);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn reassembler_bounds_fragment_metadata() {
        let mut reassembler = Reassembler::new(128);
        for offset in (1..16).step_by(2) {
            reassembler
                .insert(offset, Bytes::from_static(b"x"))
                .unwrap();
        }
        assert_eq!(
            reassembler.insert(17, Bytes::from_static(b"x")),
            Err(RecoveryError::Capacity)
        );
    }

    #[test]
    fn endpoint_reassembly_budget_is_shared_and_released() {
        let budget = Arc::new(RecoveryMemoryBudget::new(4));
        let mut first = Reassembler::with_budget(4, Arc::clone(&budget));
        let mut second = Reassembler::with_budget(4, Arc::clone(&budget));
        first.insert(0, Bytes::from_static(b"abcd")).unwrap();
        assert_eq!(
            second.insert(0, Bytes::from_static(b"x")),
            Err(RecoveryError::Capacity)
        );
        let mut output = [0; 2];
        assert_eq!(first.read(&mut output), 2);
        assert_eq!(
            second.insert(0, Bytes::from_static(b"x")),
            Err(RecoveryError::Capacity)
        );
        assert_eq!(first.read(&mut output), 2);
        assert_eq!(budget.used(), 4);
        first.acknowledge_consumed(4);
        second.insert(0, Bytes::from_static(b"x")).unwrap();
        assert_eq!(budget.used(), 1);
        drop(first);
        drop(second);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn reassembler_charges_shared_backing_until_the_last_slice_is_read() {
        let budget = Arc::new(RecoveryMemoryBudget::new(64));
        let packet = Bytes::from(vec![0x5a; 64]);
        let data = packet.slice(8..16);
        let mut reassembler = Reassembler::with_budget(8, Arc::clone(&budget));
        reassembler
            .insert_record_with_charge(0, data, false, packet.len())
            .unwrap();
        drop(packet);
        let mut output = [0; 4];
        assert_eq!(reassembler.read(&mut output), 4);
        assert_eq!(budget.used(), 64);
        assert_eq!(reassembler.read(&mut output), 4);
        assert_eq!(budget.used(), 64);
        reassembler.acknowledge_consumed(8);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn consumed_overlap_is_validated_until_ack_is_written() {
        let budget = Arc::new(RecoveryMemoryBudget::new(4));
        let mut reassembler = Reassembler::with_budget(4, Arc::clone(&budget));
        reassembler.insert(0, Bytes::from_static(b"data")).unwrap();
        let mut output = [0; 4];
        assert_eq!(reassembler.read(&mut output), 4);
        assert_eq!(budget.used(), 4);
        assert_eq!(
            reassembler.insert(0, Bytes::from_static(b"date")),
            Err(RecoveryError::ContradictoryOverlap)
        );

        reassembler.acknowledge_consumed(4);
        assert_eq!(budget.used(), 0);
        reassembler.insert(0, Bytes::from_static(b"date")).unwrap();
    }

    #[test]
    fn ack_before_partial_read_preserves_the_unread_suffix() {
        let budget = Arc::new(RecoveryMemoryBudget::new(8));
        let mut reassembler = Reassembler::with_budget(8, Arc::clone(&budget));
        reassembler
            .insert(0, Bytes::from_static(b"abcdefgh"))
            .unwrap();
        reassembler.acknowledge_consumed(8);

        let mut prefix = [0; 4];
        assert_eq!(reassembler.read(&mut prefix), 4);
        assert_eq!(&prefix, b"abcd");
        assert_eq!(budget.used(), 8);

        let mut suffix = [0; 4];
        assert_eq!(reassembler.read(&mut suffix), 4);
        assert_eq!(&suffix, b"efgh");
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn replay_over_a_consumed_prefix_is_idempotent() {
        let mut reassembler = Reassembler::new(16);
        reassembler
            .insert(0, Bytes::from_static(b"abcdefgh"))
            .unwrap();
        let mut prefix = [0; 4];
        assert_eq!(reassembler.read(&mut prefix), 4);
        assert_eq!(&prefix, b"abcd");
        reassembler
            .insert(0, Bytes::from_static(b"abcdefgh"))
            .unwrap();
        let mut suffix = [0; 4];
        assert_eq!(reassembler.read(&mut suffix), 4);
        assert_eq!(&suffix, b"efgh");
    }

    #[test]
    fn pre_open_records_expire() {
        let now = Instant::now();
        let budget = Arc::new(RecoveryMemoryBudget::new(6));
        let mut records = HashMap::from([(
            7,
            vec![
                PreOpenRecord {
                    offset: 0,
                    fin: false,
                    data: Bytes::from_static(b"old"),
                    charge: RecoveryCharge::reserve(Arc::clone(&budget), 3).unwrap(),
                    expires_at: now,
                },
                PreOpenRecord {
                    offset: 3,
                    fin: false,
                    data: Bytes::from_static(b"new"),
                    charge: RecoveryCharge::reserve(Arc::clone(&budget), 3).unwrap(),
                    expires_at: now + PRE_OPEN_TTL,
                },
            ],
        )]);
        assert_eq!(prune_pre_open(&mut records, now), 1);
        assert_eq!(records[&7].len(), 1);
        assert_eq!(budget.used(), 3);
    }

    #[test]
    fn pre_open_batch_reservation_is_atomic() {
        let reserved = AtomicU32::new(1);
        assert!(!reserve_bounded(&reserved, 2, 2));
        assert_eq!(reserved.load(Ordering::Relaxed), 1);
        assert!(reserve_bounded(&reserved, 2, 1));
        assert_eq!(reserved.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn production_repair_seed_yields_independent_equations() {
        let first = 10;
        let sources = [
            encoded_source(first, b"one!"),
            encoded_source(first + 1, b"two!"),
        ];
        let seed = repair_seed(first);
        let repair_a = repair_symbol(first, 100, seed, &sources).unwrap();
        let repair_b = repair_symbol(first, 101, seed, &sources).unwrap();
        let mut decoder = Decoder::new(16, 16, 1_200);
        assert!(
            decoder
                .add_repair(first, 2, 100, seed, &repair_a, 20_000)
                .unwrap()
                .is_empty()
        );
        let recovered = decoder
            .add_repair(first, 2, 101, seed, &repair_b, 20_000)
            .unwrap();
        assert_eq!(
            recovered
                .iter()
                .map(|source| (source.symbol_id, source.bytes.clone()))
                .collect::<Vec<_>>(),
            [(first, sources[0].clone()), (first + 1, sources[1].clone())]
        );
    }

    fn encoded_source(symbol_id: u32, payload: &'static [u8]) -> Bytes {
        let mut encoded = Vec::new();
        encode_source(
            symbol_id,
            &[SourceRecord {
                flow_id: 1,
                offset: u64::from(symbol_id),
                fin: false,
                data: payload,
            }],
            &mut encoded,
        )
        .unwrap();
        Bytes::from(encoded)
    }
}
