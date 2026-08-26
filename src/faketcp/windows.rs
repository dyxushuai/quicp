//! Windows Tier 0 `FakeTCP` adapter backed by the signed WinDivert WFP driver.
//!
//! Winsock raw TCP cannot inject TCP packets on supported Windows client versions. WinDivert
//! supplies the packet-divert and reinjection boundary; this module owns only the adapter and
//! keeps the QUICP/FakeTCP codec in the parent module. The caller must ship a matching, signed
//! WinDivert distribution and run with administrator privileges.

use super::{
    Arc, CarrierDirection, CarrierError, FakeTcpCarrier, FourTuple, IPV4_HEADER_BYTES,
    MAX_PACKET_BYTES, MAX_TCP_OPTIONS_BYTES, SocketAddr, SynDataMode, TCP_HEADER_BYTES, Vec,
};
use noq::udp::{RecvMeta, Transmit};
use noq::{AsyncUdpSocket, UdpSender};
use std::ffi::{CString, c_char, c_void};
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, sync_channel};
use std::task::{Context, Poll, Waker};
use std::thread;

const MAX_DECODE_REJECTS_PER_POLL: usize = 64;
const CHANNEL_CAPACITY: usize = 256;

// WINDIVERT_ADDRESS flags are a UINT64 bitfield in the upstream C ABI.
const ADDRESS_OUTBOUND: u64 = 1 << 17;
const ADDRESS_IMPOSTOR: u64 = 1 << 19;
const ADDRESS_IP_CHECKSUM: u64 = 1 << 21;
const ADDRESS_TCP_CHECKSUM: u64 = 1 << 22;
const WINDIVERT_LAYER_NETWORK: i32 = 0;
const WINDIVERT_SHUTDOWN_BOTH: u32 = 3;
const INVALID_HANDLE_VALUE: isize = -1;

#[repr(C)]
#[derive(Clone, Copy)]
struct WinDivertAddress {
    timestamp: i64,
    flags: u64,
    data: [u8; 64],
}

impl Default for WinDivertAddress {
    fn default() -> Self {
        Self {
            timestamp: 0,
            flags: 0,
            data: [0; 64],
        }
    }
}

const _: () = assert!(core::mem::size_of::<WinDivertAddress>() == 80);
const _: () = assert!(core::mem::align_of::<WinDivertAddress>() == 8);

#[allow(unsafe_code)]
mod ffi {
    use super::{WinDivertAddress, c_char, c_void, io};

    type Open = unsafe extern "system" fn(*const c_char, i32, i16, u64) -> isize;
    type Receive =
        unsafe extern "system" fn(isize, *mut c_void, u32, *mut u32, *mut WinDivertAddress) -> i32;
    type Send = unsafe extern "system" fn(
        isize,
        *const c_void,
        u32,
        *mut u32,
        *const WinDivertAddress,
    ) -> i32;
    type Shutdown = unsafe extern "system" fn(isize, u32) -> i32;
    type Close = unsafe extern "system" fn(isize) -> i32;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn FreeLibrary(module: *mut c_void) -> i32;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
        fn LoadLibraryA(name: *const u8) -> *mut c_void;
    }

    #[derive(Debug)]
    pub(super) struct Api {
        module: usize,
        pub(super) open: Open,
        pub(super) receive: Receive,
        pub(super) send: Send,
        pub(super) shutdown: Shutdown,
        pub(super) close: Close,
    }

    impl Api {
        #[allow(unsafe_code)]
        pub(super) fn load() -> io::Result<Self> {
            let module = unsafe { LoadLibraryA(c"WinDivert.dll".as_ptr().cast()) };
            if module.is_null() {
                return Err(io::Error::last_os_error());
            }
            let result = unsafe {
                Ok(Self {
                    module: module as usize,
                    open: load_symbol(module, c"WinDivertOpen".as_ptr())?,
                    receive: load_symbol(module, c"WinDivertRecv".as_ptr())?,
                    send: load_symbol(module, c"WinDivertSend".as_ptr())?,
                    shutdown: load_symbol(module, c"WinDivertShutdown".as_ptr())?,
                    close: load_symbol(module, c"WinDivertClose".as_ptr())?,
                })
            };
            if result.is_err() {
                unsafe {
                    let _ = FreeLibrary(module);
                }
            }
            result
        }
    }

    #[allow(unsafe_code)]
    unsafe fn load_symbol<T: Copy>(module: *mut c_void, name: *const c_char) -> io::Result<T> {
        let symbol = unsafe { GetProcAddress(module, name.cast()) };
        if symbol.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { core::mem::transmute_copy(&symbol) })
    }

    #[allow(unsafe_code)]
    impl Drop for Api {
        fn drop(&mut self) {
            unsafe {
                let _ = FreeLibrary(self.module as *mut c_void);
            }
        }
    }
}

#[allow(unsafe_code)]
#[derive(Debug)]
struct WinDivertState {
    api: Arc<ffi::Api>,
    handle: isize,
    stopped: AtomicBool,
}

#[allow(unsafe_code)]
impl WinDivertState {
    fn stop(&self) {
        if !self.stopped.swap(true, Ordering::AcqRel) {
            unsafe {
                let _ = (self.api.shutdown)(self.handle, WINDIVERT_SHUTDOWN_BOTH);
            }
        }
    }

    fn receive(&self, packet: &mut [u8], address: &mut WinDivertAddress) -> io::Result<usize> {
        let packet_len = u32::try_from(packet.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "WinDivert packet buffer is too large",
            )
        })?;
        let mut received = 0u32;
        let ok = unsafe {
            (self.api.receive)(
                self.handle,
                packet.as_mut_ptr().cast(),
                packet_len,
                &mut received,
                address,
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(received as usize)
        }
    }

    fn send(&self, packet: &[u8], address: &WinDivertAddress) -> io::Result<()> {
        let packet_len = u32::try_from(packet.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "WinDivert packet is too large")
        })?;
        let mut sent = 0u32;
        let ok = unsafe {
            (self.api.send)(
                self.handle,
                packet.as_ptr().cast(),
                packet_len,
                &mut sent,
                address,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if sent != packet_len {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "WinDivert injected only part of a packet",
            ));
        }
        Ok(())
    }
}

#[allow(unsafe_code)]
impl Drop for WinDivertState {
    fn drop(&mut self) {
        self.stop();
        unsafe {
            let _ = (self.api.close)(self.handle);
        }
    }
}

fn carrier_io_error(error: CarrierError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn build_filter(tuple: FourTuple) -> io::Result<CString> {
    let source = tuple.source.ip();
    let destination = tuple.destination.ip();
    if !source.is_ipv4() || !destination.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows WinDivert carrier currently supports IPv4 only",
        ));
    }
    let filter = format!(
        "ip and tcp and !impostor and ((outbound and ip.SrcAddr == {source} and ip.DstAddr == {destination} and tcp.SrcPort == {} and tcp.DstPort == {}) or (inbound and ip.SrcAddr == {destination} and ip.DstAddr == {source} and tcp.SrcPort == {} and tcp.DstPort == {}))",
        tuple.source.port(),
        tuple.destination.port(),
        tuple.destination.port(),
        tuple.source.port(),
    );
    CString::new(filter)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "WinDivert filter contains NUL"))
}

fn wake(waker: &Mutex<Option<Waker>>) {
    if let Ok(mut guard) = waker.lock() {
        if let Some(waker) = guard.take() {
            waker.wake();
        }
    }
}

fn spawn_receiver(
    state: Arc<WinDivertState>,
    sender: SyncSender<io::Result<Vec<u8>>>,
    waker: Arc<Mutex<Option<Waker>>>,
) -> io::Result<()> {
    thread::Builder::new()
        .name("quicp-windivert-recv".to_owned())
        .spawn(move || {
            let mut packet = vec![0; MAX_PACKET_BYTES];
            loop {
                if state.stopped.load(Ordering::Acquire) {
                    break;
                }
                let mut address = WinDivertAddress::default();
                match state.receive(&mut packet, &mut address) {
                    Ok(length) if length > 0 && length <= packet.len() => {
                        if sender.send(Ok(packet[..length].to_vec())).is_err() {
                            break;
                        }
                        wake(&waker);
                    }
                    Ok(_) => {}
                    Err(_error) if state.stopped.load(Ordering::Acquire) => break,
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        wake(&waker);
                        break;
                    }
                }
            }
        })
        .map(|_| ())
}

/// One Windows WinDivert-backed `FakeTCP` path.
#[derive(Debug)]
pub struct FakeTcpSocket {
    state: Arc<WinDivertState>,
    tuple: FourTuple,
    inbound: FakeTcpCarrier,
    outbound: Arc<Mutex<FakeTcpCarrier>>,
    server_side: bool,
    receiver: Mutex<Receiver<io::Result<Vec<u8>>>>,
    waker: Arc<Mutex<Option<Waker>>>,
    decode_rejects: u64,
}

impl FakeTcpSocket {
    /// Binds a Windows Tier 0 carrier through the signed WinDivert WFP driver.
    ///
    /// The caller must install `WinDivert.dll` and its matching signed driver files, and the
    /// process must have administrator privileges. The tuple is reserved exclusively by this
    /// handle; malformed packets and kernel-generated RSTs are diverted and dropped.
    ///
    /// # Errors
    ///
    /// Returns an error when WinDivert is unavailable, the tuple is invalid, or the driver denies
    /// the requested packet filter.
    #[allow(unsafe_code)]
    pub fn bind(
        tuple: FourTuple,
        outbound_direction: CarrierDirection,
        syn_data: SynDataMode,
        syn_mss: u16,
        outer_mtu: u16,
        _packet_socket: bool,
    ) -> io::Result<Self> {
        tuple.validate().map_err(carrier_io_error)?;
        let filter = build_filter(tuple)?;
        let (inbound, outbound) =
            FakeTcpCarrier::pair_with_mtu(tuple, outbound_direction, syn_data, syn_mss, outer_mtu)
                .map_err(carrier_io_error)?;
        let api = Arc::new(ffi::Api::load()?);
        let handle = unsafe { (api.open)(filter.as_ptr(), WINDIVERT_LAYER_NETWORK, 0, 0) };
        if handle == INVALID_HANDLE_VALUE || handle == 0 {
            return Err(io::Error::last_os_error());
        }
        let state = Arc::new(WinDivertState {
            api,
            handle,
            stopped: AtomicBool::new(false),
        });
        let (sender, receiver) = sync_channel(CHANNEL_CAPACITY);
        let waker = Arc::new(Mutex::new(None));
        if let Err(error) = spawn_receiver(Arc::clone(&state), sender, Arc::clone(&waker)) {
            state.stop();
            return Err(error);
        }
        Ok(Self {
            state,
            tuple,
            inbound,
            outbound: Arc::new(Mutex::new(outbound)),
            server_side: outbound_direction == CarrierDirection::ServerToClient,
            receiver: Mutex::new(receiver),
            waker,
            decode_rejects: 0,
        })
    }

    /// Number of packets rejected by the carrier decoder.
    #[must_use]
    pub const fn rejected_datagrams(&self) -> u64 {
        self.decode_rejects
    }

    fn next_packet(&mut self, cx: &Context<'_>) -> Option<io::Result<Vec<u8>>> {
        let receiver = match self.receiver.lock() {
            Ok(receiver) => receiver,
            Err(_) => return Some(Err(io::Error::other("WinDivert receiver poisoned"))),
        };
        match receiver.try_recv() {
            Ok(packet) => Some(packet),
            Err(TryRecvError::Disconnected) => Some(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "WinDivert receiver stopped",
            ))),
            Err(TryRecvError::Empty) => {
                let Ok(mut guard) = self.waker.lock() else {
                    return Some(Err(io::Error::other("WinDivert waker poisoned")));
                };
                *guard = Some(cx.waker().clone());
                match receiver.try_recv() {
                    Ok(packet) => Some(packet),
                    Err(TryRecvError::Disconnected) => Some(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "WinDivert receiver stopped",
                    ))),
                    Err(TryRecvError::Empty) => None,
                }
            }
        }
    }
}

impl Drop for FakeTcpSocket {
    fn drop(&mut self) {
        self.state.stop();
    }
}

impl AsyncUdpSocket for FakeTcpSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(FakeTcpSender {
            state: Arc::clone(&self.state),
            tuple: self.tuple,
            carrier: Arc::clone(&self.outbound),
            server_side: self.server_side,
            pending: vec![0; MAX_PACKET_BYTES],
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no receive buffer",
            )));
        }
        let mut rejects = 0;
        loop {
            let Some(packet) = self.next_packet(cx) else {
                return Poll::Pending;
            };
            let packet = match packet {
                Ok(packet) => packet,
                Err(error) => return Poll::Ready(Err(error)),
            };
            let decoded = match self.inbound.decode_datagram_borrowed(&packet) {
                Ok(decoded) => decoded,
                Err(_) => {
                    self.decode_rejects = self.decode_rejects.saturating_add(1);
                    rejects += 1;
                    if rejects >= MAX_DECODE_REJECTS_PER_POLL {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    continue;
                }
            };
            let payload = decoded.payload();
            if payload.len() > bufs[0].len() {
                self.decode_rejects = self.decode_rejects.saturating_add(1);
                rejects += 1;
                if rejects >= MAX_DECODE_REJECTS_PER_POLL {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                continue;
            }
            bufs[0][..payload.len()].copy_from_slice(payload);
            let mut received = RecvMeta::default();
            received.addr = self.tuple.destination;
            received.len = payload.len();
            received.stride = payload.len();
            received.dst_ip = Some(self.tuple.source.ip());
            meta[0] = received;
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.tuple.source)
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        NonZeroUsize::new(1).expect("one receive segment")
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct FakeTcpSender {
    state: Arc<WinDivertState>,
    tuple: FourTuple,
    carrier: Arc<Mutex<FakeTcpCarrier>>,
    server_side: bool,
    pending: Vec<u8>,
}

impl UdpSender for FakeTcpSender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if transmit.destination != this.tuple.destination {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FakeTCP sender destination does not match its path",
            )));
        }
        if transmit
            .src_ip
            .is_some_and(|source| source != this.tuple.source.ip())
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FakeTCP sender source does not match its path",
            )));
        }
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        if segment_size == 0 || transmit.contents.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FakeTCP sender received invalid segmentation metadata",
            )));
        }
        let segment_count = transmit.contents.len().div_ceil(segment_size);
        let packet_capacity = segment_size
            .checked_add(IPV4_HEADER_BYTES + TCP_HEADER_BYTES + MAX_TCP_OPTIONS_BYTES)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "FakeTCP packet capacity overflow",
                )
            });
        let packet_capacity = match packet_capacity {
            Ok(capacity) => capacity,
            Err(error) => return Poll::Ready(Err(error)),
        };
        if this.pending.len() < packet_capacity {
            this.pending.resize(packet_capacity, 0);
        }
        let mut carrier = match this.carrier.lock() {
            Ok(carrier) => carrier,
            Err(_) => return Poll::Ready(Err(io::Error::other("FakeTCP send state poisoned"))),
        };
        let address = WinDivertAddress {
            flags: ADDRESS_OUTBOUND | ADDRESS_IMPOSTOR | ADDRESS_IP_CHECKSUM | ADDRESS_TCP_CHECKSUM,
            ..WinDivertAddress::default()
        };
        for segment in 0..segment_count {
            let start = segment * segment_size;
            let end = (start + segment_size).min(transmit.contents.len());
            let length = if carrier.sent_syn {
                carrier.encode_datagram_into(
                    &transmit.contents[start..end],
                    &mut this.pending[..packet_capacity],
                )
            } else if this.server_side {
                carrier.encode_syn_ack_into(
                    &transmit.contents[start..end],
                    &mut this.pending[..packet_capacity],
                )
            } else {
                carrier.encode_syn_into(
                    &transmit.contents[start..end],
                    &mut this.pending[..packet_capacity],
                )
            };
            let length = match length.map_err(carrier_io_error) {
                Ok(length) => length,
                Err(error) => return Poll::Ready(Err(error)),
            };
            if let Err(error) = this.state.send(&this.pending[..length], &address) {
                return Poll::Ready(Err(error));
            }
        }
        Poll::Ready(Ok(()))
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::new(1).expect("one transmit segment")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn filter_covers_both_directions_of_one_tuple() {
        let tuple = FourTuple::new(
            SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 40_000)),
            SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 44_443)),
        );
        let filter = build_filter(tuple)
            .expect("valid IPv4 tuple")
            .into_string()
            .expect("filter is UTF-8");
        assert!(filter.contains("outbound"));
        assert!(filter.contains("inbound"));
        assert!(filter.contains("192.0.2.1"));
        assert!(filter.contains("198.51.100.1"));
        assert!(filter.contains("40000"));
        assert!(filter.contains("44443"));
    }

    #[test]
    fn filter_rejects_ipv6_until_the_adapter_supports_it() {
        let tuple = FourTuple::new(
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 40_000)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 2], 44_443)),
        );
        assert_eq!(
            build_filter(tuple)
                .expect_err("IPv6 is not admitted by the Windows adapter")
                .kind(),
            io::ErrorKind::Unsupported
        );
    }
}
