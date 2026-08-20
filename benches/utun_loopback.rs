#[cfg(target_os = "macos")]
use std::hint::black_box;
#[cfg(target_os = "macos")]
use std::io::{self, ErrorKind, Read, Write};
#[cfg(target_os = "macos")]
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
#[cfg(target_os = "macos")]
use std::pin::Pin;
#[cfg(target_os = "macos")]
use std::sync::mpsc::{self, Receiver, SyncSender};
#[cfg(target_os = "macos")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "macos")]
use std::task::{Context, Poll};
#[cfg(target_os = "macos")]
use std::thread;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use quicp::config::{
    CarrierConfig, ClientConfig, Ipv4Pool, Multipath, MultipathMode, PathCandidate, ServerConfig,
    ZeroRttMode,
};
#[cfg(target_os = "macos")]
use quicp::faketcp::{CarrierDirection, FakeTcpCarrier, FourTuple, SynDataMode};
#[cfg(target_os = "macos")]
use quicp::flow::{QuicpFlow, accept_flow};
#[cfg(target_os = "macos")]
use quicp::transport::{build_client_endpoint_with_socket, build_server_endpoint_with_socket};
#[cfg(target_os = "macos")]
use quicp::wire::{CanonicalHost, OpenRequest};
#[cfg(target_os = "macos")]
use smoltcp::iface::{Config, Interface, SocketSet};
#[cfg(target_os = "macos")]
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
#[cfg(target_os = "macos")]
use smoltcp::socket::tcp;
#[cfg(target_os = "macos")]
use smoltcp::time::Instant as SmolInstant;
#[cfg(target_os = "macos")]
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
#[cfg(target_os = "macos")]
use tun_rs::{DeviceBuilder, SyncDevice};

#[cfg(target_os = "macos")]
use noq::udp::{RecvMeta, Transmit};
#[cfg(target_os = "macos")]
use noq::{AsyncUdpSocket, UdpSender};
#[cfg(target_os = "macos")]
use tokio::io::unix::AsyncFd;

#[cfg(target_os = "macos")]
const ITERATIONS: usize = 20_480;
#[cfg(target_os = "macos")]
const CHUNK_QUEUE: usize = 64;
#[cfg(target_os = "macos")]
const PAYLOADS: &[usize] = &[64, 1_200, 4_096];
#[cfg(target_os = "macos")]
const A_LOCAL: Ipv4Addr = Ipv4Addr::new(198, 18, 240, 1);
#[cfg(target_os = "macos")]
const A_PEER: Ipv4Addr = Ipv4Addr::new(198, 18, 240, 2);
#[cfg(target_os = "macos")]
const B_LOCAL: Ipv4Addr = Ipv4Addr::new(198, 18, 241, 1);
#[cfg(target_os = "macos")]
const B_PEER: Ipv4Addr = Ipv4Addr::new(198, 18, 241, 2);
#[cfg(target_os = "macos")]
const C_LOCAL: Ipv4Addr = Ipv4Addr::new(198, 18, 242, 1);
#[cfg(target_os = "macos")]
const C_PEER: Ipv4Addr = Ipv4Addr::new(198, 18, 242, 2);
#[cfg(target_os = "macos")]
const D_LOCAL: Ipv4Addr = Ipv4Addr::new(198, 18, 243, 1);
#[cfg(target_os = "macos")]
const D_PEER: Ipv4Addr = Ipv4Addr::new(198, 18, 243, 2);
#[cfg(target_os = "macos")]
const INGRESS_PORT: u16 = 44_443;
#[cfg(target_os = "macos")]
const EGRESS_PORT: u16 = 44_444;
#[cfg(target_os = "macos")]
const APP_SOURCE_PORT: u16 = 40_001;
#[cfg(target_os = "macos")]
const GATEWAY_SOURCE_PORT: u16 = 40_002;
#[cfg(target_os = "macos")]
const DEADLINE: Duration = Duration::from_secs(30);
#[cfg(target_os = "macos")]
const CARRIER_COOKIE: SynDataMode = SynDataMode::Cookie([0x24; 16]);

#[cfg(target_os = "macos")]
type ChunkSender = tokio::sync::mpsc::Sender<Vec<u8>>;
#[cfg(target_os = "macos")]
type ChunkReceiver = tokio::sync::mpsc::Receiver<Vec<u8>>;

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug)]
enum TransportMode {
    Tcp,
    Quicp,
}

#[cfg(target_os = "macos")]
struct UtunDevice {
    device: SyncDevice,
}

#[cfg(target_os = "macos")]
struct UtunRxToken {
    packet: Vec<u8>,
}

#[cfg(target_os = "macos")]
struct UtunTxToken<'a> {
    device: &'a SyncDevice,
}

#[cfg(target_os = "macos")]
impl UtunDevice {
    fn new(device: SyncDevice) -> Self {
        Self { device }
    }
}

#[cfg(target_os = "macos")]
impl Device for UtunDevice {
    type RxToken<'a>
        = UtunRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = UtunTxToken<'a>
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut packet = vec![0_u8; 9_000];
        match self.device.recv(&mut packet) {
            Ok(length) => {
                packet.truncate(length);
                Some((
                    UtunRxToken { packet },
                    UtunTxToken {
                        device: &self.device,
                    },
                ))
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => None,
            Err(error) => panic!("utun receive failed: {error}"),
        }
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(UtunTxToken {
            device: &self.device,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 9_000;
        capabilities.max_burst_size = Some(32);
        capabilities
    }
}

#[cfg(target_os = "macos")]
impl RxToken for UtunRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

#[cfg(target_os = "macos")]
impl TxToken for UtunTxToken<'_> {
    fn consume<R, F>(self, length: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0_u8; length];
        let result = f(&mut packet);
        send_packet(self.device, &packet).expect("utun transmit failed");
        result
    }
}

#[cfg(target_os = "macos")]
struct TunCarrierSocket {
    io: Arc<AsyncFd<SyncDevice>>,
    tuple: FourTuple,
    server_side: bool,
    inbound: Arc<Mutex<FakeTcpCarrier>>,
    outbound: Arc<Mutex<FakeTcpCarrier>>,
    receive_buffer: Vec<u8>,
}

#[cfg(target_os = "macos")]
impl std::fmt::Debug for TunCarrierSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TunCarrierSocket")
            .field("tuple", &self.tuple)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "macos")]
impl TunCarrierSocket {
    fn new(device: SyncDevice, tuple: FourTuple, direction: CarrierDirection) -> io::Result<Self> {
        let inbound =
            FakeTcpCarrier::new(tuple, direction, CARRIER_COOKIE).map_err(carrier_error)?;
        let outbound =
            FakeTcpCarrier::new(tuple, direction, CARRIER_COOKIE).map_err(carrier_error)?;
        Ok(Self {
            io: Arc::new(AsyncFd::new(device)?),
            tuple,
            server_side: matches!(direction, CarrierDirection::ServerToClient),
            inbound: Arc::new(Mutex::new(inbound)),
            outbound: Arc::new(Mutex::new(outbound)),
            receive_buffer: vec![0; 65_535],
        })
    }
}

#[cfg(target_os = "macos")]
impl AsyncUdpSocket for TunCarrierSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(TunCarrierSender {
            io: Arc::clone(&self.io),
            tuple: self.tuple,
            server_side: self.server_side,
            carrier: Arc::clone(&self.outbound),
            pending: vec![0; 65_535],
            pending_len: 0,
            sent_syn: false,
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
                ErrorKind::InvalidInput,
                "no receive buffer",
            )));
        }
        loop {
            let mut guard = match self.io.poll_read_ready(cx) {
                Poll::Ready(Ok(guard)) => guard,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            };
            let result = guard.try_io(|inner| {
                let length = inner.get_ref().recv(&mut self.receive_buffer)?;
                let decoded = self
                    .inbound
                    .lock()
                    .map_err(|_| io::Error::other("FakeTCP receive state poisoned"))?
                    .decode_datagram_borrowed(&self.receive_buffer[..length]);
                let Ok(decoded) = decoded else {
                    return Ok(None);
                };
                if decoded.payload().len() > bufs[0].len() {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        "QUICP datagram exceeds receive buffer",
                    ));
                }
                bufs[0][..decoded.payload().len()].copy_from_slice(decoded.payload());
                let mut received = RecvMeta::default();
                received.addr = self.tuple.destination;
                received.len = decoded.payload().len();
                received.stride = decoded.payload().len();
                received.dst_ip = Some(self.tuple.source.ip());
                meta[0] = received;
                Ok(Some(()))
            });
            match result {
                Ok(Ok(Some(()))) => return Poll::Ready(Ok(1)),
                Ok(Ok(None)) | Err(_) => {}
                Ok(Err(error)) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.tuple.source)
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[cfg(target_os = "macos")]
struct TunCarrierSender {
    io: Arc<AsyncFd<SyncDevice>>,
    tuple: FourTuple,
    server_side: bool,
    carrier: Arc<Mutex<FakeTcpCarrier>>,
    pending: Vec<u8>,
    pending_len: usize,
    sent_syn: bool,
}

#[cfg(target_os = "macos")]
impl std::fmt::Debug for TunCarrierSender {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TunCarrierSender")
            .field("tuple", &self.tuple)
            .field("pending_len", &self.pending_len)
            .finish_non_exhaustive()
    }
}

#[cfg(target_os = "macos")]
impl UdpSender for TunCarrierSender {
    fn poll_send(
        mut self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        if transmit.destination != self.tuple.destination || transmit.segment_size.is_some() {
            return Poll::Ready(Err(io::Error::new(
                ErrorKind::InvalidInput,
                "TUN FakeTCP carrier received unsupported transmit",
            )));
        }
        if self.pending_len == 0 {
            let sent_syn = self.sent_syn;
            let server_side = self.server_side;
            let carrier = Arc::clone(&self.carrier);
            let pending = &mut self.pending;
            let length = carrier
                .lock()
                .map_err(|_| io::Error::other("FakeTCP send state poisoned"))
                .and_then(|mut carrier| {
                    if sent_syn {
                        carrier
                            .encode_datagram_into(transmit.contents, pending)
                            .map_err(carrier_error)
                    } else if server_side {
                        carrier
                            .encode_syn_ack_into(transmit.contents, pending)
                            .map_err(carrier_error)
                    } else {
                        carrier
                            .encode_syn_into(transmit.contents, pending)
                            .map_err(carrier_error)
                    }
                });
            self.pending_len = match length {
                Ok(length) => length,
                Err(error) => return Poll::Ready(Err(error)),
            };
        }
        let mut guard = match self.io.poll_write_ready(cx) {
            Poll::Ready(Ok(guard)) => guard,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        };
        match guard.try_io(|inner| inner.get_ref().send(&self.pending[..self.pending_len])) {
            Ok(Ok(length)) if length == self.pending_len => {
                self.pending_len = 0;
                self.sent_syn = true;
                Poll::Ready(Ok(()))
            }
            Ok(Ok(_)) => Poll::Ready(Err(io::Error::new(
                ErrorKind::WriteZero,
                "partial TUN FakeTCP packet",
            ))),
            Ok(Err(error)) => Poll::Ready(Err(error)),
            Err(_) => Poll::Pending,
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("utun QUICP/TCP no-TLS bench skipped: macOS only");
}

#[cfg(target_os = "macos")]
fn main() -> io::Result<()> {
    if !forwarding_enabled() {
        println!("utun QUICP/TCP no-TLS bench skipped: set net.inet.ip.forwarding=1 for the run");
        return Ok(());
    }
    println!(
        "payload_bytes,tcp_ns_per_payload,quicp_no_tls_ns_per_payload,tcp_gbps,quicp_no_tls_gbps"
    );
    for &payload_size in PAYLOADS {
        let tcp = transport_sample(payload_size, TransportMode::Tcp).map_err(|error| {
            io::Error::new(error.kind(), format!("tcp payload {payload_size}: {error}"))
        })?;
        let quicp = transport_sample(payload_size, TransportMode::Quicp).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("quicp payload {payload_size}: {error}"),
            )
        })?;
        println!(
            "{payload_size},{},{},{},{}",
            nanos_per_payload(tcp),
            nanos_per_payload(quicp),
            gbps(payload_size, tcp),
            gbps(payload_size, quicp),
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn forwarding_enabled() -> bool {
    std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "net.inet.ip.forwarding"])
        .output()
        .is_ok_and(|output| String::from_utf8_lossy(&output.stdout).trim() == "1")
}

#[cfg(target_os = "macos")]
fn build_device(address: Ipv4Addr, peer: Ipv4Addr) -> io::Result<SyncDevice> {
    DeviceBuilder::new()
        .mtu(9_000)
        .ipv4(address, 30, Some(peer))
        .with(|builder| {
            builder.packet_information(false);
        })
        .build_sync()
}

#[cfg(target_os = "macos")]
fn transport_sample(payload_size: usize, mode: TransportMode) -> io::Result<Duration> {
    let sender_device = build_device(A_LOCAL, A_PEER)?;
    let receiver_device = build_device(B_LOCAL, B_PEER)?;
    sender_device.set_nonblocking(true)?;
    receiver_device.set_nonblocking(true)?;

    let (left_sender, left_receiver) = tokio::sync::mpsc::channel(CHUNK_QUEUE);
    let (right_sender, right_receiver) = tokio::sync::mpsc::channel(CHUNK_QUEUE);
    let (app_ready_sender, app_ready_receiver) = mpsc::sync_channel(1);
    let (app_done_sender, app_done_receiver) = mpsc::sync_channel(1);
    let (gateway_ready_sender, gateway_ready_receiver) = mpsc::sync_channel(1);
    let (middle_ready_sender, middle_ready_receiver) = mpsc::sync_channel(1);
    let (app_start_sender, app_start_receiver) = mpsc::sync_channel(1);
    let (gateway_start_sender, gateway_start_receiver) = mpsc::sync_channel(1);
    let (middle_start_sender, middle_start_receiver) = mpsc::sync_channel(1);

    let middle = thread::spawn(move || {
        let result = match mode {
            TransportMode::Tcp => tcp_middle(
                left_receiver,
                right_sender,
                middle_ready_sender.clone(),
                middle_start_receiver,
            ),
            TransportMode::Quicp => quicp_middle(
                left_receiver,
                right_sender,
                middle_ready_sender.clone(),
                middle_start_receiver,
            ),
        };
        if let Err(error) = &result {
            let _ =
                middle_ready_sender.try_send(Err(io::Error::new(error.kind(), error.to_string())));
        }
        result
    });
    let gateway = thread::spawn(move || {
        let result = gateway_side(
            receiver_device,
            payload_size,
            left_sender,
            right_receiver,
            app_done_receiver,
            gateway_ready_sender.clone(),
            gateway_start_receiver,
        );
        if let Err(error) = &result {
            let _ =
                gateway_ready_sender.try_send(Err(io::Error::new(error.kind(), error.to_string())));
        }
        result
    });
    let app = thread::spawn(move || {
        let result = app_side(
            sender_device,
            payload_size,
            app_done_sender.clone(),
            app_ready_sender.clone(),
            app_start_receiver,
        );
        if let Err(error) = &result {
            let _ = app_ready_sender.try_send(Err(io::Error::new(error.kind(), error.to_string())));
            let _ = app_done_sender.try_send(Err(io::Error::new(error.kind(), error.to_string())));
        }
        result
    });

    app_ready_receiver
        .recv_timeout(DEADLINE)
        .map_err(|_| io::Error::new(ErrorKind::TimedOut, "smoltcp app setup timeout"))??;
    gateway_ready_receiver
        .recv_timeout(DEADLINE)
        .map_err(|_| io::Error::new(ErrorKind::TimedOut, "smoltcp gateway setup timeout"))??;
    middle_ready_receiver
        .recv_timeout(DEADLINE)
        .map_err(|_| io::Error::new(ErrorKind::TimedOut, "transport setup timeout"))??;

    middle_start_sender
        .send(())
        .map_err(|_| io::Error::other("transport exited before start"))?;
    gateway_start_sender
        .send(())
        .map_err(|_| io::Error::other("smoltcp gateway exited before start"))?;
    app_start_sender
        .send(())
        .map_err(|_| io::Error::other("smoltcp app exited before start"))?;

    let elapsed = app
        .join()
        .map_err(|_| io::Error::other("smoltcp app panicked"))??;
    gateway
        .join()
        .map_err(|_| io::Error::other("smoltcp gateway panicked"))??;
    middle
        .join()
        .map_err(|_| io::Error::other("transport panicked"))??;
    Ok(elapsed)
}

#[cfg(target_os = "macos")]
#[allow(clippy::needless_pass_by_value)]
fn app_side(
    device: SyncDevice,
    payload_size: usize,
    done_sender: SyncSender<io::Result<()>>,
    ready_sender: SyncSender<io::Result<()>>,
    start_receiver: Receiver<()>,
) -> io::Result<Duration> {
    let mut device = UtunDevice::new(device);
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0x51_4f_49_43;
    let mut interface = Interface::new(config, &mut device, SmolInstant::now());
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(ip_address(A_PEER), 30))
            .expect("smoltcp app address capacity");
    });
    interface
        .routes_mut()
        .add_default_ipv4_route(A_LOCAL)
        .map_err(|error| io::Error::other(format!("smoltcp app route: {error}")))?;

    let tx = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0_u8; 64 * 1024]),
        tcp::SocketBuffer::new(vec![0_u8; 64 * 1024]),
    );
    let rx = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0_u8; 64 * 1024]),
        tcp::SocketBuffer::new(vec![0_u8; 64 * 1024]),
    );
    let mut sockets = SocketSet::new(vec![]);
    let tx_handle = sockets.add(tx);
    let rx_handle = sockets.add(rx);
    sockets
        .get_mut::<tcp::Socket>(rx_handle)
        .listen(EGRESS_PORT)
        .map_err(|error| io::Error::other(format!("smoltcp app listen: {error}")))?;
    sockets
        .get_mut::<tcp::Socket>(tx_handle)
        .connect(
            interface.context(),
            (ip_address(B_PEER), INGRESS_PORT),
            (ip_address(A_PEER), APP_SOURCE_PORT),
        )
        .map_err(|error| io::Error::other(format!("smoltcp app connect: {error}")))?;

    let deadline = Instant::now() + DEADLINE;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "smoltcp app handshake timeout",
            ));
        }
        interface.poll(SmolInstant::now(), &mut device, &mut sockets);
        if sockets.get::<tcp::Socket>(tx_handle).is_active()
            && sockets.get::<tcp::Socket>(rx_handle).is_active()
        {
            ready_sender
                .send(Ok(()))
                .map_err(|_| io::Error::other("smoltcp app readiness receiver exited"))?;
            break;
        }
        thread::yield_now();
    }
    start_receiver
        .recv()
        .map_err(|_| io::Error::other("smoltcp app start sender exited"))?;

    let payload = vec![0x5a; payload_size];
    let target = payload_size.saturating_mul(ITERATIONS);
    let mut sent = 0;
    let mut received = 0;
    let start = Instant::now();
    while received < target {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                format!("smoltcp app data timeout: sent={sent} received={received}/{target}"),
            ));
        }
        interface.poll(SmolInstant::now(), &mut device, &mut sockets);
        if sent < target {
            let socket = sockets.get_mut::<tcp::Socket>(tx_handle);
            if socket.can_send() {
                let length = socket
                    .send_slice(&payload[..(target - sent).min(payload_size)])
                    .map_err(|error| io::Error::other(format!("smoltcp app send: {error}")))?;
                sent += length;
            }
        }
        let socket = sockets.get_mut::<tcp::Socket>(rx_handle);
        while socket.can_recv() && received < target {
            let length = socket
                .recv(|buffer| {
                    let length = buffer.len().min(target - received);
                    black_box(&buffer[..length]);
                    (length, length)
                })
                .map_err(|error| io::Error::other(format!("smoltcp app receive: {error}")))?;
            received += length;
        }
        thread::yield_now();
    }
    done_sender
        .send(Ok(()))
        .map_err(|_| io::Error::other("smoltcp gateway completion receiver exited"))?;
    Ok(start.elapsed())
}

#[cfg(target_os = "macos")]
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
fn gateway_side(
    device: SyncDevice,
    payload_size: usize,
    left_sender: ChunkSender,
    mut right_receiver: ChunkReceiver,
    done_receiver: Receiver<io::Result<()>>,
    ready_sender: SyncSender<io::Result<()>>,
    start_receiver: Receiver<()>,
) -> io::Result<()> {
    let mut device = UtunDevice::new(device);
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0x51_4f_49_44;
    let mut interface = Interface::new(config, &mut device, SmolInstant::now());
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(ip_address(B_PEER), 30))
            .expect("smoltcp gateway address capacity");
    });
    interface
        .routes_mut()
        .add_default_ipv4_route(B_LOCAL)
        .map_err(|error| io::Error::other(format!("smoltcp gateway route: {error}")))?;

    let ingress = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0_u8; 64 * 1024]),
        tcp::SocketBuffer::new(vec![0_u8; 64 * 1024]),
    );
    let egress = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0_u8; 64 * 1024]),
        tcp::SocketBuffer::new(vec![0_u8; 64 * 1024]),
    );
    let mut sockets = SocketSet::new(vec![]);
    let ingress_handle = sockets.add(ingress);
    let egress_handle = sockets.add(egress);
    sockets
        .get_mut::<tcp::Socket>(ingress_handle)
        .listen(INGRESS_PORT)
        .map_err(|error| io::Error::other(format!("smoltcp gateway listen: {error}")))?;
    sockets
        .get_mut::<tcp::Socket>(egress_handle)
        .connect(
            interface.context(),
            (ip_address(A_PEER), EGRESS_PORT),
            (ip_address(B_PEER), GATEWAY_SOURCE_PORT),
        )
        .map_err(|error| io::Error::other(format!("smoltcp gateway connect: {error}")))?;

    let deadline = Instant::now() + DEADLINE;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "smoltcp gateway handshake timeout",
            ));
        }
        interface.poll(SmolInstant::now(), &mut device, &mut sockets);
        if sockets.get::<tcp::Socket>(ingress_handle).is_active()
            && sockets.get::<tcp::Socket>(egress_handle).is_active()
        {
            ready_sender
                .send(Ok(()))
                .map_err(|_| io::Error::other("smoltcp gateway readiness receiver exited"))?;
            break;
        }
        thread::yield_now();
    }
    start_receiver
        .recv()
        .map_err(|_| io::Error::other("smoltcp gateway start sender exited"))?;

    let target = payload_size.saturating_mul(ITERATIONS);
    let mut received = 0;
    let mut forwarded = 0;
    let mut pending_left = None;
    let mut pending: Option<(Vec<u8>, usize)> = None;
    let mut app_done = None;
    while forwarded < target || app_done.is_none() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                format!(
                    "smoltcp gateway data timeout: received={received}/{target} forwarded={forwarded}/{target}"
                ),
            ));
        }
        interface.poll(SmolInstant::now(), &mut device, &mut sockets);

        if let Some(chunk) = pending_left.take() {
            match left_sender.try_send(chunk) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(chunk)) => {
                    pending_left = Some(chunk);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    return Err(io::Error::other("transport input receiver exited"));
                }
            }
        }
        if forwarded < target
            && pending_left.is_none()
            && sockets.get::<tcp::Socket>(ingress_handle).can_recv()
        {
            let socket = sockets.get_mut::<tcp::Socket>(ingress_handle);
            let chunk = socket
                .recv(|buffer| {
                    let length = buffer.len().min(target - received);
                    (length, buffer[..length].to_vec())
                })
                .map_err(|error| io::Error::other(format!("smoltcp gateway receive: {error}")))?;
            received += chunk.len();
            match left_sender.try_send(chunk) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(chunk)) => {
                    pending_left = Some(chunk);
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    return Err(io::Error::other("transport input receiver exited"));
                }
            }
        }

        if forwarded < target && pending.is_none() {
            match right_receiver.try_recv() {
                Ok(chunk) => pending = Some((chunk, 0)),
                Err(
                    tokio::sync::mpsc::error::TryRecvError::Empty
                    | tokio::sync::mpsc::error::TryRecvError::Disconnected,
                ) => {}
            }
        }
        if let Some((chunk, offset)) = pending.as_mut()
            && forwarded < target
            && sockets.get::<tcp::Socket>(egress_handle).can_send()
        {
            let written = sockets
                .get_mut::<tcp::Socket>(egress_handle)
                .send_slice(&chunk[*offset..])
                .map_err(|error| io::Error::other(format!("smoltcp gateway send: {error}")))?;
            *offset += written;
            forwarded += written;
            if *offset == chunk.len() {
                pending = None;
            }
        }
        if app_done.is_none() {
            match done_receiver.try_recv() {
                Ok(result) => app_done = Some(result),
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err(io::Error::other("smoltcp app completion sender exited"));
                }
            }
        }
        thread::yield_now();
    }
    app_done
        .expect("smoltcp app completion state")
        .map_err(|error| io::Error::new(error.kind(), error.to_string()))?;
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(clippy::needless_pass_by_value)]
fn tcp_middle(
    mut left_receiver: ChunkReceiver,
    right_sender: ChunkSender,
    ready_sender: SyncSender<io::Result<()>>,
    start_receiver: Receiver<()>,
) -> io::Result<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let (accepted_sender, accepted_receiver) = mpsc::sync_channel(1);
    let reader = thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        stream.set_nodelay(true)?;
        accepted_sender
            .send(())
            .map_err(|_| io::Error::other("TCP middle client exited"))?;
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let length = stream.read(&mut buffer)?;
            if length == 0 {
                return Ok(());
            }
            right_sender
                .blocking_send(buffer[..length].to_vec())
                .map_err(|_| io::Error::other("smoltcp gateway exited"))?;
        }
    });
    let mut client = TcpStream::connect(address)?;
    client.set_nodelay(true)?;
    accepted_receiver
        .recv_timeout(DEADLINE)
        .map_err(|_| io::Error::new(ErrorKind::TimedOut, "TCP middle accept timeout"))?;
    ready_sender
        .send(Ok(()))
        .map_err(|_| io::Error::other("transport readiness receiver exited"))?;
    start_receiver
        .recv()
        .map_err(|_| io::Error::other("TCP middle start sender exited"))?;
    while let Some(chunk) = left_receiver.blocking_recv() {
        client.write_all(&chunk)?;
    }
    client.shutdown(std::net::Shutdown::Write)?;
    reader
        .join()
        .map_err(|_| io::Error::other("TCP middle reader panicked"))??;
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
fn quicp_middle(
    mut left_receiver: ChunkReceiver,
    right_sender: ChunkSender,
    ready_sender: SyncSender<io::Result<()>>,
    start_receiver: Receiver<()>,
) -> io::Result<()> {
    let directory = tempfile::tempdir_in(std::env::current_dir()?)?;
    let client_tuple = FourTuple::new(
        SocketAddr::from((C_PEER, APP_SOURCE_PORT)),
        SocketAddr::from((D_PEER, INGRESS_PORT)),
    );
    let server_tuple = client_tuple.reverse();
    let server_addr = server_tuple.source;
    let client = ClientConfig {
        journal_path: directory.path().join("fakeip.journal"),
        fake_ip_pool: "198.18.0.0/15".parse::<Ipv4Pool>().expect("pool"),
        fake_dns_addr: Ipv4Addr::new(198, 18, 0, 1),
        zero_rtt: ZeroRttMode::Off,
        tls: None,
        multipath: Multipath {
            mode: MultipathMode::Off,
            candidates: vec![PathCandidate {
                name: "primary".to_owned(),
                local_ip: IpAddr::V4(C_PEER),
                server_addr,
            }],
        },
        carrier: CarrierConfig::default(),
    };
    let server = ServerConfig {
        listen_addrs: vec![server_addr],
        tls: None,
        carrier: CarrierConfig::default(),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let client_device = build_device(C_LOCAL, C_PEER)?;
        let server_device = build_device(D_LOCAL, D_PEER)?;
        client_device.set_nonblocking(true)?;
        server_device.set_nonblocking(true)?;
        let client_socket = TunCarrierSocket::new(
            client_device,
            client_tuple,
            CarrierDirection::ClientToServer,
        )?;
        let server_socket = TunCarrierSocket::new(
            server_device,
            server_tuple,
            CarrierDirection::ServerToClient,
        )?;
        let server_endpoint = build_server_endpoint_with_socket(
            &server,
            Box::new(server_socket),
            Arc::new(noq::TokioRuntime),
        )
        .map_err(debug_io_error)?;
        let actual_server_addr = server_endpoint.local_addr().map_err(debug_io_error)?;
        let client_endpoint = build_client_endpoint_with_socket(
            &client,
            Box::new(client_socket),
            Arc::new(noq::TokioRuntime),
        )
        .map_err(debug_io_error)?;
        let server_future = async {
            let incoming = server_endpoint
                .accept()
                .await
                .ok_or_else(|| io::Error::other("QUICP server stopped"))?;
            let connection = incoming.await.map_err(debug_io_error)?;
            let pending = accept_flow(&connection).await.map_err(debug_io_error)?;
            pending.accept().await.map_err(debug_io_error)
        };
        let client_future = async {
            let connection = client_endpoint
                .connect(actual_server_addr, "quicp")
                .map_err(debug_io_error)?
                .await
                .map_err(debug_io_error)?;
            let host = CanonicalHost::parse("example.com").map_err(debug_io_error)?;
            let request = OpenRequest::new(host, std::num::NonZeroU16::new(443).expect("port"));
            QuicpFlow::open(&connection, request)
                .await
                .map_err(debug_io_error)
        };
        let (server_flow, client_flow) = tokio::try_join!(server_future, client_future)?;
        ready_sender
            .send(Ok(()))
            .map_err(|_| io::Error::other("transport readiness receiver exited"))?;
        tokio::task::spawn_blocking(move || start_receiver.recv())
            .await
            .map_err(debug_io_error)?
            .map_err(|_| io::Error::other("QUICP middle start sender exited"))?;

        let (server_done_sender, server_done_receiver) =
            tokio::sync::oneshot::channel::<io::Result<()>>();
        let client_task = async move {
            let mut flow = client_flow;
            while let Some(chunk) = left_receiver.recv().await {
                tokio::io::AsyncWriteExt::write_all(&mut flow, &chunk)
                    .await
                    .map_err(debug_io_error)?;
            }
            tokio::io::AsyncWriteExt::shutdown(&mut flow)
                .await
                .map_err(debug_io_error)?;
            server_done_receiver
                .await
                .map_err(debug_io_error)?
                .map_err(|error| io::Error::new(error.kind(), error.to_string()))
        };
        let server_task = async move {
            let mut flow = server_flow;
            let mut buffer = vec![0_u8; 64 * 1024];
            let result = async {
                loop {
                    let length = tokio::io::AsyncReadExt::read(&mut flow, &mut buffer)
                        .await
                        .map_err(debug_io_error)?;
                    if length == 0 {
                        break;
                    }
                    right_sender
                        .send(buffer[..length].to_vec())
                        .await
                        .map_err(|_| io::Error::other("smoltcp gateway exited"))?;
                }
                Ok::<(), io::Error>(())
            }
            .await;
            let notification = match &result {
                Ok(()) => Ok(()),
                Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
            };
            let _ = server_done_sender.send(notification);
            result
        };
        let (client_result, server_result) = tokio::join!(client_task, server_task);
        client_result
            .map_err(|error| io::Error::new(error.kind(), format!("QUICP client: {error}")))?;
        server_result
            .map_err(|error| io::Error::new(error.kind(), format!("QUICP server: {error}")))
    })
}

#[cfg(target_os = "macos")]
fn carrier_error(error: quicp::faketcp::CarrierError) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, error)
}

#[cfg(target_os = "macos")]
fn debug_io_error(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

#[cfg(target_os = "macos")]
fn send_packet(device: &SyncDevice, packet: &[u8]) -> io::Result<()> {
    loop {
        match device.send(packet) {
            Ok(length) if length == packet.len() => return Ok(()),
            Ok(_) => return Err(io::Error::new(ErrorKind::WriteZero, "partial utun write")),
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::yield_now(),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "macos")]
fn ip_address(address: Ipv4Addr) -> IpAddress {
    IpAddress::v4(
        address.octets()[0],
        address.octets()[1],
        address.octets()[2],
        address.octets()[3],
    )
}

#[cfg(target_os = "macos")]
fn nanos_per_payload(elapsed: Duration) -> u128 {
    elapsed.as_nanos() / ITERATIONS as u128
}

#[cfg(target_os = "macos")]
fn gbps(payload_size: usize, elapsed: Duration) -> String {
    let milli_gbps = (payload_size as u128)
        .saturating_mul(ITERATIONS as u128)
        .saturating_mul(8_000)
        .checked_div(elapsed.as_nanos())
        .unwrap_or(0);
    format!("{}.{:03}", milli_gbps / 1_000, milli_gbps % 1_000)
}
