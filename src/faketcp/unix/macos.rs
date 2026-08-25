//! macOS Tier 0 raw-carrier backend.
//!
//! This backend uses privileged IPv4 IP raw sockets. It deliberately does not emulate Linux
//! `AF_PACKET` or packet-ring APIs; tuple and checksum validation stays in the shared decoder.

use super::super::{Arc, FourTuple};
use super::{IPV4_HEADER_BYTES, RAW_PACKET_BUFFER_BYTES, RawSendMode, receive_one_raw_packet};
use noq::udp::RecvMeta;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::IoSliceMut;
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;

pub(super) const SEND_BATCH_SIZE: usize = 1;
pub(super) const RECV_BATCH_SIZE: usize = 1;
pub(super) const GRO_SEGMENTS: usize = 1;

#[derive(Debug)]
pub(super) struct RawPlatform {
    io: Arc<AsyncFd<Socket>>,
    send_io: Arc<AsyncFd<Socket>>,
    send_mode: RawSendMode,
}

impl RawPlatform {
    pub(super) const SEND_BATCH_SIZE: usize = SEND_BATCH_SIZE;
    pub(super) const RECV_BATCH_SIZE: usize = RECV_BATCH_SIZE;
    pub(super) const GRO_SEGMENTS: usize = GRO_SEGMENTS;

    pub(super) fn bind(tuple: FourTuple, packet_socket: bool) -> std::io::Result<Self> {
        if packet_socket {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "AF_PACKET FakeTCP is only available on Linux",
            ));
        }
        let socket = Socket::new_raw(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
        socket.set_header_included_v4(true)?;
        socket.bind(&SockAddr::from(tuple.source))?;
        socket.set_nonblocking(true)?;
        let io = Arc::new(AsyncFd::new(socket)?);
        let send_socket = Socket::new_raw(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
        send_socket.set_header_included_v4(false)?;
        send_socket.bind(&SockAddr::from(tuple.source))?;
        send_socket.set_nonblocking(true)?;
        let send_io = Arc::new(AsyncFd::new(send_socket)?);
        Ok(Self {
            io,
            send_io,
            send_mode: RawSendMode::Ip,
        })
    }

    pub(super) fn recv_io(&self) -> &AsyncFd<Socket> {
        &self.io
    }

    pub(super) fn send_io(&self) -> &Arc<AsyncFd<Socket>> {
        &self.send_io
    }

    pub(super) const fn send_mode(&self) -> RawSendMode {
        self.send_mode
    }

    #[allow(clippy::too_many_arguments, clippy::unused_self)]
    pub(super) fn poll_recv_ring(
        &mut self,
        _cx: &mut Context<'_>,
        _bufs: &mut [IoSliceMut<'_>],
        _meta: &mut [RecvMeta],
        _tuple: FourTuple,
        _inbound: &mut super::super::FakeTcpCarrier,
        _receive_buffer: &mut [u8],
        _decode_rejects: &mut u64,
    ) -> Option<Poll<std::io::Result<usize>>> {
        None
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn send_batch(
    socket: &Socket,
    destination: &SockAddr,
    mode: RawSendMode,
    storage: &[u8],
    packet_capacity: usize,
    lengths: &[usize],
    first: usize,
) -> std::io::Result<usize> {
    let Some(&length) = lengths.get(first) else {
        return Ok(0);
    };
    let offset = first.checked_mul(packet_capacity).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "header offset overflow")
    })?;
    let packet = storage
        .get(
            offset..offset.checked_add(length).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "header length overflow")
            })?,
        )
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "packet header exceeds send storage",
            )
        })?;
    let packet = match mode {
        RawSendMode::Ip => packet.get(IPV4_HEADER_BYTES..).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "raw packet is missing an IPv4 header",
            )
        })?,
        RawSendMode::Packet => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "AF_PACKET FakeTCP is only available on Linux",
            ));
        }
    };
    let sent = socket.send_to(packet, destination)?;
    if sent != packet.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "raw FakeTCP packet was only partially sent",
        ));
    }
    Ok(1)
}

pub(super) fn receive_batch(
    socket: &Socket,
    storage: &mut [u8],
    lengths: &mut [usize; RECV_BATCH_SIZE],
) -> std::io::Result<usize> {
    let received = receive_one_raw_packet(socket, &mut storage[..RAW_PACKET_BUFFER_BYTES])?;
    lengths[0] = received;
    Ok(usize::from(received != 0))
}
