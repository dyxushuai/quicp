use std::num::NonZeroUsize;
use std::task::{Context, Poll, Waker};

use quicp::platform::{PlatformPacketBridge, PlatformPacketConfig};
use quicp::smolstack::{
    SmoltcpConfig, TcpFlowBuffers, poll_bounded, poll_tcp_read, poll_tcp_write,
};
use smoltcp::iface::{Config as InterfaceConfig, Interface, PollResult, SocketSet};
use smoltcp::time::Instant;
use smoltcp::wire::HardwareAddress;

#[test]
fn tcp_buffers_are_preallocated_and_zero_is_rejected() {
    assert!(TcpFlowBuffers::default().into_socket().is_ok());
    for buffers in [
        TcpFlowBuffers {
            receive_bytes: 0,
            send_bytes: 32,
        },
        TcpFlowBuffers {
            receive_bytes: 32,
            send_bytes: 0,
        },
    ] {
        assert!(buffers.into_socket().is_err());
    }
}

#[test]
fn smoltcp_mtu_boundaries_are_explicit() {
    for mtu in [576, 9000] {
        assert!(
            SmoltcpConfig {
                mtu,
                ..SmoltcpConfig::default()
            }
            .validate()
            .is_ok()
        );
    }
    for mtu in [575, 9001] {
        assert!(
            SmoltcpConfig {
                mtu,
                ..SmoltcpConfig::default()
            }
            .validate()
            .is_err()
        );
    }
}

#[test]
fn bounded_smoltcp_poll_drains_tier1_ingress() {
    let bridge = PlatformPacketBridge::new(PlatformPacketConfig::default()).unwrap();
    bridge.ingress_ip_borrowed(&[0x45; 64]).unwrap();
    let mut device = bridge
        .smoltcp_device(SmoltcpConfig::default())
        .expect("device");
    let mut interface = Interface::new(
        InterfaceConfig::new(HardwareAddress::Ip),
        &mut device,
        Instant::ZERO,
    );
    let mut sockets = SocketSet::new(Vec::new());

    let result = poll_bounded(
        &mut interface,
        &mut device,
        &mut sockets,
        Instant::ZERO,
        NonZeroUsize::MIN,
    );

    assert!(matches!(
        result,
        PollResult::None | PollResult::SocketStateChanged
    ));
    assert_eq!(bridge.ingress_len(), 0);
}

#[test]
fn tcp_poll_helpers_do_not_hold_the_socket_borrow() {
    let mut socket = TcpFlowBuffers::default().into_socket().unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let mut output = [0u8; 1];

    assert!(matches!(
        poll_tcp_read(&mut socket, &mut cx, &mut output),
        Poll::Ready(Ok(0))
    ));
    assert!(matches!(
        poll_tcp_write(&mut socket, &mut cx, b"x"),
        Poll::Ready(Err(error)) if error.kind() == std::io::ErrorKind::BrokenPipe
    ));
}
