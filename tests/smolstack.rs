use std::task::{Context, Poll, Waker};

use quicp::smolstack::{SmoltcpConfig, TcpFlowBuffers, poll_tcp_read, poll_tcp_write};

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
