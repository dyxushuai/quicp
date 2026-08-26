#![cfg(all(windows, feature = "runtime-tokio", feature = "internal-bench"))]

use std::net::{Ipv4Addr, SocketAddr};

use noq::AsyncUdpSocket;
use quicp::faketcp::{CarrierDirection, FakeTcpSocket, FourTuple, SynDataMode};

#[test]
#[ignore = "requires the signed WinDivert driver and Administrator privileges"]
fn windivert_carrier_binds_a_filtered_tuple() {
    let tuple = FourTuple::new(
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 40_000)),
        SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 44_443)),
    );
    let socket = FakeTcpSocket::bind(
        tuple,
        CarrierDirection::ClientToServer,
        SynDataMode::Disabled,
        1460,
        1500,
        false,
    )
    .expect("WinDivert should open the filtered tuple");
    assert_eq!(socket.local_addr().expect("local address"), tuple.source);
}
