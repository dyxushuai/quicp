//! Show the QUICP first-packet boundary without pretending to support application 0-RTT.
//!
//! This example encodes a cookie-protected `FakeTCP` SYN carrying only the backend handshake
//! datagram. OPEN and application bytes remain blocked until ordinary admission.

use std::net::{Ipv4Addr, SocketAddr};

use quicp::{CarrierDirection, FakeTcpCarrier, FourTuple, SynDataMode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tuple = FourTuple::new(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 19_000)),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 19_001)),
    );
    let cookie = SynDataMode::Cookie([0x42; 16]);
    let mut client = FakeTcpCarrier::new(tuple, CarrierDirection::ClientToServer, cookie)?;
    let mut server =
        FakeTcpCarrier::new(tuple.reverse(), CarrierDirection::ServerToClient, cookie)?;

    let handshake = b"QPCS backend handshake";
    let syn = client.encode_syn(handshake)?;
    let decoded = server.decode_datagram_borrowed(&syn)?;
    assert_eq!(decoded.payload(), handshake);
    println!(
        "cookie SYN carried {} handshake bytes; application 0-RTT remains disabled",
        decoded.payload().len()
    );
    Ok(())
}
