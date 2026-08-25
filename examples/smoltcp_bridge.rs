//! Exercise the bounded smoltcp/TUN packet seam without opening an operating-system TUN device.
//!
//! A TUN, Network Extension, or `VpnService` adapter supplies complete IP packets through
//! `ingress_ip_borrowed` and drains packets with `poll_egress_ip_into`; smoltcp remains single-owner.

#![cfg(feature = "platform-smoltcp")]

use quicp::platform::{PlatformPacketBridge, PlatformPacketConfig};
use quicp::smolstack::SmoltcpConfig;
use smoltcp::phy::{Device, TxToken};
use smoltcp::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = PlatformPacketConfig::default();
    let bridge = PlatformPacketBridge::new(config)?;
    bridge.ingress_ip_borrowed(&[0x45; 64])?;
    let mut device = bridge.smoltcp_device(SmoltcpConfig::default())?;
    let tx = device
        .transmit(Instant::ZERO)
        .ok_or("smoltcp egress queue is full")?;
    tx.consume(4, |packet| packet.copy_from_slice(&[0x45, 0, 0, 4]));
    let mut output = [0; 1500];
    let length = bridge
        .poll_egress_ip_into(&mut output)?
        .ok_or("smoltcp produced no packet")?;
    println!("smoltcp bridge moved {length} bytes through caller-owned storage");
    Ok(())
}
