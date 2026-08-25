//! Opt-in no-TLS QUICP packet-header protection.
//!
//! The example deliberately uses a reversible mask only to demonstrate the callback contract.
//! It is not authentication or payload encryption; use the TLS profile for that boundary.

use std::sync::Arc;

use quicp::{
    HeaderProtectionFactory, HeaderProtectionKeys, HeaderProtectionSide, QuicpHeaderProtector,
    TransportOptions,
};

#[derive(Debug)]
struct Mask(u8);

impl QuicpHeaderProtector for Mask {
    fn decrypt(&self, packet_number_offset: usize, packet: &mut [u8]) {
        if let Some(byte) = packet.get_mut(packet_number_offset) {
            *byte ^= self.0;
        }
    }

    fn encrypt(&self, packet_number_offset: usize, packet: &mut [u8]) {
        self.decrypt(packet_number_offset, packet);
    }

    fn sample_size(&self) -> usize {
        1
    }
}

#[derive(Debug)]
struct MaskFactory(u8);

impl HeaderProtectionFactory for MaskFactory {
    fn build(&self, _side: HeaderProtectionSide) -> HeaderProtectionKeys {
        HeaderProtectionKeys::new(Arc::new(Mask(self.0)), Arc::new(Mask(self.0)))
    }
}

fn main() {
    let options =
        TransportOptions::new().with_header_protection_factory(Arc::new(MaskFactory(0x5a)));
    let protector = Mask(0x5a);
    let mut packet = [0u8; 8];
    protector.encrypt(0, &mut packet);
    assert_eq!(packet[0], 0x5a);
    protector.decrypt(0, &mut packet);
    assert_eq!(packet[0], 0);
    println!("configured no-TLS QUICP header protection: {options:?}");
}
