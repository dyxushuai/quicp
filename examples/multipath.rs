//! Configure a bounded primary/backup QUICP connection.
//!
//! The portable `HostDatagramSocket` facade is intentionally single-path. This example shows the
//! validated multipath policy that a Unix raw-carrier adapter or a platform adapter must bind to
//! two independently routed sockets.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use quicp::{CarrierConfig, ClientConfig, Multipath, PathCandidate, ServerConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let primary = PathCandidate::new(
        "primary",
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        SocketAddr::from((Ipv4Addr::new(198, 51, 100, 10), 44_443)),
    )?;
    let backup = PathCandidate::new(
        "backup",
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
        SocketAddr::from((Ipv4Addr::new(198, 51, 100, 20), 44_443)),
    )?;
    let paths = Multipath::failover(primary, backup)?;
    let client = ClientConfig::insecure(paths.clone(), CarrierConfig::default())?;
    let server = ServerConfig::insecure(
        paths
            .candidates()
            .iter()
            .map(PathCandidate::server_addr)
            .collect(),
        CarrierConfig::default(),
    )?;

    println!(
        "validated {:?} multipath policy with {} paths",
        client.multipath().mode(),
        client.multipath().candidates().len()
    );
    println!(
        "server listens on {} configured addresses",
        server.listen_addrs().len()
    );
    println!("bind one carrier socket per candidate; never merge the two FakeTCP sequence spaces");
    Ok(())
}
