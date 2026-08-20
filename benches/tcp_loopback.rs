use std::hint::black_box;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

const ITERATIONS: usize = if cfg!(debug_assertions) { 500 } else { 20_000 };

fn main() -> io::Result<()> {
    println!("payload_bytes,roundtrip_ns,tcp_payload_gbps");
    for payload_size in [64, 1_200, 4_096] {
        let elapsed = sample(payload_size)?;
        let roundtrip_ns = elapsed / u128::try_from(ITERATIONS).expect("count");
        println!(
            "{payload_size},{roundtrip_ns},{}",
            gbps(payload_size, roundtrip_ns)
        );
    }
    Ok(())
}

fn sample(payload_size: usize) -> io::Result<u128> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    let (done_sender, done_receiver) = mpsc::sync_channel(0);
    let server = thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        stream.set_nodelay(true)?;
        let mut received = vec![0; payload_size];
        for _ in 0..ITERATIONS {
            stream.read_exact(&mut received)?;
            black_box(&received);
        }
        done_sender
            .send(())
            .map_err(|_| io::Error::other("TCP client exited"))
    });

    let mut client = TcpStream::connect(address)?;
    client.set_nodelay(true)?;
    let payload = vec![0x5a; payload_size];
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        client.write_all(&payload)?;
    }
    done_receiver
        .recv()
        .map_err(|_| io::Error::other("TCP server exited"))?;
    let elapsed = start.elapsed().as_nanos();
    client.shutdown(std::net::Shutdown::Write)?;
    server
        .join()
        .map_err(|_| io::Error::other("TCP server panicked"))??;
    Ok(elapsed)
}

fn gbps(payload_size: usize, elapsed_nanos_per_packet: u128) -> String {
    let milli_gbps = u128::try_from(payload_size)
        .expect("payload size fits u128")
        .saturating_mul(8_000)
        .checked_div(elapsed_nanos_per_packet)
        .unwrap_or(0);
    format!("{}.{:03}", milli_gbps / 1_000, milli_gbps % 1_000)
}
