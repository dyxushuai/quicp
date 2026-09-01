//! A deployable SOCKS5 CONNECT proxy carried through native `FakeTCP` QUICP flows.
//!
//! Run this binary as either a `client` or a `server` process. The client accepts local SOCKS5
//! connections and opens one QUICP flow per connection; the server connects each accepted flow
//! to its requested destination. Both sides must use the same owner-only carrier-cookie secret.

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn main() {
    eprintln!(
        "socks5_tunnel requires a native raw FakeTCP carrier; use examples/echo.rs for a portable carrier demo"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    supported::run().await
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod supported {
    use std::env;
    use std::error::Error;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::num::NonZeroU16;
    use std::path::{Path, PathBuf};

    use quicp::{
        CanonicalHost, CarrierConfig, Client, ClientConfig, Connection, FlowError, FourTuple,
        Multipath, OpenRequest, OpenStatus, PathCandidate, PendingFlow, Server, ServerConfig,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const DEFAULT_SOCKS5_LISTEN: SocketAddr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1_080);
    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
    const USAGE: &str = "Usage:\n  socks5_tunnel client --local <client-ip:port> --server <server-ip:port> [--socks5 <listen>] --secret <absolute-file>\n  socks5_tunnel server --listen <server-ip:port> --client <client-ip:port> --secret <absolute-file>\n\nBoth processes require platform-specific raw-packet privileges and tuple-scoped TCP RST suppression.\n";

    pub async fn run() -> Result<(), Box<dyn Error>> {
        let args = parse_args()?;
        match args.role {
            Role::Client => run_client(args).await,
            Role::Server => run_server(args).await,
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Role {
        Client,
        Server,
    }

    #[derive(Debug)]
    struct Args {
        role: Role,
        local: SocketAddr,
        peer: SocketAddr,
        socks5_listen: SocketAddr,
        secret: PathBuf,
    }

    fn parse_args() -> Result<Args, io::Error> {
        let mut arguments = env::args().skip(1);
        let role = match arguments.next().as_deref() {
            Some("client") => Role::Client,
            Some("server") => Role::Server,
            Some("--help" | "-h") => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            _ => return Err(usage_error("a role of `client` or `server` is required")),
        };

        let mut local = None;
        let mut peer = None;
        let mut socks5_listen = DEFAULT_SOCKS5_LISTEN;
        let mut secret = None;
        while let Some(flag) = arguments.next() {
            let value = arguments
                .next()
                .ok_or_else(|| usage_error(format!("missing value for {flag}")))?;
            match flag.as_str() {
                "--local" | "--listen" => local = Some(parse_socket(&value, &flag)?),
                "--server" | "--client" => peer = Some(parse_socket(&value, &flag)?),
                "--socks5" => socks5_listen = parse_socket(&value, &flag)?,
                "--secret" => secret = Some(PathBuf::from(value)),
                _ => return Err(usage_error(format!("unknown option {flag}"))),
            }
        }

        let local = local.ok_or_else(|| usage_error("a local/listen address is required"))?;
        let peer = peer.ok_or_else(|| usage_error("a server/client address is required"))?;
        let secret = secret.ok_or_else(|| usage_error("--secret is required"))?;
        if !local.ip().is_ipv4() || !peer.ip().is_ipv4() {
            return Err(usage_error(
                "the raw FakeTCP example currently requires IPv4 addresses",
            ));
        }
        if local.ip().is_unspecified() || peer.ip().is_unspecified() {
            return Err(usage_error(
                "local/listen and server/client addresses must be concrete IPv4 addresses",
            ));
        }
        if !secret.is_absolute() {
            return Err(usage_error("--secret must be an absolute path"));
        }
        Ok(Args {
            role,
            local,
            peer,
            socks5_listen,
            secret,
        })
    }

    fn parse_socket(value: &str, flag: &str) -> Result<SocketAddr, io::Error> {
        value
            .parse()
            .map_err(|error| usage_error(format!("invalid {flag} address {value}: {error}")))
    }

    fn usage_error(message: impl Into<String>) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{}\n{USAGE}", message.into()),
        )
    }

    fn carrier(secret: &Path) -> Result<CarrierConfig, Box<dyn Error>> {
        Ok(CarrierConfig::new(secret)?)
    }

    async fn run_client(args: Args) -> Result<(), Box<dyn Error>> {
        let tuple = FourTuple::new(args.local, args.peer);
        let path = PathCandidate::new(args.local.ip(), args.peer)?;
        let config = ClientConfig::insecure(Multipath::single(path)?, carrier(&args.secret)?)?;
        let client = Client::bind_fake_tcp(&config, &[tuple])?;
        let connection = client.connect().await?;
        let listener = TcpListener::bind(args.socks5_listen).await?;
        println!(
            "SOCKS5 client listening on {}; QUICP peer is {}",
            args.socks5_listen, args.peer
        );
        loop {
            let (stream, peer) = listener.accept().await?;
            let connection = connection.clone();
            tokio::spawn(async move {
                if let Err(error) = handle_socks5_client(stream, connection).await {
                    eprintln!("SOCKS5 client {peer} closed with error: {error}");
                }
            });
        }
    }

    async fn run_server(args: Args) -> Result<(), Box<dyn Error>> {
        let tuple = FourTuple::new(args.local, args.peer);
        let config = ServerConfig::insecure(vec![args.local], carrier(&args.secret)?)?;
        let server = Server::bind_fake_tcp(&config, &[tuple])?;
        println!(
            "QUICP SOCKS5 gateway listening on {}; expected client tuple is {}",
            args.local, args.peer
        );
        run_gateway(server).await
    }

    async fn run_gateway(server: Server) -> Result<(), Box<dyn Error>> {
        loop {
            let incoming = match server.accept().await {
                Ok(incoming) => incoming,
                Err(error) => {
                    eprintln!("QUICP gateway accept stopped: {error}");
                    return Err(error.into());
                }
            };
            tokio::spawn(async move {
                match incoming.handshake().await {
                    Ok(connection) => serve_connection(connection).await,
                    Err(error) => eprintln!("QUICP gateway handshake failed: {error}"),
                }
            });
        }
    }

    async fn serve_connection(connection: Connection) {
        loop {
            let pending = match connection.accept_flow(true).await {
                Ok(pending) => pending,
                Err(error) => {
                    eprintln!("QUICP gateway flow accept stopped: {error}");
                    return;
                }
            };
            let request = pending.request().clone();
            tokio::spawn(handle_pending_flow(pending, request));
        }
    }

    async fn handle_pending_flow(pending: PendingFlow, request: OpenRequest) {
        let mut upstream = match connect_target(&request).await {
            Ok(upstream) => upstream,
            Err(status) => {
                let _ = pending.reject(status).await;
                return;
            }
        };
        let mut flow = match pending.accept().await {
            Ok(flow) => flow,
            Err(error) => {
                eprintln!("QUICP gateway could not accept flow: {error}");
                return;
            }
        };
        if let Err(error) = quicp::flow::relay_bidirectional(&mut flow, &mut upstream).await {
            eprintln!("QUICP upstream relay stopped: {error}");
        }
    }

    async fn connect_target(request: &OpenRequest) -> Result<TcpStream, OpenStatus> {
        match tokio::time::timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((request.host.as_str(), request.port.get())),
        )
        .await
        {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(error)) => Err(match error.kind() {
                io::ErrorKind::ConnectionRefused => OpenStatus::ConnectionRefused,
                io::ErrorKind::TimedOut => OpenStatus::ConnectionTimeout,
                io::ErrorKind::NotFound => OpenStatus::ResolutionFailure,
                _ => OpenStatus::GeneralFailure,
            }),
            Err(_) => Err(OpenStatus::ConnectionTimeout),
        }
    }

    async fn handle_socks5_client(
        mut stream: TcpStream,
        connection: Connection,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let Some(request) = read_socks5_connect(&mut stream).await? else {
            return Ok(());
        };
        let mut flow = match tokio::time::timeout(
            CONNECT_TIMEOUT,
            connection.open_flow(request, true),
        )
        .await
        {
            Ok(Ok(flow)) => flow,
            Ok(Err(error)) => {
                send_socks5_reply(&mut stream, flow_error_reply(&error)).await?;
                return Ok(());
            }
            Err(_) => {
                send_socks5_reply(&mut stream, 0x06).await?;
                return Ok(());
            }
        };
        send_socks5_reply(&mut stream, 0x00).await?;
        quicp::flow::relay_bidirectional(&mut stream, &mut flow).await?;
        Ok(())
    }

    async fn read_socks5_connect(
        stream: &mut TcpStream,
    ) -> Result<Option<OpenRequest>, Box<dyn Error + Send + Sync>> {
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await?;
        if greeting[0] != 0x05 {
            send_socks5_reply(stream, 0x01).await?;
            return Ok(None);
        }
        let method_count = usize::from(greeting[1]);
        let mut methods = [0u8; 255];
        stream.read_exact(&mut methods[..method_count]).await?;
        if !methods[..method_count].contains(&0x00) {
            stream.write_all(&[0x05, 0xff]).await?;
            return Ok(None);
        }
        stream.write_all(&[0x05, 0x00]).await?;

        let mut request_header = [0u8; 4];
        stream.read_exact(&mut request_header).await?;
        if request_header[0] != 0x05 {
            send_socks5_reply(stream, 0x01).await?;
            return Ok(None);
        }
        if request_header[1] != 0x01 {
            send_socks5_reply(stream, 0x07).await?;
            return Ok(None);
        }

        let host = match request_header[3] {
            0x03 => {
                let mut length = [0u8; 1];
                stream.read_exact(&mut length).await?;
                let mut bytes = [0u8; 255];
                stream
                    .read_exact(&mut bytes[..usize::from(length[0])])
                    .await?;
                Some(std::str::from_utf8(&bytes[..usize::from(length[0])])?.to_ascii_lowercase())
            }
            0x01 => {
                let mut address = [0u8; 4];
                stream.read_exact(&mut address).await?;
                None
            }
            0x04 => {
                let mut address = [0u8; 16];
                stream.read_exact(&mut address).await?;
                None
            }
            _ => {
                send_socks5_reply(stream, 0x08).await?;
                return Ok(None);
            }
        };
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;
        let Some(host) = host else {
            send_socks5_reply(stream, 0x08).await?;
            return Ok(None);
        };
        let Ok(host) = CanonicalHost::parse(&host) else {
            send_socks5_reply(stream, 0x08).await?;
            return Ok(None);
        };
        let port = u16::from_be_bytes(port);
        let Some(port) = NonZeroU16::new(port) else {
            send_socks5_reply(stream, 0x01).await?;
            return Ok(None);
        };
        Ok(Some(OpenRequest::new(host, port)))
    }

    async fn send_socks5_reply(stream: &mut TcpStream, status: u8) -> io::Result<()> {
        stream
            .write_all(&[0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
    }

    fn flow_error_reply(error: &FlowError) -> u8 {
        match error {
            FlowError::Rejected(OpenStatus::ConnectionRefused) => 0x05,
            FlowError::Rejected(OpenStatus::ConnectionTimeout) => 0x06,
            FlowError::Rejected(OpenStatus::ResolutionFailure) => 0x04,
            FlowError::Rejected(_)
            | FlowError::Open(_)
            | FlowError::Accept(_)
            | FlowError::Read(_)
            | FlowError::Write(_)
            | FlowError::Reset(_)
            | FlowError::Session(_)
            | FlowError::Replay(_)
            | FlowError::InvalidRejectStatus => 0x01,
        }
    }
}
