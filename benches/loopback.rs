#![allow(unsafe_code)]

#[cfg(target_os = "linux")]
mod linux {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::fs;
    use std::hint::black_box;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use quicp::{
        CanonicalHost, CarrierConfig, Client, ClientConfig, FourTuple, Multipath, OpenRequest,
        PathCandidate, QuicpTransportConfig, RecoveryConfig, RecoveryMode, RecoverySnapshot,
        Server, ServerConfig, TransportError, TransportOptions,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    struct CountingAllocator;

    static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);
    static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);
    static PEAK_LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

    #[global_allocator]
    static GLOBAL: CountingAllocator = CountingAllocator;

    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let pointer = unsafe { System.alloc(layout) };
            if !pointer.is_null() {
                ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
                record_live_growth(layout.size());
            }
            pointer
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
            unsafe { System.dealloc(pointer, layout) }
        }

        unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            let replacement = unsafe { System.realloc(pointer, layout, size) };
            if !replacement.is_null() {
                ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
                if size >= layout.size() {
                    record_live_growth(size - layout.size());
                } else {
                    LIVE_BYTES.fetch_sub(layout.size() - size, Ordering::Relaxed);
                }
            }
            replacement
        }
    }

    fn record_live_growth(bytes: usize) {
        let live = LIVE_BYTES.fetch_add(bytes, Ordering::Relaxed) + bytes;
        PEAK_LIVE_BYTES.fetch_max(live, Ordering::Relaxed);
    }

    fn begin_peak_live_heap_sample() {
        let live = LIVE_BYTES.load(Ordering::Relaxed);
        PEAK_LIVE_BYTES.store(live, Ordering::Relaxed);
    }

    #[cfg(debug_assertions)]
    const TOTAL_BYTES: usize = 512 * 1024;
    #[cfg(not(debug_assertions))]
    const TOTAL_BYTES: usize = 32 * 1024 * 1024;
    const PAYLOADS: &[usize] = &[64, 1200, 4096];
    const SAMPLES: usize = 6;
    const DELIVERY_SAMPLES: usize = 256;
    const DELIVERY_COMPLETE: u64 = 1 << 63;
    const DEADLINE: Duration = Duration::from_secs(30);
    pub(super) fn run() -> io::Result<()> {
        assert_eq!(quantile(&[5, 1, 3, 2, 4], 50), 3);
        assert_eq!(median(&[1, 2, 4, 5]), 3);
        assert!(clean_path_within_five_percent(95, 100));
        assert!(!clean_path_within_five_percent(94, 100));
        let nodelay = match std::env::var("QUICP_NODELAY").as_deref() {
            Ok("1" | "true") | Err(std::env::VarError::NotPresent) => true,
            Ok("0" | "false") => false,
            Ok(_) | Err(std::env::VarError::NotUnicode(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUICP_NODELAY must be true, false, 1, or 0",
                ));
            }
        };
        let enforce_clean_path = std::env::var_os("QUICP_ENFORCE_CLEAN_PATH").is_some();
        let parse_usize = |name| match std::env::var(name) {
            Ok(value) => value.parse::<usize>().map(Some).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{name} must be an unsigned integer"),
                )
            }),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name} must be valid UTF-8"),
            )),
        };
        let total_bytes = parse_usize("QUICP_TOTAL_BYTES")?.unwrap_or(TOTAL_BYTES);
        if total_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUICP_TOTAL_BYTES must be greater than zero",
            ));
        }
        let payloads = parse_usize("QUICP_PAYLOAD_SIZE")?
            .map_or_else(|| PAYLOADS.to_vec(), |payload| vec![payload]);
        if payloads.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUICP_PAYLOAD_SIZE must be greater than zero",
            ));
        }
        if enforce_clean_path
            && (std::env::var_os("QUICP_PAYLOAD_SIZE").is_some() || total_bytes < TOTAL_BYTES)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "clean-path gate requires the default payload set and at least 32 MiB per sample",
            ));
        }
        println!("# matched_nodelay={nodelay}");
        println!(
            "payload_bytes,adaptive_p50_delivery_ns,adaptive_p95_delivery_ns,adaptive_p99_delivery_ns,adaptive_median_gbps,adaptive_median_cpu_pct,adaptive_median_allocations_per_run,adaptive_median_absolute_peak_live_rust_heap_bytes,adaptive_delivery_samples,reliable_p50_delivery_ns,reliable_p95_delivery_ns,reliable_p99_delivery_ns,reliable_median_gbps,reliable_median_cpu_pct,reliable_median_allocations_per_run,reliable_median_absolute_peak_live_rust_heap_bytes,reliable_delivery_samples,tcp_p50_delivery_ns,tcp_p95_delivery_ns,tcp_p99_delivery_ns,tcp_median_gbps,tcp_median_cpu_pct,tcp_median_allocations_per_run,tcp_median_absolute_peak_live_rust_heap_bytes,tcp_delivery_samples,adaptive_source_sent_total,adaptive_source_received_total,adaptive_repair_sent_total,adaptive_repair_symbols_per_million_source,adaptive_recovered_total,adaptive_replayed_total,adaptive_fallback_total,adaptive_dropped_total,reliable_source_sent_total,reliable_source_received_total,reliable_repair_sent_total,reliable_repair_symbols_per_million_source,reliable_recovered_total,reliable_replayed_total,reliable_fallback_total,reliable_dropped_total"
        );
        for (payload_index, payload_size) in payloads.into_iter().enumerate() {
            let iterations = total_bytes.div_ceil(payload_size);
            let tuple_base = payload_index * SAMPLES * 2;
            // Keep result-storage allocations outside every measured sample so the alternating QUICP
            // modes begin with the same harness-owned live-heap baseline.
            let mut adaptive = Samples::preallocated();
            let mut reliable = Samples::preallocated();
            let mut tcp = Samples::preallocated();
            for sample in 0..SAMPLES {
                let run = |mode, tuple| {
                    quicp_sample(payload_size, iterations, tuple, nodelay, mode).map_err(|error| {
                        if error.kind() == io::ErrorKind::PermissionDenied {
                            io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                "raw QUICP bench requires CAP_NET_RAW",
                            )
                        } else {
                            error
                        }
                    })
                };
                if sample % 2 == 0 {
                    adaptive.push(run(RecoveryMode::Adaptive, tuple_base + sample * 2)?);
                    reliable.push(run(
                        RecoveryMode::ReliableOnly,
                        tuple_base + sample * 2 + 1,
                    )?);
                } else {
                    reliable.push(run(RecoveryMode::ReliableOnly, tuple_base + sample * 2)?);
                    adaptive.push(run(RecoveryMode::Adaptive, tuple_base + sample * 2 + 1)?);
                }
            }
            if std::env::var_os("QUICP_ONLY").is_none() {
                for _ in 0..SAMPLES {
                    tcp.push(tcp_sample(payload_size, iterations, nodelay)?);
                }
            }
            let adaptive_median_goodput = adaptive.median_goodput();
            let reliable_median_goodput = reliable.median_goodput();
            let adaptive_recovery = adaptive.total_snapshot();
            let reliable_recovery = reliable.total_snapshot();
            let mut row = vec![payload_size.to_string()];
            row.extend(sample_columns(&adaptive));
            row.extend(sample_columns(&reliable));
            row.extend(sample_columns(&tcp));
            row.extend(recovery_columns(adaptive_recovery));
            row.extend(recovery_columns(reliable_recovery));
            println!("{}", row.join(","));
            if enforce_clean_path && matches!(payload_size, 1200 | 4096) {
                let repair_sent = adaptive_recovery.repair_sent;
                if repair_sent != 0 {
                    return Err(io::Error::other(format!(
                        "clean adaptive path emitted {repair_sent} repair symbols for {payload_size}-byte writes"
                    )));
                }
                if reliable_median_goodput == 0
                    || !clean_path_within_five_percent(
                        adaptive_median_goodput,
                        reliable_median_goodput,
                    )
                {
                    return Err(io::Error::other(format!(
                        "adaptive median {} Gbps fell below the 5% clean-path limit against reliable-only {} Gbps for {payload_size}-byte writes",
                        format_milli(adaptive_median_goodput),
                        format_milli(reliable_median_goodput),
                    )));
                }
            }
        }
        println!(
            "# process_lifetime_peak_rss_kib={}",
            process_usage()?.peak_rss_kib
        );
        Ok(())
    }

    struct Samples {
        goodput_milli_gbps: Vec<u128>,
        delivery_latency_nanos: Vec<u128>,
        cpu_percent_milli: Vec<u128>,
        allocations: Vec<u128>,
        absolute_peak_live_rust_heap_bytes: Vec<u128>,
        recovery: Vec<RecoverySnapshot>,
    }

    impl Samples {
        fn preallocated() -> Self {
            Self {
                goodput_milli_gbps: Vec::with_capacity(SAMPLES),
                delivery_latency_nanos: Vec::with_capacity(SAMPLES * DELIVERY_SAMPLES),
                cpu_percent_milli: Vec::with_capacity(SAMPLES),
                allocations: Vec::with_capacity(SAMPLES),
                absolute_peak_live_rust_heap_bytes: Vec::with_capacity(SAMPLES),
                recovery: Vec::with_capacity(SAMPLES),
            }
        }

        fn push(&mut self, sample: Sample) {
            self.goodput_milli_gbps.push(
                u128::try_from(sample.useful_bytes)
                    .expect("useful byte count fits u128")
                    .saturating_mul(8_000)
                    .checked_div(sample.elapsed_nanos)
                    .unwrap_or(0),
            );
            self.delivery_latency_nanos
                .extend(sample.delivery_latency_nanos);
            self.cpu_percent_milli.push(
                sample
                    .cpu_nanos
                    .saturating_mul(100_000)
                    .checked_div(sample.elapsed_nanos)
                    .unwrap_or(0),
            );
            self.allocations.push(sample.allocations as u128);
            self.absolute_peak_live_rust_heap_bytes
                .push(sample.absolute_peak_live_rust_heap_bytes as u128);
            self.recovery.push(sample.recovery);
        }

        fn latency_quantile(&self, percentile: usize) -> u128 {
            quantile(&self.delivery_latency_nanos, percentile)
        }

        fn median_goodput(&self) -> u128 {
            median(&self.goodput_milli_gbps)
        }

        fn is_empty(&self) -> bool {
            self.goodput_milli_gbps.is_empty()
        }

        fn cpu_percent(&self) -> String {
            let milli = median(&self.cpu_percent_milli);
            format!("{}.{:03}", milli / 1_000, milli % 1_000)
        }

        fn median_allocations(&self) -> u128 {
            median(&self.allocations)
        }

        fn median_absolute_peak_live_rust_heap_bytes(&self) -> u128 {
            median(&self.absolute_peak_live_rust_heap_bytes)
        }

        fn total_snapshot(&self) -> RecoverySnapshot {
            let total = |value: fn(&RecoverySnapshot) -> u64| {
                self.recovery
                    .iter()
                    .map(value)
                    .fold(0u64, u64::saturating_add)
            };
            let maximum = |value: fn(&RecoverySnapshot) -> u64| {
                self.recovery.iter().map(value).max().unwrap_or(0)
            };
            RecoverySnapshot {
                source_sent: total(|value| value.source_sent),
                source_received: total(|value| value.source_received),
                repair_sent: total(|value| value.repair_sent),
                recovered: total(|value| value.recovered),
                replayed: total(|value| value.replayed),
                fallback: total(|value| value.fallback),
                dropped: total(|value| value.dropped),
                early_accepted: total(|value| value.early_accepted),
                early_rejected: total(|value| value.early_rejected),
                path_lost_packets: total(|value| value.path_lost_packets),
                max_path_rtt_micros: maximum(|value| value.max_path_rtt_micros),
                queued_datagrams: maximum(|value| value.queued_datagrams),
                retained_source_bytes: maximum(|value| value.retained_source_bytes),
            }
        }
    }

    fn sample_columns(samples: &Samples) -> [String; 8] {
        if samples.is_empty() {
            return std::array::from_fn(|_| "NA".to_owned());
        }
        [
            samples.latency_quantile(50).to_string(),
            samples.latency_quantile(95).to_string(),
            samples.latency_quantile(99).to_string(),
            format_milli(samples.median_goodput()),
            samples.cpu_percent(),
            samples.median_allocations().to_string(),
            samples
                .median_absolute_peak_live_rust_heap_bytes()
                .to_string(),
            samples.delivery_latency_nanos.len().to_string(),
        ]
    }

    fn recovery_columns(snapshot: RecoverySnapshot) -> [String; 8] {
        let repair_parts_per_million = match (snapshot.repair_sent, snapshot.source_sent) {
            (0, _) => "0".to_owned(),
            (_, 0) => "NA".to_owned(),
            (repair, source) => u128::from(repair)
                .saturating_mul(1_000_000)
                .div_ceil(u128::from(source))
                .to_string(),
        };
        [
            snapshot.source_sent.to_string(),
            snapshot.source_received.to_string(),
            snapshot.repair_sent.to_string(),
            repair_parts_per_million,
            snapshot.recovered.to_string(),
            snapshot.replayed.to_string(),
            snapshot.fallback.to_string(),
            snapshot.dropped.to_string(),
        ]
    }

    struct Sample {
        elapsed_nanos: u128,
        cpu_nanos: u128,
        allocations: usize,
        useful_bytes: usize,
        delivery_latency_nanos: Vec<u128>,
        absolute_peak_live_rust_heap_bytes: usize,
        recovery: RecoverySnapshot,
    }

    #[derive(Clone, Copy)]
    struct ProcessUsage {
        cpu_nanos: u128,
        peak_rss_kib: i64,
    }

    fn process_usage() -> io::Result<ProcessUsage> {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        // SAFETY: getrusage initializes the provided rusage object for RUSAGE_SELF.
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: getrusage succeeded and initialized the object.
        let usage = unsafe { usage.assume_init() };
        let nanos = |time: libc::timeval| {
            u128::try_from(time.tv_sec)
                .unwrap_or(0)
                .saturating_mul(1_000_000_000)
                .saturating_add(
                    u128::try_from(time.tv_usec)
                        .unwrap_or(0)
                        .saturating_mul(1_000),
                )
        };
        Ok(ProcessUsage {
            cpu_nanos: nanos(usage.ru_utime).saturating_add(nanos(usage.ru_stime)),
            peak_rss_kib: usage.ru_maxrss,
        })
    }

    fn quantile(samples: &[u128], percentile: usize) -> u128 {
        assert_ne!(samples.len(), 0);
        assert!(percentile > 0 && percentile <= 100);
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let rank = (sorted.len() * percentile).div_ceil(100).saturating_sub(1);
        sorted[rank]
    }

    fn median(samples: &[u128]) -> u128 {
        assert_ne!(samples.len(), 0);
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        let middle = sorted.len() / 2;
        if sorted.len().is_multiple_of(2) {
            sorted[middle - 1].saturating_add(sorted[middle]) / 2
        } else {
            sorted[middle]
        }
    }

    const fn clean_path_within_five_percent(adaptive_gbps: u128, reliable_gbps: u128) -> bool {
        adaptive_gbps.saturating_mul(100) >= reliable_gbps.saturating_mul(95)
    }

    fn delivery_marks(iterations: usize) -> (usize, Vec<AtomicU64>) {
        let stride = iterations.div_ceil(DELIVERY_SAMPLES).max(1);
        let count = iterations.div_ceil(stride);
        (stride, (0..count).map(|_| AtomicU64::new(0)).collect())
    }

    fn mark_delivery_sent(marks: &[AtomicU64], stride: usize, iteration: usize, start: Instant) {
        if iteration.is_multiple_of(stride) {
            let elapsed = u64::try_from(start.elapsed().as_nanos())
                .unwrap_or(DELIVERY_COMPLETE - 2)
                .min(DELIVERY_COMPLETE - 2);
            marks[iteration / stride].store(elapsed + 1, Ordering::Relaxed);
        }
    }

    fn mark_delivery_received(
        marks: &[AtomicU64],
        stride: usize,
        iteration: usize,
        start: Instant,
    ) -> io::Result<()> {
        if !iteration.is_multiple_of(stride) {
            return Ok(());
        }
        let slot = &marks[iteration / stride];
        let sent = slot.load(Ordering::Relaxed);
        if sent == 0 || sent & DELIVERY_COMPLETE != 0 {
            return Err(io::Error::other("delivery sample was not armed"));
        }
        let now = u64::try_from(start.elapsed().as_nanos()).unwrap_or(DELIVERY_COMPLETE - 1);
        let latency = now.saturating_sub(sent - 1).min(DELIVERY_COMPLETE - 1);
        slot.store(DELIVERY_COMPLETE | latency, Ordering::Relaxed);
        Ok(())
    }

    fn collect_delivery_marks(marks: &[AtomicU64]) -> io::Result<Vec<u128>> {
        marks
            .iter()
            .map(|mark| {
                let value = mark.load(Ordering::Relaxed);
                (value & DELIVERY_COMPLETE != 0)
                    .then_some(u128::from(value & !DELIVERY_COMPLETE))
                    .ok_or_else(|| io::Error::other("delivery sample did not complete"))
            })
            .collect()
    }

    fn quicp_sample(
        payload_size: usize,
        iterations: usize,
        sample: usize,
        nodelay: bool,
        mode: RecoveryMode,
    ) -> io::Result<Sample> {
        begin_peak_live_heap_sample();
        let tuple = bench_tuple(sample);
        let (_secret_directory, carrier) = benchmark_carrier()?;
        let recovery = RecoveryConfig {
            mode,
            ..RecoveryConfig::default()
        };
        let transport = QuicpTransportConfig::default().with_recovery(recovery);
        let client = client_config(tuple, carrier.clone())
            .with_transport(transport.clone())
            .map_err(debug_io_error)?;
        let server = ServerConfig::insecure(
            vec![tuple.destination],
            carrier.with_packet_socket(packet_socket_enabled()),
        )
        .and_then(|config| config.with_transport(transport))
        .map_err(debug_io_error)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let options = TransportOptions::default();
        let mut result = runtime.block_on(async move {
            tokio::time::timeout(
                DEADLINE,
                run_quicp(
                    payload_size,
                    iterations,
                    tuple,
                    client,
                    server,
                    nodelay,
                    options,
                ),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "raw QUICP bench timed out"))?
        })?;
        result.absolute_peak_live_rust_heap_bytes = PEAK_LIVE_BYTES.load(Ordering::Relaxed);
        Ok(result)
    }

    fn bench_tuple(sample: usize) -> FourTuple {
        let process_offset = u16::try_from(std::process::id() % 1000).expect("process offset");
        let sample_offset = u16::try_from(sample).expect("sample offset");
        let offset = (process_offset + sample_offset) % 1000;
        FourTuple::new(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 40_000_u16 + offset)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 44_000_u16 + offset)),
        )
    }

    async fn run_quicp(
        payload_size: usize,
        iterations: usize,
        tuple: FourTuple,
        client: ClientConfig,
        server: ServerConfig,
        nodelay: bool,
        options: TransportOptions,
    ) -> io::Result<Sample> {
        let server = Server::bind_fake_tcp_with_options(&server, &[tuple.reverse()], &options)
            .map_err(transport_error)?;
        let client = Client::bind_fake_tcp_with_options(&client, &[tuple], &options)
            .map_err(transport_error)?;

        let server_connection = async {
            server
                .accept()
                .await
                .map_err(debug_io_error)?
                .handshake()
                .await
                .map_err(debug_io_error)
        };
        let client_connection = async { client.connect().await.map_err(debug_io_error) };
        let (server_connection, client_connection) =
            tokio::try_join!(server_connection, client_connection)?;

        let server_flow = async {
            let pending = server_connection
                .accept_flow(true)
                .await
                .map_err(debug_io_error)?;
            pending.accept().await.map_err(debug_io_error)
        };
        let client_flow = async {
            let host = CanonicalHost::parse("example.com").map_err(debug_io_error)?;
            client_connection
                .open_flow(
                    OpenRequest::new(host, std::num::NonZeroU16::new(443).expect("port")),
                    true,
                )
                .await
                .map_err(debug_io_error)
        };
        let (mut server_flow, mut client_flow) = tokio::try_join!(server_flow, client_flow)?;
        client_flow.set_nodelay(nodelay);

        let payload = vec![0x5a; payload_size];
        let mut received = vec![0; payload_size];
        let (delivery_stride, delivery_marks) = delivery_marks(iterations);
        let useful_bytes = payload_size
            .checked_mul(iterations)
            .ok_or_else(|| io::Error::other("benchmark byte count overflow"))?;
        let before = process_usage()?;
        ALLOCATIONS.store(0, Ordering::Relaxed);
        let start = Instant::now();
        let sender = async {
            for iteration in 0..iterations {
                mark_delivery_sent(&delivery_marks, delivery_stride, iteration, start);
                client_flow
                    .write_all(&payload)
                    .await
                    .map_err(debug_io_error)?;
            }
            client_flow.shutdown().await.map_err(debug_io_error)
        };
        let read_task = async {
            for iteration in 0..iterations {
                server_flow
                    .read_exact(&mut received)
                    .await
                    .map_err(debug_io_error)?;
                mark_delivery_received(&delivery_marks, delivery_stride, iteration, start)?;
                black_box(&received);
            }
            Ok::<(), io::Error>(())
        };
        tokio::try_join!(sender, read_task)?;
        let elapsed_nanos = start.elapsed().as_nanos();
        let allocations = ALLOCATIONS.load(Ordering::Relaxed);
        let after = process_usage()?;
        let mut recovery = client_connection.recovery_snapshot();
        let server_recovery = server_connection.recovery_snapshot();
        recovery.source_received = server_recovery.source_received;
        recovery.recovered = server_recovery.recovered;
        recovery.dropped = server_recovery.dropped;
        Ok(Sample {
            elapsed_nanos,
            cpu_nanos: after.cpu_nanos.saturating_sub(before.cpu_nanos),
            allocations,
            useful_bytes,
            delivery_latency_nanos: collect_delivery_marks(&delivery_marks)?,
            absolute_peak_live_rust_heap_bytes: 0,
            recovery,
        })
    }

    fn client_config(tuple: FourTuple, carrier: CarrierConfig) -> ClientConfig {
        ClientConfig::insecure(
            Multipath::single(PathCandidate::new(tuple.source.ip(), tuple.destination).unwrap())
                .unwrap(),
            carrier.with_packet_socket(packet_socket_enabled()),
        )
        .unwrap()
    }

    fn benchmark_carrier() -> io::Result<(tempfile::TempDir, CarrierConfig)> {
        let home = std::env::var_os("HOME").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "HOME is required for the bench")
        })?;
        let directory = tempfile::tempdir_in(home)?;
        let secret_path = directory.path().join("carrier-cookie.secret");
        fs::write(&secret_path, b"quicp benchmark cookie secret")?;
        fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))?;
        let carrier = CarrierConfig::new(secret_path)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        Ok((directory, carrier))
    }

    fn packet_socket_enabled() -> bool {
        std::env::var_os("QUICP_IP_RAW").is_none()
    }

    fn tcp_sample(payload_size: usize, iterations: usize, nodelay: bool) -> io::Result<Sample> {
        begin_peak_live_heap_sample();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let mut result = runtime.block_on(async {
            tokio::time::timeout(DEADLINE, run_tcp(payload_size, iterations, nodelay))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP bench timed out"))?
        })?;
        result.absolute_peak_live_rust_heap_bytes = PEAK_LIVE_BYTES.load(Ordering::Relaxed);
        Ok(result)
    }

    async fn run_tcp(payload_size: usize, iterations: usize, nodelay: bool) -> io::Result<Sample> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (mut client, (mut server, _)) =
            tokio::try_join!(TcpStream::connect(address), listener.accept())?;
        client.set_nodelay(nodelay)?;
        server.set_nodelay(nodelay)?;
        let payload = vec![0x5a; payload_size];
        let mut received = vec![0; payload_size];
        let (delivery_stride, delivery_marks) = delivery_marks(iterations);
        let useful_bytes = payload_size
            .checked_mul(iterations)
            .ok_or_else(|| io::Error::other("benchmark byte count overflow"))?;
        let before = process_usage()?;
        ALLOCATIONS.store(0, Ordering::Relaxed);
        let start = Instant::now();
        let sender = async {
            for iteration in 0..iterations {
                mark_delivery_sent(&delivery_marks, delivery_stride, iteration, start);
                client.write_all(&payload).await?;
            }
            client.shutdown().await
        };
        let receive_task = async {
            for iteration in 0..iterations {
                server.read_exact(&mut received).await?;
                mark_delivery_received(&delivery_marks, delivery_stride, iteration, start)?;
                black_box(&received);
            }
            Ok::<(), io::Error>(())
        };
        tokio::try_join!(sender, receive_task)?;
        let elapsed_nanos = start.elapsed().as_nanos();
        let allocations = ALLOCATIONS.load(Ordering::Relaxed);
        let after = process_usage()?;
        Ok(Sample {
            elapsed_nanos,
            cpu_nanos: after.cpu_nanos.saturating_sub(before.cpu_nanos),
            allocations,
            useful_bytes,
            delivery_latency_nanos: collect_delivery_marks(&delivery_marks)?,
            absolute_peak_live_rust_heap_bytes: 0,
            recovery: RecoverySnapshot::default(),
        })
    }

    fn transport_error(error: TransportError) -> io::Error {
        match error {
            TransportError::Io(error) => error,
            error => io::Error::other(error),
        }
    }

    fn debug_io_error(error: impl std::fmt::Debug) -> io::Error {
        io::Error::other(format!("{error:?}"))
    }

    fn format_milli(milli_gbps: u128) -> String {
        format!("{}.{:03}", milli_gbps / 1_000, milli_gbps % 1_000)
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("raw QUICP/TCP bench skipped: Linux raw sockets are required");
}
