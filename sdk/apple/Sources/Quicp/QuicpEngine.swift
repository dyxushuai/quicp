import CQuicp
import Darwin

public enum QuicpStatus: UInt32, Error, Sendable {
  case ok = 0
  case wouldBlock = 1
  case bufferTooSmall = 2
  case invalidArgument = 3
  case notReady = 4
  case closed = 5
  case panic = 6
  case failed = 7

  fileprivate static func fromNative(_ value: UInt32) -> Self {
    Self(rawValue: value) ?? .panic
  }
}

public struct QuicpSocketAddress: Sendable {
  public let address: String
  public let port: UInt16

  public init(_ address: String, port: UInt16) {
    self.address = address
    self.port = port
  }

  fileprivate func native() throws -> quicp_socket_address_t {
    var result = quicp_socket_address_t()
    result.port = port
    if let ipv4 = IPv4Address(address) {
      result.family = 4
      withUnsafeMutableBytes(of: &result.address) { $0.copyBytes(from: ipv4.bytes) }
    } else if let ipv6 = IPv6Address(address) {
      result.family = 6
      withUnsafeMutableBytes(of: &result.address) { $0.copyBytes(from: ipv6.bytes) }
    } else {
      throw QuicpStatus.invalidArgument
    }
    return result
  }
}

private struct IPv4Address {
  let bytes: [UInt8]
  init?(_ value: String) {
    let octets = value.split(separator: ".", omittingEmptySubsequences: false)
    guard octets.count == 4 else { return nil }
    var bytes = [UInt8]()
    bytes.reserveCapacity(4)
    for octet in octets {
      guard !octet.isEmpty,
            octet == "0" || octet.first != "0",
            octet.allSatisfy({ $0.isASCII && $0.isNumber }),
            let byte = UInt8(octet)
      else { return nil }
      bytes.append(byte)
    }
    self.bytes = bytes
  }
}

private struct IPv6Address {
  let bytes: [UInt8]
  init?(_ value: String) {
    var storage = in6_addr()
    guard value.withCString({ inet_pton(AF_INET6, $0, &storage) }) == 1 else { return nil }
    self.bytes = withUnsafeBytes(of: storage) { Array($0) }
  }
}

public struct QuicpPath: Sendable {
  public let local: QuicpSocketAddress
  public let peer: QuicpSocketAddress

  public init(local: QuicpSocketAddress, peer: QuicpSocketAddress) {
    self.local = local
    self.peer = peer
  }
}

public struct QuicpRecoverySnapshot: Sendable, Equatable {
  public let sourceSent: UInt64
  public let sourceReceived: UInt64
  public let repairSent: UInt64
  public let recovered: UInt64
  public let replayed: UInt64
  public let fallback: UInt64
  public let dropped: UInt64
  public let earlyAccepted: UInt64
  public let earlyRejected: UInt64
  public let pathLostPackets: UInt64
  public let maxPathRttMicros: UInt64
  public let queuedDatagrams: UInt64
  public let retainedSourceBytes: UInt64

  fileprivate init(_ value: quicp_recovery_snapshot_t) {
    sourceSent = value.source_sent
    sourceReceived = value.source_received
    repairSent = value.repair_sent
    recovered = value.recovered
    replayed = value.replayed
    fallback = value.fallback
    dropped = value.dropped
    earlyAccepted = value.early_accepted
    earlyRejected = value.early_rejected
    pathLostPackets = value.path_lost_packets
    maxPathRttMicros = value.max_path_rtt_micros
    queuedDatagrams = value.queued_datagrams
    retainedSourceBytes = value.retained_source_bytes
  }
}

public final class QuicpEngine {
  public enum Role: UInt32, Sendable { case client = 1, server = 2 }
  public enum RecoveryMode: UInt32, Sendable { case adaptive = 1, reliableOnly = 2 }
  public enum Security: Sendable {
    case insecure
    case mutualTLS(
      serverName: String,
      caCertificate: String,
      certificate: String,
      privateKey: String
    )
  }

  private var raw: OpaquePointer?

  public init(
    role: Role,
    paths: [QuicpPath],
    packetCapacity: UInt32 = 256,
    mtu: UInt32 = 1500,
    recoveryMode: RecoveryMode = .adaptive,
    security: Security = .insecure
  ) throws {
    guard quicp_abi_version() == QUICP_ABI_VERSION, (1...2).contains(paths.count) else {
      throw QuicpStatus.invalidArgument
    }
    let first = quicp_path_config_t(
      local: try paths[0].local.native(),
      peer: try paths[0].peer.native()
    )
    let second = paths.count == 2
      ? quicp_path_config_t(local: try paths[1].local.native(), peer: try paths[1].peer.native())
      : quicp_path_config_t()
    var config = quicp_engine_config_t(
      abi_version: QUICP_ABI_VERSION,
      role: role.rawValue,
      path_count: UInt32(paths.count),
      paths: (first, second),
      packet_capacity: packetCapacity,
      mtu: mtu,
      recovery_mode: recoveryMode.rawValue
    )
    let nativeStatus: UInt32
    switch security {
    case .insecure:
      nativeStatus = quicp_engine_create(&config, &raw)
    case let .mutualTLS(serverName, caCertificate, certificate, privateKey):
      let values = [serverName, caCertificate, certificate, privateKey].map { Array($0.utf8) }
      nativeStatus = values[0].withUnsafeBufferPointer { serverName in
        values[1].withUnsafeBufferPointer { caCertificate in
          values[2].withUnsafeBufferPointer { certificate in
            values[3].withUnsafeBufferPointer { privateKey in
              var tls = quicp_tls_config_t(
                server_name: quicp_bytes_t(
                  data: serverName.baseAddress, length: UInt32(serverName.count)
                ),
                ca_certificate: quicp_bytes_t(
                  data: caCertificate.baseAddress, length: UInt32(caCertificate.count)
                ),
                certificate: quicp_bytes_t(
                  data: certificate.baseAddress, length: UInt32(certificate.count)
                ),
                private_key: quicp_bytes_t(
                  data: privateKey.baseAddress, length: UInt32(privateKey.count)
                )
              )
              return quicp_engine_create_tls(&config, &tls, &raw)
            }
          }
        }
      }
    }
    let status = QuicpStatus.fromNative(nativeStatus)
    guard status == .ok else { throw status }
  }

  deinit { _ = close() }

  public var connectionStatus: QuicpStatus {
    guard let raw else { return .closed }
    return QuicpStatus.fromNative(quicp_engine_connection_state(raw))
  }

  @discardableResult
  public func drive(elapsedNanoseconds: UInt64, maxTasks: UInt32 = 256) -> (QuicpStatus, UInt32) {
    guard let raw else { return (.closed, 0) }
    var processed: UInt32 = 0
    let status = quicp_engine_drive(raw, elapsedNanoseconds, maxTasks, &processed)
    return (QuicpStatus.fromNative(status), processed)
  }

  public var nextTimerNanoseconds: UInt64? {
    guard let raw else { return nil }
    var present: UInt32 = 0
    var deadline: UInt64 = 0
    guard quicp_engine_next_timer(raw, &present, &deadline) == QUICP_STATUS_OK else { return nil }
    return present == 0 ? nil : deadline
  }

  public var recoverySnapshot: Result<QuicpRecoverySnapshot, QuicpStatus> {
    guard let raw else { return .failure(.closed) }
    var snapshot = quicp_recovery_snapshot_t()
    let status = QuicpStatus.fromNative(quicp_engine_recovery_snapshot(raw, &snapshot))
    return status == .ok ? .success(QuicpRecoverySnapshot(snapshot)) : .failure(status)
  }

  public func ingress(path: UInt32, datagram: UnsafeRawBufferPointer) -> QuicpStatus {
    guard let raw, let base = datagram.baseAddress else { return .invalidArgument }
    return QuicpStatus.fromNative(quicp_engine_ingress(
      raw, path, base.assumingMemoryBound(to: UInt8.self), UInt32(datagram.count)
    ))
  }

  public func egress(path: UInt32, into output: UnsafeMutableRawBufferPointer) -> (QuicpStatus, Int) {
    guard let raw, let base = output.baseAddress else { return (.invalidArgument, 0) }
    var length: UInt32 = 0
    let status = quicp_engine_egress(
      raw, path, base.assumingMemoryBound(to: UInt8.self), UInt32(output.count), &length
    )
    return (QuicpStatus.fromNative(status), Int(length))
  }

  public func markPathUnavailable(_ path: UInt32) -> QuicpStatus {
    guard let raw else { return .closed }
    return QuicpStatus.fromNative(quicp_engine_path_unavailable(raw, path))
  }

  public func openFlow(host: String, port: UInt16) -> Result<QuicpFlow, QuicpStatus> {
    guard let raw else { return .failure(.closed) }
    var handle: UInt64 = 0
    let status = host.utf8CString.withUnsafeBufferPointer { bytes in
      quicp_engine_open_flow(raw, bytes.baseAddress, UInt32(bytes.count - 1), port, &handle)
    }
    let value = QuicpStatus.fromNative(status)
    return value == .ok ? .success(QuicpFlow(engine: self, handle: handle)) : .failure(value)
  }

  public func openReplaySafeFlow(
    token: UnsafeRawBufferPointer,
    nonce: UInt64,
    host: String,
    port: UInt16,
    initial: UnsafeRawBufferPointer
  ) -> Result<QuicpFlow, QuicpStatus> {
    guard let raw,
          let tokenBase = token.baseAddress,
          let initialBase = initial.baseAddress
    else { return .failure(.invalidArgument) }
    var handle: UInt64 = 0
    let status = host.utf8CString.withUnsafeBufferPointer { bytes in
      quicp_engine_open_replay_safe_flow(
        raw,
        tokenBase.assumingMemoryBound(to: UInt8.self), UInt32(token.count), nonce,
        bytes.baseAddress, UInt32(bytes.count - 1), port,
        initialBase.assumingMemoryBound(to: UInt8.self), UInt32(initial.count),
        &handle
      )
    }
    let value = QuicpStatus.fromNative(status)
    return value == .ok ? .success(QuicpFlow(engine: self, handle: handle)) : .failure(value)
  }

  public func pollFlowRequest(replaySafe: Bool = false) -> Result<QuicpPendingFlow, QuicpStatus> {
    guard let raw else { return .failure(.closed) }
    var request: UInt64 = 0
    var host = [UInt8](repeating: 0, count: Int(QUICP_MAX_HOST_BYTES))
    var hostLength: UInt32 = 0
    var port: UInt16 = 0
    var initial = [UInt8](repeating: 0, count: Int(QUICP_MAX_EARLY_INITIAL_BYTES))
    var initialLength: UInt32 = 0
    let rawStatus = host.withUnsafeMutableBufferPointer { host in
      initial.withUnsafeMutableBufferPointer { initial in
        if replaySafe {
          return quicp_engine_poll_replay_safe_flow_request(
            raw, &request,
            host.baseAddress, UInt32(host.count), &hostLength, &port,
            initial.baseAddress, UInt32(initial.count), &initialLength
          )
        }
        return quicp_engine_poll_flow_request(
          raw, &request,
          host.baseAddress, UInt32(host.count), &hostLength, &port,
          initial.baseAddress, UInt32(initial.count), &initialLength
        )
      }
    }
    let status = QuicpStatus.fromNative(rawStatus)
    guard status == .ok else { return .failure(status) }
    let name = String(decoding: host.prefix(Int(hostLength)), as: UTF8.self)
    return .success(QuicpPendingFlow(
      engine: self,
      request: request,
      host: name,
      port: port,
      initialData: Array(initial.prefix(Int(initialLength)))
    ))
  }

  public func configureReplayAdmission(
    secret: UnsafeRawBufferPointer,
    epoch: UInt64,
    maxAttempts: UInt32
  ) -> QuicpStatus {
    guard let raw, let base = secret.baseAddress else { return .invalidArgument }
    return QuicpStatus.fromNative(quicp_engine_configure_replay_admission(
      raw, base.assumingMemoryBound(to: UInt8.self), UInt32(secret.count), epoch, maxAttempts
    ))
  }

  public func issueReplayToken(
    nowSeconds: UInt64,
    ttlSeconds: UInt64,
    into output: UnsafeMutableRawBufferPointer
  ) -> (QuicpStatus, Int) {
    guard let raw else { return (.closed, 0) }
    var length: UInt32 = 0
    let status = quicp_engine_issue_replay_token(
      raw, nowSeconds, ttlSeconds,
      output.baseAddress?.assumingMemoryBound(to: UInt8.self),
      UInt32(output.count), &length
    )
    return (QuicpStatus.fromNative(status), Int(length))
  }

  @discardableResult
  public func close() -> QuicpStatus {
    guard raw != nil else { return .closed }
    return QuicpStatus.fromNative(quicp_engine_close(&raw))
  }

  fileprivate func read(_ handle: UInt64, into output: UnsafeMutableRawBufferPointer) -> (QuicpStatus, Int) {
    guard let raw, let base = output.baseAddress else { return (.invalidArgument, 0) }
    var count: UInt32 = 0
    let status = quicp_flow_read(
      raw, handle, base.assumingMemoryBound(to: UInt8.self), UInt32(output.count), &count
    )
    return (QuicpStatus.fromNative(status), Int(count))
  }

  fileprivate func write(_ handle: UInt64, from input: UnsafeRawBufferPointer) -> (QuicpStatus, Int) {
    guard let raw, let base = input.baseAddress else { return (.invalidArgument, 0) }
    var count: UInt32 = 0
    let status = quicp_flow_write(
      raw, handle, base.assumingMemoryBound(to: UInt8.self), UInt32(input.count), &count
    )
    return (QuicpStatus.fromNative(status), Int(count))
  }

  fileprivate func flush(_ handle: UInt64) -> QuicpStatus {
    guard let raw else { return .closed }
    return QuicpStatus.fromNative(quicp_flow_flush(raw, handle))
  }

  fileprivate func shutdown(_ handle: UInt64) -> QuicpStatus {
    guard let raw else { return .closed }
    return QuicpStatus.fromNative(quicp_flow_shutdown(raw, handle))
  }

  fileprivate func closeFlow(_ handle: UInt64) -> QuicpStatus {
    guard let raw else { return .closed }
    return QuicpStatus.fromNative(quicp_flow_close(raw, handle))
  }

  fileprivate func accept(_ request: UInt64) -> Result<QuicpFlow, QuicpStatus> {
    guard let raw else { return .failure(.closed) }
    var handle: UInt64 = 0
    let status = QuicpStatus.fromNative(
      quicp_engine_accept_pending_flow(raw, request, &handle)
    )
    return status == .ok ? .success(QuicpFlow(engine: self, handle: handle)) : .failure(status)
  }

  fileprivate func reject(_ request: UInt64) -> QuicpStatus {
    guard let raw else { return .closed }
    return QuicpStatus.fromNative(quicp_engine_reject_pending_flow(raw, request))
  }
}

public final class QuicpPendingFlow {
  private let engine: QuicpEngine
  private var request: UInt64
  public let host: String
  public let port: UInt16
  public let initialData: [UInt8]

  fileprivate init(
    engine: QuicpEngine,
    request: UInt64,
    host: String,
    port: UInt16,
    initialData: [UInt8]
  ) {
    self.engine = engine
    self.request = request
    self.host = host
    self.port = port
    self.initialData = initialData
  }

  public func accept() -> Result<QuicpFlow, QuicpStatus> {
    guard request != 0 else { return .failure(.closed) }
    let result = engine.accept(request)
    if case .success = result { request = 0 }
    return result
  }

  public func reject() -> QuicpStatus {
    guard request != 0 else { return .closed }
    let status = engine.reject(request)
    if status == .ok { request = 0 }
    return status
  }
}

public final class QuicpFlow {
  private let engine: QuicpEngine
  private var handle: UInt64

  fileprivate init(engine: QuicpEngine, handle: UInt64) {
    self.engine = engine
    self.handle = handle
  }

  deinit { _ = close() }

  public func read(into output: UnsafeMutableRawBufferPointer) -> (QuicpStatus, Int) {
    handle == 0 ? (.closed, 0) : engine.read(handle, into: output)
  }

  public func write(from input: UnsafeRawBufferPointer) -> (QuicpStatus, Int) {
    handle == 0 ? (.closed, 0) : engine.write(handle, from: input)
  }

  public func flush() -> QuicpStatus {
    handle == 0 ? .closed : engine.flush(handle)
  }

  public func shutdown() -> QuicpStatus {
    handle == 0 ? .closed : engine.shutdown(handle)
  }

  @discardableResult
  public func close() -> QuicpStatus {
    guard handle != 0 else { return .closed }
    let current = handle
    handle = 0
    return engine.closeFlow(current)
  }
}
