import XCTest

@testable import Quicp

final class QuicpTests: XCTestCase {
  private func pump(_ source: QuicpEngine, _ destination: QuicpEngine, path: UInt32) throws {
    while true {
      var packet = [UInt8](repeating: 0, count: 2_048)
      let (status, count) = packet.withUnsafeMutableBytes { source.egress(path: path, into: $0) }
      if status == .wouldBlock { return }
      guard status == .ok else { throw status }
      let ingress = packet.withUnsafeBytes {
        destination.ingress(path: path, datagram: UnsafeRawBufferPointer(rebasing: $0[..<count]))
      }
      guard ingress == .ok else { throw ingress }
    }
  }

  private func progress(
    _ client: QuicpEngine,
    _ server: QuicpEngine,
    _ elapsed: UInt64,
    paths: [UInt32]
  ) throws {
    XCTAssertEqual(client.drive(elapsedNanoseconds: elapsed).0, .ok)
    XCTAssertEqual(server.drive(elapsedNanoseconds: elapsed).0, .ok)
    for path in paths {
      try pump(client, server, path: path)
      try pump(server, client, path: path)
    }
  }

  func testEngineValidatesPathsAndLifecycle() throws {
    XCTAssertThrowsError(try QuicpEngine(role: .client, paths: []))
    for malformed in [".1.2.3.4", "1..2.3", "1.2.3.4.", "01.2.3.4"] {
      XCTAssertThrowsError(try QuicpEngine(
        role: .client,
        paths: [QuicpPath(
          local: QuicpSocketAddress(malformed, port: 40_000),
          peer: QuicpSocketAddress("127.0.0.1", port: 40_001)
        )]
      ))
    }
    XCTAssertThrowsError(try QuicpEngine(
      role: .client,
      paths: [QuicpPath(
        local: QuicpSocketAddress("127.0.0.1", port: 40_000),
        peer: QuicpSocketAddress("127.0.0.1", port: 40_001)
      )],
      security: .mutualTLS(
        serverName: "server.example",
        caCertificate: "relative-ca.pem",
        certificate: "relative-cert.pem",
        privateKey: "relative-key.pem"
      )
    ))
    let engine = try QuicpEngine(
      role: .client,
      paths: [
        QuicpPath(
          local: QuicpSocketAddress("127.0.0.1", port: 40_000),
          peer: QuicpSocketAddress("127.0.0.1", port: 40_001)
        )
      ]
    )
    XCTAssertEqual(engine.connectionStatus, .wouldBlock)
    if case .failure(let status) = engine.recoverySnapshot {
      XCTAssertEqual(status, .notReady)
    } else {
      XCTFail("connecting engines must not expose recovery counters")
    }
    XCTAssertEqual(engine.markPathUnavailable(0), .ok)
    XCTAssertEqual(engine.close(), .ok)
    XCTAssertEqual(engine.close(), .closed)
  }

  func testReliableOnlyEngineKeepsFlowAliveAfterPrimaryPathLoss() throws {
    let clientPaths = [
      QuicpPath(
        local: QuicpSocketAddress("127.0.0.1", port: 41_000),
        peer: QuicpSocketAddress("127.0.0.2", port: 41_001)
      ),
      QuicpPath(
        local: QuicpSocketAddress("127.0.0.3", port: 41_002),
        peer: QuicpSocketAddress("127.0.0.4", port: 41_003)
      ),
    ]
    let client = try QuicpEngine(
      role: .client,
      paths: clientPaths,
      recoveryMode: .reliableOnly
    )
    let server = try QuicpEngine(
      role: .server,
      paths: clientPaths.map { QuicpPath(local: $0.peer, peer: $0.local) },
      recoveryMode: .reliableOnly
    )
    var elapsed: UInt64 = 0
    var activePaths: [UInt32] = [0, 1]
    for _ in 0..<6_000 where client.connectionStatus != .ok || server.connectionStatus != .ok {
      try progress(client, server, elapsed, paths: activePaths)
      elapsed += 1_000_000
    }
    XCTAssertEqual(client.connectionStatus, .ok)
    XCTAssertEqual(server.connectionStatus, .ok)

    var primeClient: QuicpFlow?
    var primePending: QuicpPendingFlow?
    var primeServer: QuicpFlow?
    for _ in 0..<1_000 where primeClient == nil || primeServer == nil {
      if primeClient == nil,
         case .success(let flow) = client.openFlow(host: "prime.example", port: 443) {
        primeClient = flow
      }
      if primePending == nil,
         case .success(let pending) = server.pollFlowRequest() {
        XCTAssertEqual(pending.host, "prime.example")
        primePending = pending
      }
      if primeServer == nil, let pending = primePending,
         case .success(let flow) = pending.accept() {
        primeServer = flow
      }
      try progress(client, server, elapsed, paths: activePaths)
      elapsed += 1_000_000
    }
    let closedClient = try XCTUnwrap(primeClient)
    let closedServer = try XCTUnwrap(primeServer)
    XCTAssertEqual(closedClient.close(), .ok)
    XCTAssertEqual(closedServer.close(), .ok)

    let secret = [UInt8](repeating: 0x5A, count: 32)
    XCTAssertEqual(secret.withUnsafeBytes {
      server.configureReplayAdmission(secret: $0, epoch: 7, maxAttempts: 16)
    }, .ok)
    let nowSeconds = UInt64(Date().timeIntervalSince1970)
    var token = [UInt8]()
    let required = token.withUnsafeMutableBytes {
      server.issueReplayToken(nowSeconds: nowSeconds, ttlSeconds: 60, into: $0)
    }
    XCTAssertEqual(required.0, .bufferTooSmall)
    XCTAssertGreaterThan(required.1, 0)
    token = [UInt8](repeating: 0, count: required.1)
    let issued = token.withUnsafeMutableBytes {
      server.issueReplayToken(nowSeconds: nowSeconds, ttlSeconds: 60, into: $0)
    }
    XCTAssertEqual(issued.0, .ok)
    XCTAssertEqual(issued.1, token.count)
    let initial = Array("Swift replay-safe initial bytes".utf8)
    var clientFlow: QuicpFlow?
    var pendingFlow: QuicpPendingFlow?
    var serverFlow: QuicpFlow?
    for _ in 0..<1_000 where clientFlow == nil || serverFlow == nil {
      if clientFlow == nil {
        let opened = token.withUnsafeBytes { token in
          initial.withUnsafeBytes { initial in
            client.openReplaySafeFlow(
              token: token, nonce: 42, host: "swift.example", port: 443, initial: initial
            )
          }
        }
        if case .success(let flow) = opened { clientFlow = flow }
      }
      if pendingFlow == nil,
         case .success(let pending) = server.pollFlowRequest(replaySafe: true) {
        XCTAssertEqual(pending.host, "swift.example")
        XCTAssertEqual(pending.initialData, initial)
        pendingFlow = pending
      }
      if serverFlow == nil, let pending = pendingFlow,
         case .success(let flow) = pending.accept() {
        serverFlow = flow
      }
      try progress(client, server, elapsed, paths: activePaths)
      elapsed += 1_000_000
    }
    let sender = try XCTUnwrap(clientFlow)
    let receiver = try XCTUnwrap(serverFlow)
    XCTAssertEqual(closedClient.flush(), .closed)
    XCTAssertEqual(closedServer.flush(), .closed)
    var output = [UInt8](repeating: 0, count: 64)
    var received = 0
    for _ in 0..<1_000 where received == 0 {
      try progress(client, server, elapsed, paths: activePaths)
      elapsed += 1_000_000
      let read = output.withUnsafeMutableBytes { receiver.read(into: $0) }
      if read.0 == .ok { received = read.1 }
    }
    XCTAssertEqual(Array(output[..<received]), initial)

    for _ in 0..<1_000 {
      try progress(client, server, elapsed, paths: activePaths)
      elapsed += 1_000_000
    }
    XCTAssertEqual(client.markPathUnavailable(0), .ok)
    XCTAssertEqual(server.markPathUnavailable(0), .ok)
    activePaths = [1]

    let payload = Array("QUICP/2 through Swift".utf8)
    let write = payload.withUnsafeBytes { sender.write(from: $0) }
    XCTAssertEqual(write.0, .ok)
    XCTAssertEqual(write.1, payload.count)

    received = 0
    for _ in 0..<1_000 where received == 0 {
      XCTAssertTrue([.ok, .wouldBlock].contains(sender.flush()))
      try progress(client, server, elapsed, paths: activePaths)
      elapsed += 1_000_000
      let read = output.withUnsafeMutableBytes { receiver.read(into: $0) }
      if read.0 == .ok { received = read.1 }
    }
    XCTAssertEqual(Array(output[..<received]), payload)
    for _ in 0..<1_000 where sender.shutdown() != .ok {
      try progress(client, server, elapsed, paths: activePaths)
      elapsed += 1_000_000
    }
    var eof = false
    for _ in 0..<1_000 where !eof {
      try progress(client, server, elapsed, paths: activePaths)
      elapsed += 1_000_000
      let read = output.withUnsafeMutableBytes { receiver.read(into: $0) }
      eof = read == (.ok, 0)
    }
    XCTAssertTrue(eof)
  }
}
