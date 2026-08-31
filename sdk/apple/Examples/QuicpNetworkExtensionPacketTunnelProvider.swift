// Minimal IP-over-QUICP Network Extension client.
// The peer accepts `packet-tunnel.internal:1` and uses the same u16-length packet framing.

#if canImport(NetworkExtension)
import Network
import NetworkExtension
import Quicp

final class QuicpNetworkExtensionPacketTunnelProvider: NEPacketTunnelProvider {
  private let queue = DispatchQueue(label: "io.quicp.network-extension")
  private var engine: QuicpEngine?
  private var flow: QuicpFlow?
  private var underlay: NWConnection?
  private var startedAt: DispatchTime?
  private var startupCompletion: ((Error?) -> Void)?
  private var timer: DispatchWorkItem?
  private var outbound = Data()
  private var outboundOffset = 0
  private var inbound = Data()
  private var underlayScratch = [UInt8](repeating: 0, count: 65_535)
  private var flowScratch = [UInt8](repeating: 0, count: 65_535)
  private var readingPackets = false
  private var stopping = false

  override func startTunnel(
    options: [String: NSObject]?,
    completionHandler: @escaping (Error?) -> Void
  ) {
    queue.async { [weak self] in
      guard let self else { return }
      stopping = false
      startupCompletion = completionHandler
      do {
        let peer = QuicpSocketAddress("203.0.113.10", port: 44_443)
        engine = try QuicpEngine(
          role: .client,
          paths: [QuicpPath(
            local: QuicpSocketAddress("192.0.2.10", port: 40_000), peer: peer
          )]
        )
        let connection = NWConnection(host: "203.0.113.10", port: 44_443, using: .udp)
        underlay = connection
        startedAt = .now()
        connection.stateUpdateHandler = { [weak self] state in
          self?.queue.async { self?.underlayStateChanged(state) }
        }
        connection.start(queue: queue)
      } catch {
        finishStartup(error)
      }
    }
  }

  override func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    queue.async { [weak self] in
      guard let self else {
        completionHandler()
        return
      }
      stopping = true
      if startupCompletion != nil {
        finishStartup(NWError.posix(.ECANCELED))
      } else {
        tearDown()
      }
      completionHandler()
    }
  }

  private func underlayStateChanged(_ state: NWConnection.State) {
    guard !stopping else { return }
    switch state {
    case .ready:
      receiveUnderlay()
      drive()
    case .failed(let error):
      fail(error)
    case .cancelled:
      if startupCompletion != nil { fail(NWError.posix(.ECONNABORTED)) }
    default:
      break
    }
  }

  private func receiveUnderlay() {
    underlay?.receiveMessage { [weak self] data, _, _, error in
      self?.queue.async {
        guard let self else { return }
        guard !self.stopping else { return }
        if let error { return self.fail(error) }
        if let data {
          data.withUnsafeBytes { _ = self.engine?.ingress(path: 0, datagram: $0) }
        }
        self.drive()
        self.receiveUnderlay()
      }
    }
  }

  private func drive() {
    guard !stopping, let engine, let startedAt else { return }
    timer?.cancel()
    timer = nil
    let elapsed = DispatchTime.now().uptimeNanoseconds - startedAt.uptimeNanoseconds
    guard engine.drive(elapsedNanoseconds: elapsed).0 == .ok else {
      return fail(NWError.posix(.ECONNABORTED))
    }
    drainUnderlay(engine)
    advanceStartup(engine)
    writePacketsToFlow()
    readPacketsFromFlow()
    scheduleTimer(engine, elapsed: elapsed)
  }

  private func drainUnderlay(_ engine: QuicpEngine) {
    while true {
      let result = underlayScratch.withUnsafeMutableBytes { engine.egress(path: 0, into: $0) }
      guard result.0 == .ok else { break }
      underlay?.send(content: Data(underlayScratch.prefix(result.1)), completion: .contentProcessed {
        [weak self] error in
        guard let error else { return }
        self?.queue.async { self?.fail(error) }
      })
    }
  }

  private func advanceStartup(_ engine: QuicpEngine) {
    guard startupCompletion != nil, flow == nil, engine.connectionStatus == .ok else { return }
    switch engine.openFlow(host: "packet-tunnel.internal", port: 1) {
    case .failure(.wouldBlock):
      return
    case .failure(let error):
      fail(error)
    case .success(let flow):
      self.flow = flow
      let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "203.0.113.10")
      let ipv4 = NEIPv4Settings(addresses: ["198.18.0.2"], subnetMasks: ["255.255.255.252"])
      ipv4.includedRoutes = [NEIPv4Route.default()]
      settings.ipv4Settings = ipv4
      settings.mtu = 1_500
      setTunnelNetworkSettings(settings) { [weak self] error in
        self?.queue.async {
          guard let self else { return }
          guard !self.stopping else { return }
          if let error { return self.finishStartup(error) }
          self.finishStartup(nil)
          self.requestPackets()
        }
      }
    }
  }

  private func requestPackets() {
    guard !readingPackets, outbound.isEmpty else { return }
    readingPackets = true
    packetFlow.readPackets { [weak self] packets, _ in
      self?.queue.async {
        guard let self else { return }
        self.readingPackets = false
        for packet in packets {
          guard !packet.isEmpty, packet.count <= Int(UInt16.max) else { continue }
          var length = UInt16(packet.count).bigEndian
          withUnsafeBytes(of: &length) { self.outbound.append(contentsOf: $0) }
          self.outbound.append(packet)
        }
        self.outboundOffset = 0
        self.drive()
      }
    }
  }

  private func writePacketsToFlow() {
    guard let flow else { return }
    while outboundOffset < outbound.count {
      let result = outbound.withUnsafeBytes { bytes in
        flow.write(from: UnsafeRawBufferPointer(rebasing: bytes[outboundOffset...]))
      }
      if result.0 == .wouldBlock { break }
      guard result.0 == .ok, result.1 > 0 else {
        return fail(NWError.posix(.ECONNABORTED))
      }
      outboundOffset += result.1
    }
    guard outboundOffset == outbound.count else { return }
    outbound.removeAll(keepingCapacity: true)
    outboundOffset = 0
    let status = flow.flush()
    guard status == .ok || status == .wouldBlock else {
      return fail(NWError.posix(.ECONNABORTED))
    }
    requestPackets()
  }

  private func readPacketsFromFlow() {
    guard let flow else { return }
    var packets = [Data]()
    while true {
      let result = flowScratch.withUnsafeMutableBytes { flow.read(into: $0) }
      if result.0 == .wouldBlock { break }
      guard result.0 == .ok else { return fail(NWError.posix(.ECONNABORTED)) }
      if result.1 == 0 { return fail(NWError.posix(.ECONNABORTED)) }
      inbound.append(contentsOf: flowScratch.prefix(result.1))
    }
    var consumed = 0
    while inbound.count - consumed >= 2 {
      let length = Int(inbound.withUnsafeBytes { bytes in
        UInt16(bigEndian: bytes.loadUnaligned(fromByteOffset: consumed, as: UInt16.self))
      })
      guard length != 0 else { return fail(NWError.posix(.EINVAL)) }
      guard inbound.count - consumed >= length + 2 else { break }
      packets.append(inbound.subdata(in: (consumed + 2)..<(consumed + length + 2)))
      consumed += length + 2
    }
    if consumed != 0 { inbound.removeSubrange(0..<consumed) }
    guard !packets.isEmpty else { return }
    let protocols = packets.map { packet -> NSNumber in
      NSNumber(value: packet.first.map { $0 >> 4 == 6 ? AF_INET6 : AF_INET } ?? AF_INET)
    }
    packetFlow.writePackets(packets, withProtocols: protocols)
  }

  private func scheduleTimer(_ engine: QuicpEngine, elapsed: UInt64) {
    guard let deadline = engine.nextTimerNanoseconds else { return }
    let delay = deadline > elapsed ? deadline - elapsed : 0
    let work = DispatchWorkItem { [weak self] in self?.drive() }
    timer = work
    queue.asyncAfter(
      deadline: .now() + .nanoseconds(Int(min(delay, UInt64(Int.max)))), execute: work
    )
  }

  private func finishStartup(_ error: Error?) {
    guard let completion = startupCompletion else { return }
    startupCompletion = nil
    if error != nil { tearDown() }
    completion(error)
  }

  private func fail(_ error: Error) {
    if startupCompletion != nil {
      finishStartup(error)
    } else {
      cancelTunnelWithError(error)
      tearDown()
    }
  }

  private func tearDown() {
    timer?.cancel()
    timer = nil
    underlay?.stateUpdateHandler = nil
    underlay?.cancel()
    underlay = nil
    _ = flow?.close()
    flow = nil
    _ = engine?.close()
    engine = nil
    startedAt = nil
    outbound.removeAll(keepingCapacity: false)
    inbound.removeAll(keepingCapacity: false)
    readingPackets = false
  }
}
#endif
