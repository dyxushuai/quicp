// Example host loop for an iOS Network Extension.
//
// The Rust bridge is only the bounded packet seam. A production provider still has to connect
// these packets to a permitted underlay carrier and apply its own route/admission policy.

#if canImport(NetworkExtension)
import NetworkExtension
import Quicp

final class QuicpNetworkExtensionPacketTunnelProvider: NEPacketTunnelProvider {
  private var bridge: QuicpBridge?

  override func startTunnel(
    options: [String: NSObject]?,
    completionHandler: @escaping (Error?) -> Void
  ) {
    do {
      let bridge = try QuicpBridge()
      let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.1")
      settings.ipv4Settings = NEIPv4Settings(
        addresses: ["198.18.0.2"],
        subnetMasks: ["255.255.0.0"]
      )
      settings.ipv4Settings?.includedRoutes = [NEIPv4Route.default()]
      setTunnelNetworkSettings(settings) { [weak self] error in
        guard let self, error == nil else {
          completionHandler(error)
          return
        }
        self.bridge = bridge
        self.readPackets()
        completionHandler(nil)
      }
    } catch {
      completionHandler(error)
    }
  }

  override func stopTunnel(
    with reason: NEProviderStopReason,
    completionHandler: @escaping () -> Void
  ) {
    bridge?.close()
    bridge = nil
    completionHandler()
  }

  private func readPackets() {
    packetFlow.readPackets { [weak self] packets, protocols in
      guard let self, let bridge = self.bridge else { return }
      let batchSize = Int(QUICP_MAX_BATCH_PACKETS)
      for start in stride(from: 0, to: packets.count, by: batchSize) {
        let end = min(start + batchSize, packets.count)
        self.process(Array(packets[start..<end]), protocols: Array(protocols[start..<end]), bridge: bridge)
      }
      self.readPackets()
    }
  }

  private func process(_ packets: [Data], protocols: [NSNumber], bridge: QuicpBridge) {
    guard !packets.isEmpty else { return }
    withInputPointers(packets) { inputs in
      var outputStorage = packets.map { _ in [UInt8](repeating: 0, count: 65_535) }
      withOutputPointers(&outputStorage) { outputs in
        let result = bridge.processBatch(inputs: inputs, outputs: outputs)
        guard result.status == .ok || result.status == .wouldBlock else { return }
        var forwarded = [Data]()
        var forwardedProtocols = [NSNumber]()
        for index in 0..<result.outputsWritten {
          let length = Int(outputs[index].len)
          forwarded.append(Data(outputStorage[index].prefix(length)))
          forwardedProtocols.append(protocols[index])
        }
        if !forwarded.isEmpty {
          packetFlow.writePackets(forwarded, withProtocols: forwardedProtocols)
        }
      }
    }
  }

  private func withInputPointers<R>(
    _ packets: [Data],
    index: Int = 0,
    descriptors: [QuicpInputPacket] = [],
    _ body: (UnsafeBufferPointer<QuicpInputPacket>) -> R
  ) -> R {
    guard index < packets.count else {
      return descriptors.withUnsafeBufferPointer(body)
    }
    return packets[index].withUnsafeBytes { bytes in
      var next = descriptors
      next.append(
        QuicpInputPacket(
          data: bytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
          len: UInt32(bytes.count)
        )
      )
      return withInputPointers(packets, index: index + 1, descriptors: next, body)
    }
  }

  private func withOutputPointers<R>(
    _ storage: inout [[UInt8]],
    index: Int = 0,
    descriptors: [QuicpOutputPacket] = [],
    _ body: (UnsafeMutableBufferPointer<QuicpOutputPacket>) -> R
  ) -> R {
    guard index < storage.count else {
      return descriptors.withUnsafeMutableBufferPointer(body)
    }
    return storage[index].withUnsafeMutableBufferPointer { bytes in
      var next = descriptors
      next.append(
        QuicpOutputPacket(data: bytes.baseAddress, capacity: UInt32(bytes.count), len: 0)
      )
      return withOutputPointers(&storage, index: index + 1, descriptors: next, body)
    }
  }
}
#endif
