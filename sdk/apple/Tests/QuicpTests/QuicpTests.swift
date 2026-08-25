import XCTest

@testable import Quicp

final class QuicpTests: XCTestCase {
  func testBridgeLifecycleAndEmptyBatch() throws {
    let bridge = try QuicpBridge()
    let inputs: [QuicpInputPacket] = []
    var outputs: [QuicpOutputPacket] = []
    let result = inputs.withUnsafeBufferPointer { inputs in
      outputs.withUnsafeMutableBufferPointer { outputs in
        bridge.processBatch(inputs: inputs, outputs: outputs)
      }
    }
    XCTAssertEqual(result.status, .wouldBlock)
    XCTAssertEqual(result.inputsConsumed, 0)
    XCTAssertEqual(result.outputsWritten, 0)

    let packet = [UInt8](repeating: 0x45, count: 64)
    let accepted = packet.withUnsafeBufferPointer { packet in
      let inputs = [
        QuicpInputPacket(data: packet.baseAddress, len: UInt32(packet.count))
      ]
      return inputs.withUnsafeBufferPointer { inputs in
        outputs.withUnsafeMutableBufferPointer { outputs in
          bridge.processBatch(inputs: inputs, outputs: outputs)
        }
      }
    }
    XCTAssertEqual(accepted.status, .ok)
    XCTAssertEqual(accepted.inputsConsumed, 1)
    XCTAssertEqual(bridge.close(), .ok)
    XCTAssertEqual(bridge.close(), .closed)
  }
}
