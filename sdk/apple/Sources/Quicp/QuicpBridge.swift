import CQuicp

public typealias QuicpInputPacket = quicp_input_packet_t
public typealias QuicpOutputPacket = quicp_output_packet_t

public enum QuicpStatus: UInt32, Error, Sendable {
  case ok = 0
  case wouldBlock = 1
  case bufferTooSmall = 2
  case invalidArgument = 3
  case notReady = 4
  case closed = 5
  case panic = 6
}

public struct QuicpBatchResult: Sendable {
  public let status: QuicpStatus
  public let inputsConsumed: UInt32
  public let outputsWritten: UInt32
}

/// A single-owner, nonblocking bridge over caller-owned packet buffers.
///
/// Calls on one instance must be serialized by the owning executor.
public final class QuicpBridge {
  private var raw: OpaquePointer?

  public init() throws {
    guard quicp_abi_version() == QUICP_ABI_VERSION else {
      throw QuicpStatus.notReady
    }
    let status = QuicpStatus(rawValue: quicp_bridge_create(&raw)) ?? .panic
    guard status == .ok else { throw status }
  }

  deinit {
    _ = close()
  }

  @discardableResult
  public func close() -> QuicpStatus {
    guard raw != nil else { return .closed }
    return QuicpStatus(rawValue: quicp_bridge_close(&raw)) ?? .panic
  }

  public func processBatch(
    inputs: UnsafeBufferPointer<QuicpInputPacket>,
    outputs: UnsafeMutableBufferPointer<QuicpOutputPacket>
  ) -> QuicpBatchResult {
    guard let raw else {
      return QuicpBatchResult(status: .closed, inputsConsumed: 0, outputsWritten: 0)
    }
    guard inputs.count <= QUICP_MAX_BATCH_PACKETS,
      outputs.count <= QUICP_MAX_BATCH_PACKETS
    else {
      return QuicpBatchResult(
        status: .invalidArgument,
        inputsConsumed: 0,
        outputsWritten: 0
      )
    }

    var result = quicp_batch_result_t(inputs_consumed: 0, outputs_written: 0)
    let status = quicp_bridge_process_batch(
      raw,
      inputs.baseAddress,
      UInt32(inputs.count),
      outputs.baseAddress,
      UInt32(outputs.count),
      &result
    )
    return QuicpBatchResult(
      status: QuicpStatus(rawValue: status) ?? .panic,
      inputsConsumed: result.inputs_consumed,
      outputsWritten: result.outputs_written
    )
  }
}
