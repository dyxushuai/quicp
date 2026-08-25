package io.quicp

import java.nio.ByteBuffer
import java.nio.ByteOrder

fun main() {
    QuicpBridge.create().use { bridge ->
        val empty = bridge.processBatch(null, null, 0, null, null, 0)
        check(empty.status == QuicpBridge.STATUS_WOULD_BLOCK)

        val packet = ByteBuffer.allocateDirect(64)
        val descriptor = ByteBuffer.allocateDirect(QuicpBridge.INPUT_DESCRIPTOR_BYTES)
            .order(ByteOrder.nativeOrder())
        descriptor.putInt(0, 0)
        descriptor.putInt(Int.SIZE_BYTES, packet.capacity())
        val accepted = bridge.processBatch(packet, descriptor, 1, null, null, 0)
        check(accepted.status == QuicpBridge.STATUS_OK)
        check(accepted.inputsConsumed == 1)

        val shiftedPacket = packet.duplicate().position(1)
        check(
            runCatching {
                bridge.processBatch(shiftedPacket, descriptor, 1, null, null, 0)
            }.exceptionOrNull() is IllegalArgumentException
        )

        descriptor.putInt(0, 1)
        val rejected = bridge.processBatch(packet, descriptor, 1, null, null, 0)
        check(rejected.status == QuicpBridge.STATUS_INVALID_ARGUMENT)
        check(rejected.inputsConsumed == 0)

        val output = ByteBuffer.allocateDirect(64).asReadOnlyBuffer()
        val outputDescriptor = ByteBuffer.allocateDirect(QuicpBridge.OUTPUT_DESCRIPTOR_BYTES)
            .order(ByteOrder.nativeOrder())
        check(
            runCatching {
                bridge.processBatch(null, null, 0, output, outputDescriptor, 1)
            }.exceptionOrNull() is IllegalArgumentException
        )
    }
}
