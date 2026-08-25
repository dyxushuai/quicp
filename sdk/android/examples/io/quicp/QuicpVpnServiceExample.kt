package io.quicp

import android.content.Intent
import android.net.VpnService
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal VpnService packet-loop example.
 *
 * The Rust bridge owns only bounded packet queues. The service owns the TUN descriptor, the
 * underlay socket/carrier, cancellation, and the single-thread call ordering. This example does
 * not grant raw underlay access or implement routing by itself.
 */
class QuicpVpnServiceExample : VpnService() {
    @Volatile
    private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val tun = Builder()
            .setSession("QUICP")
            .addAddress("198.18.0.2", 15)
            .addRoute("0.0.0.0", 0)
            .establish() ?: return START_NOT_STICKY

        Thread {
            QuicpBridge.create().use { bridge ->
                running = true
                val input = FileInputStream(tun.fileDescriptor).channel
                val output = FileOutputStream(tun.fileDescriptor).channel
                val inputData = ByteBuffer.allocateDirect(64 * 1500)
                val inputDescriptors = ByteBuffer.allocateDirect(64 * QuicpBridge.INPUT_DESCRIPTOR_BYTES)
                    .order(ByteOrder.nativeOrder())
                val outputData = ByteBuffer.allocateDirect(64 * 1500)
                val outputDescriptors = ByteBuffer.allocateDirect(64 * QuicpBridge.OUTPUT_DESCRIPTOR_BYTES)
                    .order(ByteOrder.nativeOrder())

                // Replace this loop's TUN reads/writes with the app's nonblocking selector. The
                // bridge call remains single-owner and all descriptor memory stays host-owned.
                while (running) {
                    inputData.clear()
                    inputDescriptors.clear()
                    outputData.clear()
                    outputDescriptors.clear()
                    val length = input.read(inputData)
                    if (length <= 0) break
                    inputDescriptors.putInt(0, 0)
                    inputDescriptors.putInt(Int.SIZE_BYTES, length)
                    for (index in 0 until 64) {
                        val field = index * QuicpBridge.OUTPUT_DESCRIPTOR_BYTES
                        outputDescriptors.putInt(field, index * 1500)
                        outputDescriptors.putInt(field + Int.SIZE_BYTES, 1500)
                        outputDescriptors.putInt(field + 2 * Int.SIZE_BYTES, 0)
                    }
                    val result = bridge.processBatch(
                        inputData,
                        inputDescriptors,
                        1,
                        outputData,
                        outputDescriptors,
                        64,
                    )
                    if (result.status == QuicpBridge.STATUS_CLOSED) break
                    for (index in 0 until result.outputsWritten) {
                        val field = index * QuicpBridge.OUTPUT_DESCRIPTOR_BYTES
                        val offset = outputDescriptors.getInt(field)
                        val produced = outputDescriptors.getInt(field + 2 * Int.SIZE_BYTES)
                        outputData.position(offset)
                        outputData.limit(offset + produced)
                        while (outputData.hasRemaining()) output.write(outputData)
                        outputData.clear()
                    }
                    // Pump the permitted underlay carrier after this TUN tick. It must feed
                    // returned datagrams back through ingress descriptors on the next iteration.
                }
                input.close()
                output.close()
            }
            tun.close()
        }.start()
        return START_STICKY
    }

    override fun onRevoke() {
        running = false
        super.onRevoke()
    }
}
