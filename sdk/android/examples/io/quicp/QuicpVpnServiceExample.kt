package io.quicp

import android.content.Intent
import android.net.VpnService
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector

/**
 * VpnService ownership skeleton for one QUICP underlay.
 *
 * The app still owns route policy and the mapping between TUN IP packets and application flows.
 */
class QuicpVpnServiceExample : VpnService() {
    @Volatile private var running = false
    @Volatile private var selector: Selector? = null
    @Volatile private var worker: Thread? = null

    @Synchronized
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (worker?.isAlive == true) return START_NOT_STICKY
        running = true
        worker = Thread {
            try {
                val remote = InetSocketAddress("203.0.113.10", 44_443)
                DatagramChannel.open().use { channel ->
                    channel.configureBlocking(false)
                    channel.socket().bind(InetSocketAddress(40_000))
                    check(protect(channel.socket())) { "failed to protect QUICP underlay" }
                    channel.connect(remote)
                    Selector.open().use { activeSelector ->
                        selector = activeSelector
                        channel.register(activeSelector, SelectionKey.OP_READ)
                        try {
                            QuicpEngine.create(
                                role = QuicpEngine.Role.CLIENT,
                                paths = listOf(
                                    QuicpPath(
                                        local = QuicpSocketAddress("192.0.2.10", 40_000),
                                        peer = QuicpSocketAddress("203.0.113.10", 44_443),
                                    )
                                ),
                            ).use { engine ->
                                val started = System.nanoTime()
                                val packet = ByteBuffer.allocateDirect(65_535)
                                while (running) {
                                    check(
                                        engine.drive(System.nanoTime() - started).status == QuicpStatus.OK
                                    ) { "QUICP engine stopped" }
                                    while (true) {
                                        packet.clear()
                                        val result = engine.egress(0, packet)
                                        if (result.status == QuicpStatus.WOULD_BLOCK) break
                                        check(result.status == QuicpStatus.OK) { "QUICP egress failed" }
                                        packet.limit(result.bytes)
                                        check(channel.write(packet) == result.bytes) {
                                            "QUICP underlay send would block"
                                        }
                                    }
                                    val elapsed = System.nanoTime() - started
                                    val delay = engine.nextTimerNanos?.minus(elapsed)
                                    if (delay == null) {
                                        activeSelector.select()
                                    } else if (delay <= 0) {
                                        activeSelector.selectNow()
                                    } else {
                                        activeSelector.select((delay + 999_999) / 1_000_000)
                                    }
                                    activeSelector.selectedKeys().clear()
                                    packet.clear()
                                    if (channel.read(packet) > 0) {
                                        packet.flip()
                                        check(
                                            engine.ingress(0, packet, packet.remaining()) == QuicpStatus.OK
                                        ) { "QUICP ingress failed" }
                                    }
                                }
                            }
                        } finally {
                            selector = null
                        }
                    }
                }
            } finally {
                running = false
                synchronized(this) { worker = null }
                stopSelf(startId)
            }
        }.also(Thread::start)
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        running = false
        selector?.wakeup()
        super.onRevoke()
    }

    override fun onDestroy() {
        running = false
        selector?.wakeup()
        super.onDestroy()
    }
}
