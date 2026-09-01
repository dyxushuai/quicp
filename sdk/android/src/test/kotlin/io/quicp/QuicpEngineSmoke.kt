package io.quicp

import java.nio.ByteBuffer

private fun pump(source: QuicpEngine, destination: QuicpEngine, path: Int) {
    val packet = ByteBuffer.allocateDirect(2_048)
    while (true) {
        val result = source.egress(path, packet)
        if (result.status == QuicpStatus.WOULD_BLOCK) return
        check(result.status == QuicpStatus.OK)
        check(destination.ingress(path, packet, result.bytes) == QuicpStatus.OK)
        check(packet.position() == 0 && packet.capacity() == 2_048)
    }
}

private fun progress(
    client: QuicpEngine,
    server: QuicpEngine,
    elapsedNanos: Long,
    paths: IntRange,
) {
    check(client.drive(elapsedNanos).status == QuicpStatus.OK)
    check(server.drive(elapsedNanos).status == QuicpStatus.OK)
    paths.forEach { path ->
        pump(client, server, path)
        pump(server, client, path)
    }
}

fun main() {
    check(runCatching { QuicpStatus.decode(99) }.exceptionOrNull() is IllegalStateException)
    check(
        runCatching {
            QuicpEngine.create(
                role = QuicpEngine.Role.CLIENT,
                paths = listOf(
                    QuicpPath(
                        local = QuicpSocketAddress("localhost.example", 40_000),
                        peer = QuicpSocketAddress("127.0.0.1", 40_001),
                    )
                ),
            )
        }.exceptionOrNull() is IllegalArgumentException
    )
    check(
        runCatching {
            QuicpEngine.create(
                role = QuicpEngine.Role.CLIENT,
                paths = listOf(
                    QuicpPath(
                        local = QuicpSocketAddress("127.0.0.1", 40_000),
                        peer = QuicpSocketAddress("127.0.0.1", 40_001),
                    )
                ),
                security = QuicpEngine.Security.MutualTls(
                    serverName = "server.example",
                    caCertificate = "relative-ca.pem",
                    certificate = "relative-cert.pem",
                    privateKey = "relative-key.pem",
                ),
            )
        }.exceptionOrNull() is QuicpException
    )

    val client = QuicpEngine.create(
        role = QuicpEngine.Role.CLIENT,
        paths = listOf(
            QuicpPath(
                local = QuicpSocketAddress("127.0.0.1", 41_000),
                peer = QuicpSocketAddress("127.0.0.1", 41_001),
            ),
            QuicpPath(
                local = QuicpSocketAddress("127.0.0.1", 41_002),
                peer = QuicpSocketAddress("127.0.0.1", 41_003),
            ),
        ),
        recoveryMode = QuicpEngine.RecoveryMode.RELIABLE_ONLY,
    )
    val server = QuicpEngine.create(
        role = QuicpEngine.Role.SERVER,
        paths = listOf(
            QuicpPath(
                local = QuicpSocketAddress("127.0.0.1", 41_001),
                peer = QuicpSocketAddress("127.0.0.1", 41_000),
            ),
            QuicpPath(
                local = QuicpSocketAddress("127.0.0.1", 41_003),
                peer = QuicpSocketAddress("127.0.0.1", 41_002),
            ),
        ),
        recoveryMode = QuicpEngine.RecoveryMode.RELIABLE_ONLY,
    )

    client.use {
        server.use {
            val limited = ByteBuffer.allocateDirect(8).limit(1)
            check(
                runCatching { client.ingress(0, limited, 2) }.exceptionOrNull()
                    is IllegalArgumentException
            )
            var elapsed = 0L
            var attempts = 0
            while ((client.connectionStatus != QuicpStatus.OK ||
                    server.connectionStatus != QuicpStatus.OK) && attempts < 6_000
            ) {
                progress(client, server, elapsed, 0..1)
                elapsed += 1_000_000
                attempts += 1
            }
            check(client.connectionStatus == QuicpStatus.OK)
            check(server.connectionStatus == QuicpStatus.OK)

            var primeSender: QuicpFlow? = null
            var primePending: QuicpPendingFlow? = null
            var primeReceiver: QuicpFlow? = null
            attempts = 0
            while ((primeSender == null || primeReceiver == null) && attempts < 1_000) {
                if (primeSender == null) {
                    primeSender = client.openFlow("prime.example", 443).getOrNull()
                }
                if (primePending == null) {
                    primePending = server.pollFlowRequest().getOrNull()
                }
                if (primeReceiver == null) {
                    primeReceiver = primePending?.accept()?.getOrNull()
                }
                progress(client, server, elapsed, 0..1)
                elapsed += 1_000_000
                attempts += 1
            }
            check(primeSender != null && primeReceiver != null)
            primeSender.close()
            primeReceiver.close()

            repeat(1_000) {
                progress(client, server, elapsed, 0..1)
                elapsed += 1_000_000
            }
            check(client.markPathUnavailable(0) == QuicpStatus.OK)
            check(server.markPathUnavailable(0) == QuicpStatus.OK)

            val secret = ByteBuffer.allocateDirect(32)
            repeat(32) { secret.put(it, 0x5a.toByte()) }
            check(server.configureReplayAdmission(secret, 32, 7, 16) == QuicpStatus.OK)
            val nowSeconds = System.currentTimeMillis() / 1_000
            check(
                server.issueReplayToken(nowSeconds, 60, ByteBuffer.allocateDirect(0)) ==
                    QuicpIoResult(QuicpStatus.BUFFER_TOO_SMALL, 73)
            )
            val token = ByteBuffer.allocateDirect(73)
            check(
                server.issueReplayToken(nowSeconds, 60, token) ==
                    QuicpIoResult(QuicpStatus.OK, 73)
            )
            check(token.position() == 0 && token.capacity() == 73)
            val initialBytes = "Kotlin replay-safe initial bytes".encodeToByteArray()
            val initial = ByteBuffer.allocateDirect(initialBytes.size).put(initialBytes).rewind()
            var sender: QuicpFlow? = null
            var pending: QuicpPendingFlow? = null
            var receiver: QuicpFlow? = null
            attempts = 0
            while ((sender == null || receiver == null) && attempts < 1_000) {
                if (sender == null) {
                    sender = client.openReplaySafeFlow(
                        token, 73, 42, "kotlin.example", 443, initial, initialBytes.size
                    ).getOrNull()
                }
                if (pending == null) {
                    pending = server.pollFlowRequest(replaySafe = true).getOrNull()
                }
                if (receiver == null) {
                    receiver = pending?.accept()?.getOrNull()
                }
                progress(client, server, elapsed, 1..1)
                elapsed += 1_000_000
                attempts += 1
            }

            sender!!.use { flow ->
                receiver!!.use { peer ->
                    val output = ByteBuffer.allocateDirect(64)
                    var received = 0
                    attempts = 0
                    while (received == 0 && attempts < 1_000) {
                        progress(client, server, elapsed, 1..1)
                        elapsed += 1_000_000
                        val result = peer.read(output)
                        if (result.status == QuicpStatus.OK) received = result.bytes
                        attempts += 1
                    }
                    check(received == initialBytes.size)
                    check(initialBytes.indices.all { output.get(it) == initialBytes[it] })

                    val payload = "QUICP/2 through Kotlin".encodeToByteArray()
                    val input = ByteBuffer.allocateDirect(payload.size).put(payload).rewind()
                    check(
                        flow.write(input, payload.size) ==
                            QuicpIoResult(QuicpStatus.OK, payload.size)
                    )
                    check(input.position() == 0 && input.capacity() == payload.size)

                    received = 0
                    attempts = 0
                    while (received == 0 && attempts < 1_000) {
                        check(
                            flow.flush() in
                                listOf(QuicpStatus.OK, QuicpStatus.WOULD_BLOCK)
                        )
                        progress(client, server, elapsed, 1..1)
                        elapsed += 1_000_000
                        val result = peer.read(output)
                        if (result.status == QuicpStatus.OK) received = result.bytes
                        attempts += 1
                    }
                    check(received == payload.size)
                    check(payload.indices.all { output.get(it) == payload[it] })
                    check(output.position() == 0 && output.capacity() == 64)
                    attempts = 0
                    while (flow.shutdown() != QuicpStatus.OK && attempts < 1_000) {
                        progress(client, server, elapsed, 1..1)
                        elapsed += 1_000_000
                        attempts += 1
                    }
                    var eof = false
                    attempts = 0
                    while (!eof && attempts < 1_000) {
                        progress(client, server, elapsed, 1..1)
                        elapsed += 1_000_000
                        val result = peer.read(output)
                        eof = result == QuicpIoResult(QuicpStatus.OK, 0)
                        attempts += 1
                    }
                    check(eof)
                }
            }
        }
    }

    val closedFlow = QuicpFlow(client, 1)
    val closedBuffer = ByteBuffer.allocateDirect(1)
    check(closedFlow.read(closedBuffer) == QuicpIoResult(QuicpStatus.CLOSED, 0))
    check(closedFlow.write(closedBuffer, 1) == QuicpIoResult(QuicpStatus.CLOSED, 0))
    check(closedFlow.flush() == QuicpStatus.CLOSED)
    check(closedFlow.shutdown() == QuicpStatus.CLOSED)
    closedFlow.close()
}
