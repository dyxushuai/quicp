package io.quicp

import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer

data class QuicpSocketAddress(val address: String, val port: Int)
data class QuicpPath(val local: QuicpSocketAddress, val peer: QuicpSocketAddress)
enum class QuicpStatus(val wire: Int) {
    OK(0), WOULD_BLOCK(1), BUFFER_TOO_SMALL(2), INVALID_ARGUMENT(3),
    NOT_READY(4), CLOSED(5), PANIC(6), FAILED(7);

    companion object {
        fun decode(wire: Int): QuicpStatus =
            entries.firstOrNull { it.wire == wire }
                ?: throw IllegalStateException("unknown QUICP status $wire")
    }
}
data class QuicpIoResult(val status: QuicpStatus, val bytes: Int)
data class QuicpDriveResult(val status: QuicpStatus, val tasks: Int)
data class QuicpRecoverySnapshot(
    val sourceSent: Long,
    val sourceReceived: Long,
    val repairSent: Long,
    val recovered: Long,
    val replayed: Long,
    val fallback: Long,
    val dropped: Long,
    val earlyAccepted: Long,
    val earlyRejected: Long,
    val pathLostPackets: Long,
    val maxPathRttMicros: Long,
    val queuedDatagrams: Long,
    val retainedSourceBytes: Long,
)

/** Single-owner synchronous engine. The owning event loop serializes every call. */
class QuicpEngine private constructor(private var handle: Long) : AutoCloseable {
    enum class Role(val wire: Int) { CLIENT(1), SERVER(2) }
    enum class RecoveryMode(val wire: Int) { ADAPTIVE(1), RELIABLE_ONLY(2) }
    sealed interface Security {
        data object Insecure : Security
        data class MutualTls(
            val serverName: String,
            val caCertificate: String,
            val certificate: String,
            val privateKey: String,
        ) : Security
    }

    companion object {
        init { System.loadLibrary("quicp_jni") }

        @JvmStatic
        fun create(
            role: Role,
            paths: List<QuicpPath>,
            packetCapacity: Int = 256,
            mtu: Int = 1500,
            recoveryMode: RecoveryMode = RecoveryMode.ADAPTIVE,
            security: Security = Security.Insecure,
        ): QuicpEngine {
            require(paths.size in 1..2)
            require(packetCapacity > 0 && mtu > 0)
            val config = ByteBuffer.allocateDirect(nativeConfigSize())
            check(
                status(
                    nativeInitConfig(
                        config, role.wire, paths.size, packetCapacity, mtu, recoveryMode.wire
                    )
                ) == QuicpStatus.OK
            )
            paths.forEachIndexed { index, path ->
                check(
                    status(
                        nativeSetPath(
                            config, index,
                            address(path.local), path.local.port,
                            address(path.peer), path.peer.port,
                        )
                    ) == QuicpStatus.OK
                )
            }
            val status = IntArray(1)
            val handle = when (security) {
                Security.Insecure -> nativeCreate(config, status)
                is Security.MutualTls -> nativeCreateTls(
                    config,
                    status,
                    security.serverName.encodeToByteArray(),
                    security.caCertificate.encodeToByteArray(),
                    security.certificate.encodeToByteArray(),
                    security.privateKey.encodeToByteArray(),
                )
            }
            if (handle == 0L) throw QuicpException(QuicpStatus.decode(status[0]))
            return QuicpEngine(handle)
        }

        private fun address(value: QuicpSocketAddress): ByteArray {
            require(value.port in 1..65535)
            return if (value.address.contains(':')) {
                require(!value.address.contains('%'))
                val parsed = InetAddress.getByName(value.address)
                require(parsed is Inet6Address)
                parsed.address
            } else {
                val octets = value.address.split('.')
                require(octets.size == 4)
                octets.map { octet ->
                    require(octet.isNotEmpty() && (octet == "0" || !octet.startsWith('0')))
                    require(octet.all(Char::isDigit))
                    val number = octet.toInt()
                    require(number in 0..255)
                    number.toByte()
                }.toByteArray()
            }
        }

        @JvmStatic private external fun nativeConfigSize(): Int
        @JvmStatic private external fun nativeInitConfig(
            config: ByteBuffer, role: Int, pathCount: Int, packetCapacity: Int,
            mtu: Int, recoveryMode: Int,
        ): Int
        @JvmStatic private external fun nativeSetPath(
            config: ByteBuffer, path: Int,
            localAddress: ByteArray, localPort: Int,
            peerAddress: ByteArray, peerPort: Int,
        ): Int
        @JvmStatic private external fun nativeCreate(config: ByteBuffer, status: IntArray): Long
        @JvmStatic private external fun nativeCreateTls(
            config: ByteBuffer,
            status: IntArray,
            serverName: ByteArray,
            caCertificate: ByteArray,
            certificate: ByteArray,
            privateKey: ByteArray,
        ): Long
        @JvmStatic private external fun nativeDrive(handle: Long, elapsedNanos: Long, maxTasks: Int): Long
        @JvmStatic private external fun nativeNextTimer(handle: Long): Long
        @JvmStatic private external fun nativeConnectionState(handle: Long): Int
        @JvmStatic private external fun nativeRecoverySnapshot(handle: Long, output: LongArray): Int
        @JvmStatic private external fun nativeIngress(handle: Long, path: Int, data: ByteBuffer, length: Int): Int
        @JvmStatic private external fun nativeEgress(handle: Long, path: Int, output: ByteBuffer, limit: Int): Long
        @JvmStatic private external fun nativePathUnavailable(handle: Long, path: Int): Int
        @JvmStatic private external fun nativeOpenFlow(
            handle: Long, host: ByteArray, port: Int, flow: LongArray,
        ): Int
        @JvmStatic private external fun nativeOpenReplaySafeFlow(
            handle: Long,
            token: ByteBuffer,
            tokenLength: Int,
            nonce: Long,
            host: ByteArray,
            port: Int,
            initial: ByteBuffer,
            initialLength: Int,
            flow: LongArray,
        ): Int
        @JvmStatic private external fun nativePollFlowRequest(
            handle: Long,
            replay: Boolean,
            host: ByteBuffer,
            initial: ByteBuffer,
            metadata: LongArray,
        ): Int
        @JvmStatic private external fun nativeAcceptPendingFlow(
            handle: Long, request: Long, flow: LongArray,
        ): Int
        @JvmStatic private external fun nativeRejectPendingFlow(handle: Long, request: Long): Int
        @JvmStatic private external fun nativeConfigureReplayAdmission(
            handle: Long,
            secret: ByteBuffer,
            secretLength: Int,
            epoch: Long,
            maxAttempts: Int,
        ): Int
        @JvmStatic private external fun nativeIssueReplayToken(
            handle: Long,
            nowSeconds: Long,
            ttlSeconds: Long,
            output: ByteBuffer,
            limit: Int,
        ): Long
        @JvmStatic private external fun nativeRead(handle: Long, flow: Long, output: ByteBuffer, limit: Int): Long
        @JvmStatic private external fun nativeWrite(handle: Long, flow: Long, input: ByteBuffer, length: Int): Long
        @JvmStatic private external fun nativeFlush(handle: Long, flow: Long): Int
        @JvmStatic private external fun nativeShutdown(handle: Long, flow: Long): Int
        @JvmStatic private external fun nativeCloseFlow(handle: Long, flow: Long): Int
        @JvmStatic private external fun nativeClose(handle: Long): Int

        private fun status(packed: Long) = QuicpStatus.decode(packed.toInt())
        private fun status(raw: Int) = QuicpStatus.decode(raw)
        private fun value(packed: Long) = (packed ushr 32).toInt()
        private fun flow(rawStatus: Int, output: LongArray, engine: QuicpEngine): Result<QuicpFlow> {
            val decoded = status(rawStatus)
            return if (decoded == QuicpStatus.OK) {
                Result.success(QuicpFlow(engine, output[0]))
            } else {
                Result.failure(QuicpException(decoded))
            }
        }
    }

    val connectionStatus: QuicpStatus
        get() = if (handle == 0L) QuicpStatus.CLOSED else status(nativeConnectionState(handle))
    val nextTimerNanos: Long? get() = nativeNextTimer(handle).takeIf { it >= 0 }
    private val requestHost = ByteBuffer.allocateDirect(253)
    private val requestInitial = ByteBuffer.allocateDirect(32 * 1024)
    private val requestMetadata = LongArray(4)

    fun recoverySnapshot(): Result<QuicpRecoverySnapshot> {
        if (handle == 0L) return Result.failure(QuicpException(QuicpStatus.CLOSED))
        val values = LongArray(13)
        val status = status(nativeRecoverySnapshot(handle, values))
        return if (status == QuicpStatus.OK) {
            Result.success(
                QuicpRecoverySnapshot(
                    values[0], values[1], values[2], values[3], values[4],
                    values[5], values[6], values[7], values[8], values[9],
                    values[10], values[11], values[12],
                )
            )
        } else {
            Result.failure(QuicpException(status))
        }
    }

    fun drive(elapsedNanos: Long, maxTasks: Int = 256): QuicpDriveResult {
        if (handle == 0L) return QuicpDriveResult(QuicpStatus.CLOSED, 0)
        val packed = nativeDrive(handle, elapsedNanos, maxTasks)
        return QuicpDriveResult(status(packed), value(packed))
    }

    fun ingress(path: Int, data: ByteBuffer, length: Int): QuicpStatus {
        requireDirect(data)
        require(length in 1..data.limit())
        return if (handle == 0L) QuicpStatus.CLOSED else status(nativeIngress(handle, path, data, length))
    }

    fun egress(path: Int, output: ByteBuffer): QuicpIoResult {
        requireDirect(output, writable = true)
        if (handle == 0L) return QuicpIoResult(QuicpStatus.CLOSED, 0)
        val packed = nativeEgress(handle, path, output, output.limit())
        return QuicpIoResult(status(packed), value(packed))
    }

    fun markPathUnavailable(path: Int): QuicpStatus =
        if (handle == 0L) QuicpStatus.CLOSED else status(nativePathUnavailable(handle, path))

    fun openFlow(host: String, port: Int): Result<QuicpFlow> {
        require(port in 1..65535)
        if (handle == 0L) return Result.failure(QuicpException(QuicpStatus.CLOSED))
        val output = LongArray(1)
        return flow(nativeOpenFlow(handle, host.encodeToByteArray(), port, output), output, this)
    }

    fun openReplaySafeFlow(
        token: ByteBuffer,
        tokenLength: Int,
        nonce: Long,
        host: String,
        port: Int,
        initial: ByteBuffer,
        initialLength: Int,
    ): Result<QuicpFlow> {
        requireDirect(token)
        requireDirect(initial)
        require(tokenLength in 1..token.limit())
        require(initialLength in 1..initial.limit())
        require(port in 1..65535)
        if (handle == 0L) return Result.failure(QuicpException(QuicpStatus.CLOSED))
        val output = LongArray(1)
        val status = nativeOpenReplaySafeFlow(
            handle, token, tokenLength, nonce, host.encodeToByteArray(), port, initial,
            initialLength, output,
        )
        return flow(status, output, this)
    }

    fun pollFlowRequest(replaySafe: Boolean = false): Result<QuicpPendingFlow> {
        if (handle == 0L) return Result.failure(QuicpException(QuicpStatus.CLOSED))
        val status = status(
            nativePollFlowRequest(
                handle, replaySafe, requestHost, requestInitial, requestMetadata,
            )
        )
        if (status != QuicpStatus.OK) return Result.failure(QuicpException(status))
        val hostLength = requestMetadata[1].toInt()
        val initialLength = requestMetadata[3].toInt()
        if (hostLength !in 1..requestHost.capacity() || initialLength !in 0..requestInitial.capacity()) {
            return Result.failure(QuicpException(QuicpStatus.FAILED))
        }
        val host = ByteArray(hostLength)
        requestHost.position(0)
        requestHost.get(host)
        requestHost.clear()
        val initial = ByteArray(initialLength)
        requestInitial.position(0)
        requestInitial.get(initial)
        requestInitial.clear()
        return Result.success(
            QuicpPendingFlow(
                this,
                requestMetadata[0],
                host.decodeToString(throwOnInvalidSequence = true),
                requestMetadata[2].toInt(),
                initial,
            )
        )
    }

    fun configureReplayAdmission(
        secret: ByteBuffer,
        secretLength: Int,
        epoch: Long,
        maxAttempts: Int,
    ): QuicpStatus {
        requireDirect(secret)
        require(secretLength in 32..secret.limit())
        require(maxAttempts > 0)
        return if (handle == 0L) QuicpStatus.CLOSED else status(
            nativeConfigureReplayAdmission(handle, secret, secretLength, epoch, maxAttempts)
        )
    }

    fun issueReplayToken(
        nowSeconds: Long,
        ttlSeconds: Long,
        output: ByteBuffer,
    ): QuicpIoResult {
        require(nowSeconds >= 0 && ttlSeconds > 0)
        requireDirect(output, writable = true)
        if (handle == 0L) return QuicpIoResult(QuicpStatus.CLOSED, 0)
        val packed = nativeIssueReplayToken(handle, nowSeconds, ttlSeconds, output, output.limit())
        return QuicpIoResult(status(packed), value(packed))
    }

    internal fun read(flow: Long, output: ByteBuffer): QuicpIoResult {
        requireDirect(output, writable = true)
        if (handle == 0L) return QuicpIoResult(QuicpStatus.CLOSED, 0)
        val packed = nativeRead(handle, flow, output, output.limit())
        return QuicpIoResult(status(packed), value(packed))
    }

    internal fun write(flow: Long, input: ByteBuffer, length: Int): QuicpIoResult {
        requireDirect(input)
        require(length in 1..input.limit())
        if (handle == 0L) return QuicpIoResult(QuicpStatus.CLOSED, 0)
        val packed = nativeWrite(handle, flow, input, length)
        return QuicpIoResult(status(packed), value(packed))
    }

    internal fun flush(flow: Long) = if (handle == 0L) QuicpStatus.CLOSED else status(nativeFlush(handle, flow))
    internal fun shutdown(flow: Long) = if (handle == 0L) QuicpStatus.CLOSED else status(nativeShutdown(handle, flow))
    internal fun closeFlow(flow: Long) = if (handle == 0L) QuicpStatus.CLOSED else status(nativeCloseFlow(handle, flow))
    internal fun acceptPending(request: Long): Result<QuicpFlow> {
        if (handle == 0L) return Result.failure(QuicpException(QuicpStatus.CLOSED))
        val output = LongArray(1)
        return flow(nativeAcceptPendingFlow(handle, request, output), output, this)
    }
    internal fun rejectPending(request: Long) =
        if (handle == 0L) QuicpStatus.CLOSED else status(nativeRejectPendingFlow(handle, request))

    override fun close() {
        val current = handle
        if (current == 0L) return
        handle = 0
        nativeClose(current)
    }

    private fun requireDirect(buffer: ByteBuffer, writable: Boolean = false) {
        require(buffer.isDirect && buffer.position() == 0)
        if (writable) require(!buffer.isReadOnly)
    }
}

class QuicpPendingFlow internal constructor(
    private val engine: QuicpEngine,
    private var request: Long,
    val host: String,
    val port: Int,
    val initialData: ByteArray,
) {
    fun accept(): Result<QuicpFlow> {
        if (request == 0L) return Result.failure(QuicpException(QuicpStatus.CLOSED))
        val result = engine.acceptPending(request)
        if (result.isSuccess) request = 0
        return result
    }

    fun reject(): QuicpStatus {
        if (request == 0L) return QuicpStatus.CLOSED
        val status = engine.rejectPending(request)
        if (status == QuicpStatus.OK) request = 0
        return status
    }
}

class QuicpFlow internal constructor(private val engine: QuicpEngine, private var handle: Long) : AutoCloseable {
    fun read(output: ByteBuffer) = if (handle == 0L) QuicpIoResult(QuicpStatus.CLOSED, 0) else engine.read(handle, output)
    fun write(input: ByteBuffer, length: Int) = if (handle == 0L) QuicpIoResult(QuicpStatus.CLOSED, 0) else engine.write(handle, input, length)
    fun flush() = if (handle == 0L) QuicpStatus.CLOSED else engine.flush(handle)
    fun shutdown() = if (handle == 0L) QuicpStatus.CLOSED else engine.shutdown(handle)

    override fun close() {
        val current = handle
        if (current == 0L) return
        handle = 0
        engine.closeFlow(current)
    }
}

class QuicpException(val status: QuicpStatus) : Exception("QUICP status $status")
