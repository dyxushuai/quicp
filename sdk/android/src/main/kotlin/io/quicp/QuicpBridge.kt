package io.quicp

import java.nio.ByteBuffer
import java.nio.ByteOrder

@JvmInline
value class QuicpBatchResult internal constructor(private val packed: Long) {
    val status: Int get() = (packed and 0xff).toInt()
    val inputsConsumed: Int get() = ((packed ushr 8) and 0xff).toInt()
    val outputsWritten: Int get() = ((packed ushr 16) and 0xff).toInt()
}

/** Single-owner bridge. Calls on one instance must be serialized by the owner. */
class QuicpBridge private constructor(private var handle: Long) : AutoCloseable {
    companion object {
        const val MAX_BATCH_PACKETS = 64
        const val INPUT_DESCRIPTOR_BYTES = 8
        const val OUTPUT_DESCRIPTOR_BYTES = 12
        const val STATUS_OK = 0
        const val STATUS_WOULD_BLOCK = 1
        const val STATUS_BUFFER_TOO_SMALL = 2
        const val STATUS_INVALID_ARGUMENT = 3
        const val STATUS_NOT_READY = 4
        const val STATUS_CLOSED = 5
        const val STATUS_PANIC = 6

        init {
            System.loadLibrary("quicp_jni")
        }

        @JvmStatic
        fun create(): QuicpBridge {
            val handle = nativeCreate()
            check(handle != 0L) { "quicp bridge creation failed" }
            return QuicpBridge(handle)
        }

        @JvmStatic private external fun nativeCreate(): Long
        @JvmStatic private external fun nativeProcessBatch(
            handle: Long,
            inputData: ByteBuffer?,
            inputDescriptors: ByteBuffer?,
            inputCount: Int,
            outputData: ByteBuffer?,
            outputDescriptors: ByteBuffer?,
            outputCount: Int,
        ): Long
        @JvmStatic private external fun nativeClose(handle: Long): Int
    }

    fun processBatch(
        inputData: ByteBuffer?,
        inputDescriptors: ByteBuffer?,
        inputCount: Int,
        outputData: ByteBuffer?,
        outputDescriptors: ByteBuffer?,
        outputCount: Int,
    ): QuicpBatchResult {
        require(inputCount in 0..MAX_BATCH_PACKETS)
        require(outputCount in 0..MAX_BATCH_PACKETS)
        requireDirectNative(inputData, inputDescriptors, inputCount * INPUT_DESCRIPTOR_BYTES)
        requireDirectNative(outputData, outputDescriptors, outputCount * OUTPUT_DESCRIPTOR_BYTES)
        if (outputCount != 0) {
            require(outputData?.isReadOnly == false)
            require(outputDescriptors?.isReadOnly == false)
        }
        if (handle == 0L) return QuicpBatchResult(STATUS_CLOSED.toLong())
        return QuicpBatchResult(
            nativeProcessBatch(
                handle,
                inputData,
                inputDescriptors,
                inputCount,
                outputData,
                outputDescriptors,
                outputCount,
            )
        )
    }

    override fun close() {
        val current = handle
        if (current == 0L) return
        handle = 0L
        nativeClose(current)
    }

    private fun requireDirectNative(data: ByteBuffer?, descriptors: ByteBuffer?, required: Int) {
        if (required == 0) return
        requireNotNull(data).also {
            require(it.isDirect)
            require(it.position() == 0)
        }
        requireNotNull(descriptors).also {
            require(it.isDirect)
            require(it.order() == ByteOrder.nativeOrder())
            require(it.position() == 0)
            require(it.capacity() >= required)
        }
    }
}
