package com.blerpc.protocol

/**
 * Reassembles fragmented containers back into complete payloads.
 *
 * Feed incoming containers via [feed]; when all fragments of a transaction
 * have arrived, the complete payload is returned.
 */
class ContainerAssembler {
    private val transactions = mutableMapOf<Int, AssemblyState>()

    /**
     * Feed a received container into the assembler.
     *
     * @return The complete reassembled payload when all fragments have arrived, or null.
     */
    fun feed(container: Container): ByteArray? {
        if (container.containerType == ContainerType.CONTROL) {
            return null
        }

        val tid = container.transactionId

        if (container.containerType == ContainerType.FIRST) {
            transactions[tid] =
                AssemblyState(
                    totalLength = container.totalLength,
                    expectedSeq = 1,
                    fragments = mutableListOf(container.payload),
                    receivedLength = container.payload.size,
                )
        } else if (tid in transactions) {
            val state = transactions[tid]!!
            if (container.sequenceNumber != state.expectedSeq) {
                transactions.remove(tid)
                return null
            }
            state.fragments.add(container.payload)
            state.receivedLength += container.payload.size
            state.expectedSeq++
        } else {
            return null
        }

        val state = transactions[tid]!!
        if (state.receivedLength >= state.totalLength) {
            val allBytes = ByteArray(state.fragments.sumOf { it.size })
            var offset = 0
            for (frag in state.fragments) {
                frag.copyInto(allBytes, offset)
                offset += frag.size
            }
            transactions.remove(tid)
            return allBytes.copyOfRange(0, state.totalLength)
        }

        return null
    }

    /** Clear all in-progress assembly state. */
    fun reset() {
        transactions.clear()
    }

    private data class AssemblyState(
        val totalLength: Int,
        var expectedSeq: Int,
        val fragments: MutableList<ByteArray>,
        var receivedLength: Int,
    )
}
