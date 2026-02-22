package com.blerpc.protocol

/** Container type encoded in bits 7-6 of the flags byte. */
enum class ContainerType(val value: Int) {
    FIRST(0x00),
    SUBSEQUENT(0x01),
    CONTROL(0x03),
    ;

    companion object {
        fun fromValue(v: Int): ContainerType = entries.first { it.value == v }
    }
}

/** Control command encoded in bits 5-2 of the flags byte. */
enum class ControlCmd(val value: Int) {
    NONE(0x00),
    TIMEOUT(0x01),
    STREAM_END_C2P(0x02),
    STREAM_END_P2C(0x03),
    CAPABILITIES(0x04),
    ERROR(0x05),
    KEY_EXCHANGE(0x06),
    ;

    companion object {
        fun fromValue(v: Int): ControlCmd = entries.first { it.value == v }
    }
}

const val FIRST_HEADER_SIZE = 6
const val SUBSEQUENT_HEADER_SIZE = 4
const val CONTROL_HEADER_SIZE = 4
const val ATT_OVERHEAD = 3
const val BLERPC_ERROR_RESPONSE_TOO_LARGE: Byte = 0x01
const val BLERPC_ERROR_BUSY: Byte = 0x02
const val CAPABILITY_FLAG_ENCRYPTION_SUPPORTED: Int = 0x0001
