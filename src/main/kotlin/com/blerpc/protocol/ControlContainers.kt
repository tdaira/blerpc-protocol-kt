package com.blerpc.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

fun makeTimeoutRequest(
    transactionId: Int,
    sequenceNumber: Int = 0,
): Container =
    Container(
        transactionId = transactionId,
        sequenceNumber = sequenceNumber,
        containerType = ContainerType.CONTROL,
        controlCmd = ControlCmd.TIMEOUT,
        payload = ByteArray(0),
    )

fun makeTimeoutResponse(
    transactionId: Int,
    timeoutMs: Int,
    sequenceNumber: Int = 0,
): Container {
    val payload = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(timeoutMs.toShort()).array()
    return Container(
        transactionId = transactionId,
        sequenceNumber = sequenceNumber,
        containerType = ContainerType.CONTROL,
        controlCmd = ControlCmd.TIMEOUT,
        payload = payload,
    )
}

fun makeStreamEndC2P(
    transactionId: Int,
    sequenceNumber: Int = 0,
): Container =
    Container(
        transactionId = transactionId,
        sequenceNumber = sequenceNumber,
        containerType = ContainerType.CONTROL,
        controlCmd = ControlCmd.STREAM_END_C2P,
        payload = ByteArray(0),
    )

fun makeStreamEndP2C(
    transactionId: Int,
    sequenceNumber: Int = 0,
): Container =
    Container(
        transactionId = transactionId,
        sequenceNumber = sequenceNumber,
        containerType = ContainerType.CONTROL,
        controlCmd = ControlCmd.STREAM_END_P2C,
        payload = ByteArray(0),
    )

fun makeCapabilitiesRequest(
    transactionId: Int,
    maxRequestPayloadSize: Int = 0,
    maxResponsePayloadSize: Int = 0,
    flags: Int = 0,
    sequenceNumber: Int = 0,
): Container {
    val payload =
        ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(maxRequestPayloadSize.toShort())
            .putShort(maxResponsePayloadSize.toShort())
            .putShort(flags.toShort())
            .array()
    return Container(
        transactionId = transactionId,
        sequenceNumber = sequenceNumber,
        containerType = ContainerType.CONTROL,
        controlCmd = ControlCmd.CAPABILITIES,
        payload = payload,
    )
}

fun makeCapabilitiesResponse(
    transactionId: Int,
    maxRequestPayloadSize: Int,
    maxResponsePayloadSize: Int,
    flags: Int = 0,
    sequenceNumber: Int = 0,
): Container {
    val payload =
        ByteBuffer.allocate(6).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(maxRequestPayloadSize.toShort())
            .putShort(maxResponsePayloadSize.toShort())
            .putShort(flags.toShort())
            .array()
    return Container(
        transactionId = transactionId,
        sequenceNumber = sequenceNumber,
        containerType = ContainerType.CONTROL,
        controlCmd = ControlCmd.CAPABILITIES,
        payload = payload,
    )
}

fun makeErrorResponse(
    transactionId: Int,
    errorCode: Int,
    sequenceNumber: Int = 0,
): Container =
    Container(
        transactionId = transactionId,
        sequenceNumber = sequenceNumber,
        containerType = ContainerType.CONTROL,
        controlCmd = ControlCmd.ERROR,
        payload = byteArrayOf(errorCode.toByte()),
    )

fun makeKeyExchange(
    transactionId: Int,
    payload: ByteArray,
    sequenceNumber: Int = 0,
): Container =
    Container(
        transactionId = transactionId,
        sequenceNumber = sequenceNumber,
        containerType = ContainerType.CONTROL,
        controlCmd = ControlCmd.KEY_EXCHANGE,
        payload = payload,
    )
