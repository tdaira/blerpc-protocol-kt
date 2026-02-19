package com.blerpc.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.math.ec.rfc8032.Ed25519

/** Direction bytes for nonce construction. */
const val DIRECTION_C2P: Byte = 0x00
const val DIRECTION_P2C: Byte = 0x01

/** Confirmation plaintexts. */
val CONFIRM_CENTRAL = "BLERPC_CONFIRM_C".toByteArray(Charsets.US_ASCII)
val CONFIRM_PERIPHERAL = "BLERPC_CONFIRM_P".toByteArray(Charsets.US_ASCII)

/** Key exchange step constants. */
const val KEY_EXCHANGE_STEP1: Byte = 0x01
const val KEY_EXCHANGE_STEP2: Byte = 0x02
const val KEY_EXCHANGE_STEP3: Byte = 0x03
const val KEY_EXCHANGE_STEP4: Byte = 0x04

/** X25519 raw key prefix bytes for JCA encoding. */
private val X25519_PKCS8_PREFIX =
    byteArrayOf(
        0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20,
    )
private val X25519_X509_PREFIX =
    byteArrayOf(
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
        0x6E, 0x03, 0x21, 0x00,
    )

object BlerpcCrypto {
    private val secureRandom = SecureRandom()

    data class X25519KeyPair(
        val privateKeyRaw: ByteArray,
        val publicKeyRaw: ByteArray,
    )

    fun generateX25519KeyPair(): X25519KeyPair {
        val kpg = KeyPairGenerator.getInstance("X25519")
        val kp = kpg.generateKeyPair()
        val privRaw = kp.private.encoded.let { it.copyOfRange(X25519_PKCS8_PREFIX.size, it.size) }
        val pubRaw = kp.public.encoded.let { it.copyOfRange(X25519_X509_PREFIX.size, it.size) }
        return X25519KeyPair(privRaw, pubRaw)
    }

    fun x25519SharedSecret(
        privateKeyRaw: ByteArray,
        peerPublicRaw: ByteArray,
    ): ByteArray {
        val kf = KeyFactory.getInstance("X25519")
        val privKey = kf.generatePrivate(PKCS8EncodedKeySpec(X25519_PKCS8_PREFIX + privateKeyRaw))
        val pubKey = kf.generatePublic(X509EncodedKeySpec(X25519_X509_PREFIX + peerPublicRaw))

        val ka = KeyAgreement.getInstance("X25519")
        ka.init(privKey)
        ka.doPhase(pubKey, true)
        return ka.generateSecret()
    }

    fun deriveSessionKey(
        sharedSecret: ByteArray,
        centralPubkey: ByteArray,
        peripheralPubkey: ByteArray,
    ): ByteArray {
        val salt = centralPubkey + peripheralPubkey
        val info = "blerpc-session-key".toByteArray(Charsets.US_ASCII)
        return hkdfSha256(sharedSecret, salt, info, 16)
    }

    data class Ed25519KeyPair(
        val privateKeyRaw: ByteArray,
        val publicKeyRaw: ByteArray,
    )

    fun generateEd25519KeyPair(): Ed25519KeyPair {
        val seed = ByteArray(Ed25519.SECRET_KEY_SIZE)
        secureRandom.nextBytes(seed)
        val pubRaw = ByteArray(Ed25519.PUBLIC_KEY_SIZE)
        Ed25519.generatePublicKey(seed, 0, pubRaw, 0)
        return Ed25519KeyPair(seed, pubRaw)
    }

    fun ed25519Sign(
        privateKeyRaw: ByteArray,
        message: ByteArray,
    ): ByteArray {
        val sig = ByteArray(Ed25519.SIGNATURE_SIZE)
        Ed25519.sign(privateKeyRaw, 0, message, 0, message.size, sig, 0)
        return sig
    }

    fun ed25519Verify(
        publicKeyRaw: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean {
        return try {
            Ed25519.verify(signature, 0, publicKeyRaw, 0, message, 0, message.size)
        } catch (_: Exception) {
            false
        }
    }

    private fun buildNonce(
        counter: Int,
        direction: Byte,
    ): ByteArray {
        val nonce = ByteArray(12)
        nonce[0] = (counter and 0xFF).toByte()
        nonce[1] = ((counter shr 8) and 0xFF).toByte()
        nonce[2] = ((counter shr 16) and 0xFF).toByte()
        nonce[3] = ((counter shr 24) and 0xFF).toByte()
        nonce[4] = direction
        return nonce
    }

    fun encryptCommand(
        sessionKey: ByteArray,
        counter: Int,
        direction: Byte,
        plaintext: ByteArray,
    ): ByteArray {
        val nonce = buildNonce(counter, direction)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(sessionKey, "AES"),
            GCMParameterSpec(128, nonce),
        )
        val ctAndTag = cipher.doFinal(plaintext)

        val out = ByteBuffer.allocate(4 + ctAndTag.size).order(ByteOrder.LITTLE_ENDIAN)
        out.putInt(counter)
        out.put(ctAndTag)
        return out.array()
    }

    data class DecryptedCommand(val counter: Int, val plaintext: ByteArray)

    fun decryptCommand(
        sessionKey: ByteArray,
        direction: Byte,
        data: ByteArray,
    ): DecryptedCommand {
        require(data.size >= 20) { "Encrypted payload too short: ${data.size}" }

        val buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        val counter = buf.int
        val ctAndTag = data.copyOfRange(4, data.size)

        val nonce = buildNonce(counter, direction)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(sessionKey, "AES"),
            GCMParameterSpec(128, nonce),
        )
        val plaintext = cipher.doFinal(ctAndTag)
        return DecryptedCommand(counter, plaintext)
    }

    fun encryptConfirmation(
        sessionKey: ByteArray,
        message: ByteArray,
    ): ByteArray {
        val nonce = ByteArray(12)
        secureRandom.nextBytes(nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(sessionKey, "AES"),
            GCMParameterSpec(128, nonce),
        )
        val ctAndTag = cipher.doFinal(message)
        return nonce + ctAndTag
    }

    fun decryptConfirmation(
        sessionKey: ByteArray,
        data: ByteArray,
    ): ByteArray {
        require(data.size >= 44) { "Confirmation too short: ${data.size}" }
        val nonce = data.copyOfRange(0, 12)
        val ctAndTag = data.copyOfRange(12, data.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(sessionKey, "AES"),
            GCMParameterSpec(128, nonce),
        )
        return cipher.doFinal(ctAndTag)
    }

    fun buildStep1Payload(centralX25519Pubkey: ByteArray): ByteArray = byteArrayOf(KEY_EXCHANGE_STEP1) + centralX25519Pubkey

    fun parseStep1Payload(data: ByteArray): ByteArray {
        require(data.size >= 33 && data[0] == KEY_EXCHANGE_STEP1) { "Invalid step 1 payload" }
        return data.copyOfRange(1, 33)
    }

    fun buildStep2Payload(
        peripheralX25519Pubkey: ByteArray,
        ed25519Signature: ByteArray,
        peripheralEd25519Pubkey: ByteArray,
    ): ByteArray =
        byteArrayOf(KEY_EXCHANGE_STEP2) +
            peripheralX25519Pubkey +
            ed25519Signature +
            peripheralEd25519Pubkey

    fun parseStep2Payload(data: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        require(data.size >= 129 && data[0] == KEY_EXCHANGE_STEP2) { "Invalid step 2 payload" }
        return Triple(
            data.copyOfRange(1, 33),
            data.copyOfRange(33, 97),
            data.copyOfRange(97, 129),
        )
    }

    fun buildStep3Payload(confirmationEncrypted: ByteArray): ByteArray = byteArrayOf(KEY_EXCHANGE_STEP3) + confirmationEncrypted

    fun parseStep3Payload(data: ByteArray): ByteArray {
        require(data.size >= 45 && data[0] == KEY_EXCHANGE_STEP3) { "Invalid step 3 payload" }
        return data.copyOfRange(1, 45)
    }

    fun buildStep4Payload(confirmationEncrypted: ByteArray): ByteArray = byteArrayOf(KEY_EXCHANGE_STEP4) + confirmationEncrypted

    fun parseStep4Payload(data: ByteArray): ByteArray {
        require(data.size >= 45 && data[0] == KEY_EXCHANGE_STEP4) { "Invalid step 4 payload" }
        return data.copyOfRange(1, 45)
    }

    /** HKDF-SHA256 implementation. */
    private fun hkdfSha256(
        ikm: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        length: Int,
    ): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")

        // Extract
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        // Expand
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val hashLen = 32
        val n = (length + hashLen - 1) / hashLen
        var t = ByteArray(0)
        val okm = ByteArray(n * hashLen)
        for (i in 1..n) {
            mac.update(t)
            mac.update(info)
            mac.update(i.toByte())
            t = mac.doFinal()
            System.arraycopy(t, 0, okm, (i - 1) * hashLen, hashLen)
        }
        return okm.copyOfRange(0, length)
    }
}

class BlerpcCryptoSession(
    sessionKey: ByteArray,
    isCentral: Boolean,
) {
    private val sessionKey = sessionKey.copyOf()
    private var txCounter = 0
    private var rxCounter = 0
    private var rxFirstDone = false
    private val txDirection: Byte = if (isCentral) DIRECTION_C2P else DIRECTION_P2C
    private val rxDirection: Byte = if (isCentral) DIRECTION_P2C else DIRECTION_C2P

    fun encrypt(plaintext: ByteArray): ByteArray {
        val result = BlerpcCrypto.encryptCommand(sessionKey, txCounter, txDirection, plaintext)
        txCounter++
        return result
    }

    fun decrypt(data: ByteArray): ByteArray {
        val (counter, plaintext) = BlerpcCrypto.decryptCommand(sessionKey, rxDirection, data)
        if (rxFirstDone) {
            require(counter > rxCounter) { "Replay detected" }
        }
        rxCounter = counter
        rxFirstDone = true
        return plaintext
    }
}

class CentralKeyExchange {
    private var x25519PrivKey: ByteArray? = null
    private var x25519PubKey: ByteArray? = null
    private var sessionKey: ByteArray? = null

    fun start(): ByteArray {
        val keyPair = BlerpcCrypto.generateX25519KeyPair()
        x25519PrivKey = keyPair.privateKeyRaw
        x25519PubKey = keyPair.publicKeyRaw
        return BlerpcCrypto.buildStep1Payload(x25519PubKey!!)
    }

    fun processStep2(
        step2Payload: ByteArray,
        verifyKeyCb: ((ByteArray) -> Boolean)? = null,
    ): ByteArray {
        val (periphX25519Pub, signature, periphEd25519Pub) =
            BlerpcCrypto.parseStep2Payload(step2Payload)

        val signMsg = x25519PubKey!! + periphX25519Pub
        require(BlerpcCrypto.ed25519Verify(periphEd25519Pub, signMsg, signature)) {
            "Ed25519 signature verification failed"
        }

        if (verifyKeyCb != null) {
            require(verifyKeyCb(periphEd25519Pub)) { "Peripheral key rejected by verify callback" }
        }

        val sharedSecret = BlerpcCrypto.x25519SharedSecret(x25519PrivKey!!, periphX25519Pub)
        sessionKey = BlerpcCrypto.deriveSessionKey(sharedSecret, x25519PubKey!!, periphX25519Pub)

        val encryptedConfirm = BlerpcCrypto.encryptConfirmation(sessionKey!!, CONFIRM_CENTRAL)
        return BlerpcCrypto.buildStep3Payload(encryptedConfirm)
    }

    fun finish(step4Payload: ByteArray): BlerpcCryptoSession {
        val encryptedPeriph = BlerpcCrypto.parseStep4Payload(step4Payload)
        val plaintext = BlerpcCrypto.decryptConfirmation(sessionKey!!, encryptedPeriph)
        require(plaintext.contentEquals(CONFIRM_PERIPHERAL)) { "Peripheral confirmation mismatch" }
        return BlerpcCryptoSession(sessionKey!!, isCentral = true)
    }
}

class PeripheralKeyExchange(
    private val x25519PrivKey: ByteArray,
    private val x25519PubKey: ByteArray,
    private val ed25519PrivKey: ByteArray,
    private val ed25519PubKey: ByteArray,
) {
    private var sessionKey: ByteArray? = null

    fun processStep1(step1Payload: ByteArray): ByteArray {
        val centralX25519Pubkey = BlerpcCrypto.parseStep1Payload(step1Payload)

        val signMsg = centralX25519Pubkey + x25519PubKey
        val signature = BlerpcCrypto.ed25519Sign(ed25519PrivKey, signMsg)

        val sharedSecret = BlerpcCrypto.x25519SharedSecret(x25519PrivKey, centralX25519Pubkey)
        sessionKey = BlerpcCrypto.deriveSessionKey(sharedSecret, centralX25519Pubkey, x25519PubKey)

        return BlerpcCrypto.buildStep2Payload(x25519PubKey, signature, ed25519PubKey)
    }

    fun processStep3(step3Payload: ByteArray): Pair<ByteArray, BlerpcCryptoSession> {
        val encrypted = BlerpcCrypto.parseStep3Payload(step3Payload)
        val plaintext = BlerpcCrypto.decryptConfirmation(sessionKey!!, encrypted)
        require(plaintext.contentEquals(CONFIRM_CENTRAL)) { "Central confirmation mismatch" }

        val encryptedConfirm = BlerpcCrypto.encryptConfirmation(sessionKey!!, CONFIRM_PERIPHERAL)
        val step4 = BlerpcCrypto.buildStep4Payload(encryptedConfirm)
        val session = BlerpcCryptoSession(sessionKey!!, isCentral = false)

        return Pair(step4, session)
    }

    fun handleStep(payload: ByteArray): Pair<ByteArray, BlerpcCryptoSession?> {
        require(payload.isNotEmpty()) { "Empty key exchange payload" }
        return when (payload[0]) {
            KEY_EXCHANGE_STEP1 -> Pair(processStep1(payload), null)
            KEY_EXCHANGE_STEP3 -> {
                val (step4, session) = processStep3(payload)
                Pair(step4, session)
            }
            else -> throw IllegalArgumentException(
                "Invalid key exchange step: 0x${payload[0].toInt().and(0xFF).toString(16).padStart(2, '0')}"
            )
        }
    }
}

suspend fun centralPerformKeyExchange(
    send: suspend (ByteArray) -> Unit,
    receive: suspend () -> ByteArray,
    verifyKeyCb: ((ByteArray) -> Boolean)? = null,
): BlerpcCryptoSession {
    val kx = CentralKeyExchange()

    // Step 1: Send central's ephemeral public key
    val step1 = kx.start()
    send(step1)

    // Step 2: Receive peripheral's response
    val step2 = receive()

    // Step 2 -> Step 3: Verify and produce confirmation
    val step3 = kx.processStep2(step2, verifyKeyCb)
    send(step3)

    // Step 4: Receive peripheral's confirmation
    val step4 = receive()

    return kx.finish(step4)
}
