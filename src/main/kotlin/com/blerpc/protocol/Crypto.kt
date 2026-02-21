package com.blerpc.protocol

import org.bouncycastle.math.ec.rfc8032.Ed25519
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

/**
 * Cryptographic operations for bleRPC E2E encryption.
 *
 * Provides X25519 key agreement, Ed25519 signing/verification,
 * AES-128-GCM encryption, and HKDF-SHA256 key derivation.
 */
object BlerpcCrypto {
    private val secureRandom = SecureRandom()

    data class X25519KeyPair(
        val privateKeyRaw: ByteArray,
        val publicKeyRaw: ByteArray,
    )

    /** Generate an X25519 key pair for ECDH key agreement. */
    fun generateX25519KeyPair(): X25519KeyPair {
        val kpg = KeyPairGenerator.getInstance("X25519")
        val kp = kpg.generateKeyPair()
        val privRaw = kp.private.encoded.let { it.copyOfRange(X25519_PKCS8_PREFIX.size, it.size) }
        val pubRaw = kp.public.encoded.let { it.copyOfRange(X25519_X509_PREFIX.size, it.size) }
        return X25519KeyPair(privRaw, pubRaw)
    }

    /** Compute X25519 shared secret (32 bytes). */
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

    /**
     * Derive 16-byte AES-128 session key using HKDF-SHA256.
     *
     * Salt is `centralPubkey || peripheralPubkey`, info is `"blerpc-session-key"`.
     */
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

    /** Generate an Ed25519 key pair for digital signatures. */
    fun generateEd25519KeyPair(): Ed25519KeyPair {
        val seed = ByteArray(Ed25519.SECRET_KEY_SIZE)
        secureRandom.nextBytes(seed)
        return ed25519KeyPairFromSeed(seed)
    }

    /** Create an Ed25519 key pair from a raw 32-byte seed (private key). */
    fun ed25519KeyPairFromSeed(seed: ByteArray): Ed25519KeyPair {
        require(seed.size == Ed25519.SECRET_KEY_SIZE) {
            "Ed25519 seed must be ${Ed25519.SECRET_KEY_SIZE} bytes, got ${seed.size}"
        }
        val pubRaw = ByteArray(Ed25519.PUBLIC_KEY_SIZE)
        Ed25519.generatePublicKey(seed, 0, pubRaw, 0)
        return Ed25519KeyPair(seed.copyOf(), pubRaw)
    }

    /** Sign [message] with Ed25519, returning a 64-byte signature. */
    fun ed25519Sign(
        privateKeyRaw: ByteArray,
        message: ByteArray,
    ): ByteArray {
        val sig = ByteArray(Ed25519.SIGNATURE_SIZE)
        Ed25519.sign(privateKeyRaw, 0, message, 0, message.size, sig, 0)
        return sig
    }

    /** Verify an Ed25519 [signature] over [message]. Returns true if valid. */
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

    /**
     * Encrypt a command payload with AES-128-GCM.
     *
     * Output format: `[counter:4B LE][ciphertext:NB][tag:16B]`.
     */
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

    /** Decrypt a command payload with AES-128-GCM. */
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

    /** Encrypt a confirmation message for key exchange step 3/4. */
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

    /** Decrypt a confirmation message from key exchange step 3/4. */
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

/**
 * Stateful encryption/decryption session established after key exchange.
 *
 * Tracks send/receive counters and provides replay protection.
 *
 * @param sessionKey The 16-byte AES-128 session key.
 * @param isCentral True if this is the central side of the connection.
 */
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

    /** Encrypt [plaintext] and advance the send counter. */
    fun encrypt(plaintext: ByteArray): ByteArray {
        val result = BlerpcCrypto.encryptCommand(sessionKey, txCounter, txDirection, plaintext)
        txCounter++
        return result
    }

    /** Decrypt [data] with replay protection. Throws on replay or auth failure. */
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

/**
 * Central-side key exchange state machine.
 *
 * Usage: [start] → send step 1 → receive step 2 → [processStep2] →
 * send step 3 → receive step 4 → [finish] → [BlerpcCryptoSession].
 */
class CentralKeyExchange {
    private var x25519PrivKey: ByteArray? = null
    private var x25519PubKey: ByteArray? = null
    private var sessionKey: ByteArray? = null

    /** Generate an ephemeral X25519 key pair and return the step 1 payload. */
    fun start(): ByteArray {
        val keyPair = BlerpcCrypto.generateX25519KeyPair()
        x25519PrivKey = keyPair.privateKeyRaw
        x25519PubKey = keyPair.publicKeyRaw
        return BlerpcCrypto.buildStep1Payload(x25519PubKey!!)
    }

    /**
     * Process step 2 from peripheral: verify signature, derive session key,
     * and produce step 3 payload with encrypted confirmation.
     *
     * @param verifyKeyCb Optional callback to verify the peripheral's Ed25519 public key (TOFU).
     */
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

    /** Process step 4 from peripheral, verify confirmation, and return the session. */
    fun finish(step4Payload: ByteArray): BlerpcCryptoSession {
        val encryptedPeriph = BlerpcCrypto.parseStep4Payload(step4Payload)
        val plaintext = BlerpcCrypto.decryptConfirmation(sessionKey!!, encryptedPeriph)
        require(plaintext.contentEquals(CONFIRM_PERIPHERAL)) { "Peripheral confirmation mismatch" }
        return BlerpcCryptoSession(sessionKey!!, isCentral = true)
    }
}

/**
 * Peripheral-side key exchange state machine.
 *
 * Use [handleStep] for automatic step dispatching, or call
 * [processStep1] and [processStep3] directly.
 */
class PeripheralKeyExchange(
    private val ed25519Seed: ByteArray,
) {
    private val ed25519PubKey: ByteArray
    private var sessionKey: ByteArray? = null

    init {
        val kp = BlerpcCrypto.ed25519KeyPairFromSeed(ed25519Seed)
        ed25519PubKey = kp.publicKeyRaw
    }

    /**
     * Process step 1 from central: generate ephemeral X25519 keypair,
     * sign, derive session key, and produce step 2 payload.
     */
    fun processStep1(step1Payload: ByteArray): ByteArray {
        val centralX25519Pubkey = BlerpcCrypto.parseStep1Payload(step1Payload)

        // Generate ephemeral X25519 keypair (forward secrecy)
        val x25519Kp = BlerpcCrypto.generateX25519KeyPair()

        val signMsg = centralX25519Pubkey + x25519Kp.publicKeyRaw
        val signature = BlerpcCrypto.ed25519Sign(ed25519Seed, signMsg)

        val sharedSecret = BlerpcCrypto.x25519SharedSecret(x25519Kp.privateKeyRaw, centralX25519Pubkey)
        sessionKey = BlerpcCrypto.deriveSessionKey(sharedSecret, centralX25519Pubkey, x25519Kp.publicKeyRaw)

        return BlerpcCrypto.buildStep2Payload(x25519Kp.publicKeyRaw, signature, ed25519PubKey)
    }

    /** Process step 3 from central: verify confirmation, produce step 4 + session. */
    fun processStep3(step3Payload: ByteArray): Pair<ByteArray, BlerpcCryptoSession> {
        val encrypted = BlerpcCrypto.parseStep3Payload(step3Payload)
        val plaintext = BlerpcCrypto.decryptConfirmation(sessionKey!!, encrypted)
        require(plaintext.contentEquals(CONFIRM_CENTRAL)) { "Central confirmation mismatch" }

        val encryptedConfirm = BlerpcCrypto.encryptConfirmation(sessionKey!!, CONFIRM_PERIPHERAL)
        val step4 = BlerpcCrypto.buildStep4Payload(encryptedConfirm)
        val session = BlerpcCryptoSession(sessionKey!!, isCentral = false)

        return Pair(step4, session)
    }

    /**
     * Handle a single key exchange step, dispatching to [processStep1] or [processStep3].
     *
     * @return Pair of (response payload, session or null if not yet established).
     */
    fun handleStep(payload: ByteArray): Pair<ByteArray, BlerpcCryptoSession?> {
        require(payload.isNotEmpty()) { "Empty key exchange payload" }
        return when (payload[0]) {
            KEY_EXCHANGE_STEP1 -> Pair(processStep1(payload), null)
            KEY_EXCHANGE_STEP3 -> {
                val (step4, session) = processStep3(payload)
                Pair(step4, session)
            }
            else -> throw IllegalArgumentException(
                "Invalid key exchange step: 0x${payload[0].toInt().and(0xFF).toString(16).padStart(2, '0')}",
            )
        }
    }
}

/**
 * Perform the complete 4-step central key exchange using send/receive callbacks.
 *
 * @param send Callback to send a key exchange payload over BLE.
 * @param receive Callback to receive a key exchange payload from BLE.
 * @param verifyKeyCb Optional callback to verify the peripheral's Ed25519 public key.
 * @return An established [BlerpcCryptoSession] ready for encryption/decryption.
 */
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
