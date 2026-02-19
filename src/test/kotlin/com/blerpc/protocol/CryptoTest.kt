package com.blerpc.protocol

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class PeripheralHandleStepTest {
    private fun makePeripheralKx(): PeripheralKeyExchange {
        val x = BlerpcCrypto.generateX25519KeyPair()
        val ed = BlerpcCrypto.generateEd25519KeyPair()
        return PeripheralKeyExchange(x.privateKeyRaw, x.publicKeyRaw, ed.privateKeyRaw, ed.publicKeyRaw)
    }

    @Test
    fun testHandleStep1() {
        val kx = makePeripheralKx()
        val centralKp = BlerpcCrypto.generateX25519KeyPair()
        val step1 = BlerpcCrypto.buildStep1Payload(centralKp.publicKeyRaw)

        val (response, session) = kx.handleStep(step1)
        assertEquals(KEY_EXCHANGE_STEP2, response[0])
        assertEquals(129, response.size)
        assertNull(session)
    }

    @Test
    fun testHandleStep3() {
        val kx = makePeripheralKx()
        val centralKx = CentralKeyExchange()

        val step1 = centralKx.start()
        val (step2, session1) = kx.handleStep(step1)
        assertNull(session1)

        val step3 = centralKx.processStep2(step2)
        val (step4, session2) = kx.handleStep(step3)
        assertEquals(KEY_EXCHANGE_STEP4, step4[0])
        assertEquals(45, step4.size)
        assertNotNull(session2)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testHandleStepInvalid() {
        val kx = makePeripheralKx()
        val payload = byteArrayOf(KEY_EXCHANGE_STEP2) + ByteArray(128)
        kx.handleStep(payload)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testHandleStepEmpty() {
        val kx = makePeripheralKx()
        kx.handleStep(byteArrayOf())
    }
}

class CounterZeroReplayTest {
    @Test(expected = IllegalArgumentException::class)
    fun testCounterZeroReplayAttack() {
        val x = BlerpcCrypto.generateX25519KeyPair()
        val ed = BlerpcCrypto.generateEd25519KeyPair()
        val periphKx = PeripheralKeyExchange(x.privateKeyRaw, x.publicKeyRaw, ed.privateKeyRaw, ed.publicKeyRaw)

        val centralKx = CentralKeyExchange()
        val step1 = centralKx.start()
        val step2 = periphKx.processStep1(step1)
        val step3 = centralKx.processStep2(step2)
        val (step4, periphSession) = periphKx.processStep3(step3)
        val centralSession = centralKx.finish(step4)

        // Encrypt a message (counter=0)
        val enc0 = centralSession.encrypt("msg0".toByteArray())
        // First decrypt succeeds
        periphSession.decrypt(enc0)
        // Replay of counter-0 must fail
        periphSession.decrypt(enc0)
    }
}

class CentralPerformKeyExchangeTest {
    @Test
    fun testFullHandshake() = runBlocking {
        val x = BlerpcCrypto.generateX25519KeyPair()
        val ed = BlerpcCrypto.generateEd25519KeyPair()
        val periphKx = PeripheralKeyExchange(x.privateKeyRaw, x.publicKeyRaw, ed.privateKeyRaw, ed.publicKeyRaw)

        val payloads = mutableListOf<ByteArray>()
        var periphSession: BlerpcCryptoSession? = null

        val session = centralPerformKeyExchange(
            send = { payload ->
                val (response, sess) = periphKx.handleStep(payload)
                if (sess != null) periphSession = sess
                payloads.add(response)
            },
            receive = { payloads.removeFirst() },
        )

        assertNotNull(session)
        assertNotNull(periphSession)

        // Verify sessions work by encrypting/decrypting
        val encrypted = session.encrypt("test".toByteArray())
        val decrypted = periphSession!!.decrypt(encrypted)
        assertArrayEquals("test".toByteArray(), decrypted)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testVerifyCbReject(): Unit = runBlocking {
        val x = BlerpcCrypto.generateX25519KeyPair()
        val ed = BlerpcCrypto.generateEd25519KeyPair()
        val periphKx = PeripheralKeyExchange(x.privateKeyRaw, x.publicKeyRaw, ed.privateKeyRaw, ed.publicKeyRaw)

        val payloads = mutableListOf<ByteArray>()

        centralPerformKeyExchange(
            send = { payload ->
                val (response, _) = periphKx.handleStep(payload)
                payloads.add(response)
            },
            receive = { payloads.removeFirst() },
            verifyKeyCb = { false },
        )
    }

    @Test
    fun testVerifyCbAccept() = runBlocking {
        val x = BlerpcCrypto.generateX25519KeyPair()
        val ed = BlerpcCrypto.generateEd25519KeyPair()
        val periphKx = PeripheralKeyExchange(x.privateKeyRaw, x.publicKeyRaw, ed.privateKeyRaw, ed.publicKeyRaw)

        val payloads = mutableListOf<ByteArray>()
        val seenKeys = mutableListOf<ByteArray>()

        val session = centralPerformKeyExchange(
            send = { payload ->
                val (response, _) = periphKx.handleStep(payload)
                payloads.add(response)
            },
            receive = { payloads.removeFirst() },
            verifyKeyCb = { key ->
                seenKeys.add(key)
                true
            },
        )

        assertNotNull(session)
        assertEquals(1, seenKeys.size)
        assertArrayEquals(ed.publicKeyRaw, seenKeys[0])
    }
}
