# blerpc-protocol-kt

BLE RPC protocol library for Kotlin/JVM.

Part of the [bleRPC](https://blerpc.net) project.

## Overview

Kotlin implementation of the bleRPC binary protocol:

- Container fragmentation and reassembly with MTU-aware splitting
- Command packet encoding/decoding with protobuf payload support
- Control messages (timeout, stream end, capabilities, error)
- **Encryption layer** — E2E encryption with X25519 key exchange, Ed25519 signatures, and AES-128-GCM

## Installation

Add the GitHub Packages repository and dependency to your `build.gradle.kts`:

```kotlin
repositories {
    maven {
        url = uri("https://maven.pkg.github.com/tdaira/blerpc-protocol-kt")
        credentials {
            username = project.findProperty("gpr.user") as String?
            password = project.findProperty("gpr.key") as String?
        }
    }
}

dependencies {
    implementation("com.blerpc:blerpc-protocol-kt:0.5.0")
}
```

## Encryption

The library provides E2E encryption using a 4-step key exchange protocol (X25519 ECDH + Ed25519 signatures) and AES-128-GCM session encryption.

```kotlin
import com.blerpc.protocol.centralPerformKeyExchange
import com.blerpc.protocol.BlerpcCryptoSession

// Perform key exchange (central side)
val session = centralPerformKeyExchange(send = ::bleSend, receive = ::bleReceive)

// Encrypt outgoing commands
val ciphertext = session.encrypt(plaintext)

// Decrypt incoming commands
val plaintext = session.decrypt(ciphertext)
```

## Requirements

- Java 17+
- Kotlin 1.9+

## License

[LGPL-3.0](LICENSE) with [Static Linking Exception](LICENSING_EXCEPTION)
