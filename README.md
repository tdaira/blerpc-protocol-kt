# blerpc-protocol-kt

BLE RPC protocol library for Kotlin/JVM.

Part of the [bleRPC](https://blerpc.net) project.

## Overview

Kotlin implementation of the bleRPC binary protocol:

- Container fragmentation and reassembly with MTU-aware splitting
- Command packet encoding/decoding with protobuf payload support
- Control messages (timeout, stream end, capabilities, error)

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
    implementation("com.blerpc:blerpc-protocol-kt:0.1.0")
}
```

## Requirements

- Java 17+
- Kotlin 1.9+

## License

[LGPL-3.0](LICENSE)
