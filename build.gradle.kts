plugins {
    kotlin("jvm") version "2.4.21"
    kotlin("plugin.serialization") version "2.4.21"
    id("com.gradleup.shadow") version "9.6.1"
}

group = "io.bitbytelab"
version = "2.1.0"

// Build JDK: gradle/gradle-daemon-jvm.properties pins the Gradle daemon to JDK 25. The
// toolchain compiles and tests on JDK 25 and emits Java 25 bytecode, so the jar needs a Burp
// running Java 25 or newer. Turbo relies on virtual threads that do not pin their carrier
// inside `synchronized` (JEP 491, JDK 24+).
kotlin {
    jvmToolchain(25)
}

repositories {
    mavenCentral()
}

val ktorVersion = "3.6.1"
val montoyaVersion = "2026.7"

dependencies {
    // Burp Suite Montoya API — provided by Burp at runtime, never bundled
    compileOnly("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")

    // --- MCP server (Kotlin SDK on Ktor CIO) ---
    implementation("io.modelcontextprotocol:kotlin-sdk-server:0.16.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.13.0")
    // kotlin-sdk-server 0.16.0 was built against Ktor 3.5.2 / serialization 1.11.0; newer minor
    // releases are binary compatible. Re-check when bumping the SDK.
    implementation("io.ktor:ktor-server-cio:$ktorVersion")
    implementation("io.ktor:ktor-server-sse:$ktorVersion")
    implementation("io.ktor:ktor-server-cors:$ktorVersion")
    implementation("io.ktor:ktor-server-content-negotiation:$ktorVersion")
    implementation("io.ktor:ktor-serialization-kotlinx-json:$ktorVersion")

    // --- Turbo engine ---
    implementation("org.python:jython-standalone:2.7.4")
    implementation("com.fifesoft:rsyntaxtextarea:4.0.1")
    implementation("com.fifesoft:rstaui:4.0.0")
    implementation("com.twitter:hpack:1.0.2")
    implementation("tech.kwik:kwik:0.12.3")

    // JOSE key ring, JWS, and JWE.
    // BouncyCastle is required for secp256k1 (ES256K), X448/Ed448 and PEM encode/decode.
    implementation("com.nimbusds:nimbus-jose-jwt:10.10")
    implementation("org.bouncycastle:bcprov-jdk18on:1.87")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.87")
    // Nimbus X25519 JWE calls Tink's subtle X25519/XChaCha20Poly1305, which need no protobuf;
    // Nimbus 10.10 excludes it from its own (optional) Tink dependency too.
    implementation("com.google.crypto.tink:tink:1.24.0") {
        exclude(group = "com.google.protobuf", module = "protobuf-java")
    }

    // GraphQL schema modeling (introspection JSON/SDL -> GraphQLSchema, query generation, SDL
    // printing). Plain JVM library, not sensitive to the Kotlin/Ktor pins above.
    implementation("com.graphql-java:graphql-java:26.2")

    // YAML OpenAPI/Swagger documents (api_import_openapi). Parsed with SafeConstructor only.
    implementation("org.yaml:snakeyaml:2.7")

    // --- Tests ---
    testImplementation(kotlin("test-junit5"))
    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    // Montoya is compileOnly for main; tests construct Montoya-typed values directly.
    testImplementation("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("io.ktor:ktor-server-test-host:$ktorVersion")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

// --- Single-sourced version -------------------------------------------------
// BuildInfo.VERSION is generated from the Gradle project `version`, so the UI tab,
// dashboard and MCP server identity can never drift from build.gradle.kts.
val generatedVersionDir = layout.buildDirectory.dir("generated/version/kotlin")
val generateBuildInfo = tasks.register("generateBuildInfo") {
    val outDir = generatedVersionDir
    val ver = project.version.toString()
    inputs.property("version", ver)
    outputs.dir(outDir)
    doLast {
        val f = outDir.get().file("io/bitbytelab/raijin/core/BuildInfo.kt").asFile
        f.parentFile.mkdirs()
        f.writeText(
            """
            |package io.bitbytelab.raijin.core
            |
            |/** Generated from the Gradle project version — do not edit by hand. */
            |object BuildInfo {
            |    const val VERSION: String = "$ver"
            |}
            |""".trimMargin()
        )
    }
}
kotlin.sourceSets["main"].kotlin.srcDir(generatedVersionDir)
tasks.named("compileKotlin") { dependsOn(generateBuildInfo) }
tasks.named("compileTestKotlin") { dependsOn(generateBuildInfo) }

tasks.shadowJar {
    archiveBaseName.set("raijin")
    archiveClassifier.set("")
    archiveVersion.set("")

    // Merge META-INF/services — required for ServiceLoader discovery (Ktor engines,
    // kotlinx-serialization formats, ...). Shadow 9 excludes duplicates by default, so
    // service files (and the Kotlin module metadata Shadow also merges) are let through for
    // the merge.
    mergeServiceFiles()
    filesMatching(listOf("META-INF/services/**", "META-INF/*.kotlin_module")) {
        duplicatesStrategy = DuplicatesStrategy.INCLUDE
    }

    // Signed dependencies (at.favre.lib:hkdf, pulled in by Kwik) ship signature files that
    // stop describing the archive once it is repackaged. Left in, the JVM refuses to define
    // any class from this jar and Burp reports "Extension class is not a recognized type".
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/*.EC")

    // Burp Suite provides the Montoya API at runtime
    dependencies {
        exclude(dependency("net.portswigger.burp.extensions:montoya-api"))
    }
}

// The plain (thin) jar is never what you load into Burp — only build the fat jar.
tasks.jar { enabled = false }

tasks.build {
    dependsOn(tasks.shadowJar)
}

// Convenience: copy the fat JAR to the project root for loading into Burp
tasks.register<Copy>("copyJar") {
    dependsOn(tasks.shadowJar)
    from(tasks.shadowJar.get().archiveFile)
    into(layout.projectDirectory)
}
