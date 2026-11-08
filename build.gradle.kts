plugins {
    kotlin("jvm") version "2.1.20"
    kotlin("plugin.serialization") version "2.1.20"
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "io.bitbytelab"
version = "1.0.0"

// Build JDK: gradle/gradle-daemon-jvm.properties pins the Gradle daemon to JDK 21, so
// `./gradlew` relaunches the build under JDK 21 even when started from a newer JVM (e.g.
// Burp's bundled Java 25). Kotlin 2.1.20 cannot compile these .kts scripts on Java 22+.
//
// Bytecode target is 21: the Turbo engines use virtual threads
// (Thread.ofVirtual / Executors.newThreadPerTaskExecutor). Burp ships Java 21+.
kotlin {
    jvmToolchain(21)
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

repositories {
    mavenCentral()
}

val ktorVersion = "3.2.3"
val montoyaVersion = "2026.2"

dependencies {
    // Burp Suite Montoya API — provided by Burp at runtime, never bundled
    compileOnly("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")

    // --- MCP server (Kotlin SDK on Ktor CIO) ---
    implementation("io.modelcontextprotocol:kotlin-sdk-server:0.8.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
    // Ktor versions must match what kotlin-sdk-server 0.8.3 was compiled against
    implementation("io.ktor:ktor-server-cio:$ktorVersion")
    implementation("io.ktor:ktor-server-sse:$ktorVersion")
    implementation("io.ktor:ktor-server-cors:$ktorVersion")
    implementation("io.ktor:ktor-server-content-negotiation:$ktorVersion")
    implementation("io.ktor:ktor-serialization-kotlinx-json:$ktorVersion")

    // --- Turbo engine ---
    implementation("org.python:jython-standalone:2.7.0")
    implementation("com.fifesoft:rsyntaxtextarea:3.1.1")
    implementation("com.fifesoft:rstaui:3.1.1")
    implementation("com.twitter:hpack:1.0.2")
    implementation("tech.kwik:kwik:0.10.3")

    // --- Tests ---
    testImplementation(kotlin("test-junit5"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    // Montoya is compileOnly for main; tests construct Montoya-typed values directly.
    testImplementation("net.portswigger.burp.extensions:montoya-api:$montoyaVersion")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}

tasks.compileKotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

tasks.compileTestKotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

// --- Single-sourced version -------------------------------------------------
// BuildInfo.VERSION is generated from the Gradle project `version`, so the UI tab,
// dashboard and MCP server identity can never drift from build.gradle.kts.
val generatedVersionDir = layout.buildDirectory.dir("generated/version/kotlin")
val generateBuildInfo by tasks.registering {
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
    // kotlinx-serialization formats, ...)
    mergeServiceFiles()

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
