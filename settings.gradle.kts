// Gradle's daemon runs on JDK 21 via gradle/gradle-daemon-jvm.properties, even
// when ./gradlew is launched with a newer JVM such as Burp's bundled Java.
// Keep this aligned with the bytecode/toolchain target in build.gradle.kts.
rootProject.name = "raijin"
