// Gradle's daemon runs on JDK 25 via gradle/gradle-daemon-jvm.properties, even
// when ./gradlew is launched with another JVM.
// Keep this aligned with the bytecode/toolchain target in build.gradle.kts.
rootProject.name = "raijin"
