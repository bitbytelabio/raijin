package io.bitbytelab.raijin.transport

import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption

/**
 * Shared atomic JSONL disk-store helpers used by [ActivityStore], [FindingsStore], and [AuditLog].
 */
internal object JsonlStoreSupport {

    fun appendLine(file: File, line: String) {
        file.parentFile?.mkdirs()
        Files.writeString(
            file.toPath(),
            line + "\n",
            Charsets.UTF_8,
            StandardOpenOption.CREATE,
            StandardOpenOption.WRITE,
            StandardOpenOption.APPEND
        )
    }

    fun atomicWriteLines(target: File, lines: List<String>) {
        val parent = target.parentFile ?: File(".")
        parent.mkdirs()
        val tmp = Files.createTempFile(parent.toPath(), target.name + ".", ".tmp")
        try {
            Files.write(tmp, lines, Charsets.UTF_8)
            try {
                Files.move(tmp, target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: Exception) {
                Files.move(tmp, target.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(tmp)
        }
    }
}
