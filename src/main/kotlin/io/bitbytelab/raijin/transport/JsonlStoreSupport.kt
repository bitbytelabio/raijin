package io.bitbytelab.raijin.transport

import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock

/**
 * Shared JSONL disk-store helpers used by [ActivityStore], [FindingsStore], and [AuditLog]: one lock
 * per file, appends, atomic rewrites, and failure reporting.
 */
internal object JsonlStoreSupport {

    private val locks = ConcurrentHashMap<String, ReentrantLock>()
    private val reported = ConcurrentHashMap<String, String>()

    /**
     * Where write failures go besides stderr. The extension points it at Burp's error log so a
     * full disk or a permission problem shows up in Burp instead of only on the console.
     */
    @Volatile
    var errorSink: ((String) -> Unit)? = null

    /** The lock for [file], shared by every store instance that writes it (appends, rewrites, rotation). */
    fun lockFor(file: File): ReentrantLock = locks.computeIfAbsent(key(file)) { ReentrantLock() }

    /**
     * Records a failed [op] on [file]: prints it to stderr and, once per distinct message until the
     * store recovers, to [errorSink]. Returns the message for the store's `lastError`.
     */
    fun reportFailure(store: String, op: String, file: File, ex: Exception): String {
        val reason = ex.message ?: ex::class.simpleName ?: "unknown error"
        val message = "Raijin: $store.$op failed (${file.absolutePath}): $reason"
        System.err.println(message)
        if (reported.put(key(file), reason) != reason) runCatching { errorSink?.invoke(message) }
        return reason
    }

    /** Marks [file] healthy again, so its next failure is reported even if the message repeats. */
    fun recovered(file: File) {
        if (reported.isNotEmpty()) reported.remove(key(file))
    }

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

    /** Replaces [target] with [lines] through a synced temp file and a rename, so a crash leaves the old or the new file. */
    fun atomicWriteLines(target: File, lines: List<String>) {
        val parent = target.absoluteFile.parentFile ?: File(".")
        parent.mkdirs()
        val tmp = Files.createTempFile(parent.toPath(), target.name + ".", ".tmp")
        try {
            Files.write(tmp, lines, Charsets.UTF_8)
            FileChannel.open(tmp, StandardOpenOption.WRITE).use { it.force(true) }
            try {
                Files.move(tmp, target.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (_: Exception) {
                Files.move(tmp, target.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(tmp)
        }
    }

    private fun key(file: File): String = file.absoluteFile.normalize().path
}
