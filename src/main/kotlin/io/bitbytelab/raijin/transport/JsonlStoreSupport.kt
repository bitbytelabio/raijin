package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.core.BodyText
import java.io.File
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
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

    /**
     * Appends [line] (lone surrogates replaced, so it always encodes as UTF-8). A new file is made
     * owner-only where the file system has POSIX permissions; a file whose last line was cut off
     * by a crash gets its line ended first, so the new record stays parseable.
     */
    fun appendLine(file: File, line: String) {
        file.parentFile?.mkdirs()
        val path = file.toPath()
        createPrivate(path)
        val prefix = if (endsWithoutNewline(path)) "\n" else ""
        Files.writeString(
            path,
            prefix + BodyText.stripLoneSurrogates(line) + "\n",
            Charsets.UTF_8,
            StandardOpenOption.CREATE,
            StandardOpenOption.WRITE,
            StandardOpenOption.APPEND
        )
    }

    /** Store files already made owner-only in this process. */
    private val privateFiles = ConcurrentHashMap.newKeySet<String>()

    /**
     * Makes [path] owner-only (rw-------) where POSIX permissions apply: created that way when it
     * does not exist, and once per process tightened when an older version left it readable to
     * others (the stores hold cookies, tokens and keys).
     */
    private fun createPrivate(path: Path) {
        val owner = PosixFilePermissions.fromString("rw-------")
        if (!Files.exists(path)) {
            try {
                Files.createFile(path, PosixFilePermissions.asFileAttribute(owner))
            } catch (_: UnsupportedOperationException) {
                // Not a POSIX file system: the default permissions apply.
            } catch (_: FileAlreadyExistsException) {
                // Another writer created it first.
            }
        }
        if (privateFiles.add(path.toAbsolutePath().normalize().toString())) {
            runCatching { if (Files.getPosixFilePermissions(path) != owner) Files.setPosixFilePermissions(path, owner) }
        }
    }

    private fun endsWithoutNewline(path: Path): Boolean {
        val size = try { Files.size(path) } catch (_: Exception) { return false }
        if (size == 0L) return false
        return FileChannel.open(path, StandardOpenOption.READ).use { channel ->
            val last = ByteBuffer.allocate(1)
            channel.read(last, size - 1)
            last.get(0) != '\n'.code.toByte()
        }
    }

    /** Replaces [target] with [lines] through a synced temp file and a rename, so a crash leaves the old or the new file. */
    fun atomicWriteLines(target: File, lines: List<String>) {
        val parent = target.absoluteFile.parentFile ?: File(".")
        parent.mkdirs()
        val tmp = Files.createTempFile(parent.toPath(), target.name + ".", ".tmp")
        try {
            Files.write(tmp, lines.map(BodyText::stripLoneSurrogates), Charsets.UTF_8)
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
