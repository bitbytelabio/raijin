package io.bitbytelab.raijin.ui

import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.swing.SwingUtilities

/**
 * Off-EDT work for one Raijin tab: the job of `javax.swing.SwingWorker`, on threads the tab owns.
 * SwingWorker's shared pool outlives an extension reload; this one stops in [dispose].
 *
 * - [execute] and [compute] run on a small daemon pool; [compute] hands its result to the EDT.
 * - [persist] runs store writes one at a time in submission order, so the operator's last action is
 *   the one that reaches disk. Writes queued before [dispose] still complete; the state they save is
 *   read through a [storeSnapshot], which [dispose] freezes before the owner clears that state.
 * - After [dispose], new work is ignored, and results and errors of work still running are dropped.
 *
 * [onError] is called on the worker thread with the failed task's description.
 */
internal class UiTasks(private val onError: (desc: String, error: Exception) -> Unit) {
    private val disposed = AtomicBoolean(false)
    private val workers = pool("raijin-ui", WORKERS)
    private val writer = pool("raijin-ui-store", 1)
    private val snapshots = CopyOnWriteArrayList<StoreSnapshot<*, *>>()

    val isDisposed: Boolean get() = disposed.get()

    /** Runs [work] off the EDT. */
    fun execute(desc: String, work: () -> Unit) = submit(workers, desc, work)

    /** Runs [work] off the EDT, then [onResult] with its result on the EDT. */
    fun <T> compute(desc: String, work: () -> T, onResult: (T) -> Unit) = submit(workers, desc) {
        val result = work()
        SwingUtilities.invokeLater { if (!disposed.get()) onResult(result) }
    }

    /** Queues a store write behind every earlier one. */
    fun persist(desc: String, write: () -> Unit) = submit(writer, desc, write)

    /** The state [persist] writes save, frozen by [dispose]; see [StoreSnapshot]. */
    fun <T, K> storeSnapshot(
        live: () -> List<T>,
        key: (T) -> K,
        newestFirst: Boolean,
        track: (added: (T) -> Unit, removed: (K) -> Unit) -> Unit,
    ): StoreSnapshot<T, K> = StoreSnapshot(live, key, newestFirst, track).also { snapshot ->
        snapshots += snapshot
        if (disposed.get()) snapshot.freeze()
    }

    /**
     * Stops the tab's work without waiting for it: queued store writes finish later, on their own
     * thread. Freezing the [storeSnapshot]s first is what makes that safe, and it only copies memory,
     * so this never blocks the EDT.
     */
    fun dispose() {
        if (!disposed.compareAndSet(false, true)) return
        snapshots.forEach { it.freeze() }
        workers.shutdownNow()
        writer.shutdown()
    }

    private fun submit(executor: ThreadPoolExecutor, desc: String, task: () -> Unit) {
        if (disposed.get()) return
        try {
            executor.execute {
                try {
                    task()
                } catch (e: Exception) {
                    if (!disposed.get()) onError(desc, e)
                }
            }
        } catch (_: RejectedExecutionException) {
            // Disposed between the check and the submit.
        }
    }

    private companion object {
        const val WORKERS = 4

        fun pool(name: String, size: Int): ThreadPoolExecutor {
            val seq = AtomicInteger()
            val factory = ThreadFactory { r -> Thread(r, "$name-${seq.incrementAndGet()}").apply { isDaemon = true } }
            return ThreadPoolExecutor(size, size, 30, TimeUnit.SECONDS, LinkedBlockingQueue(), factory)
                .apply { allowCoreThreadTimeOut(true) }
        }
    }
}

/**
 * State a [UiTasks.persist] write saves. A store rewrite reads it under the store's file lock, so a
 * concurrent append is never overwritten with older data; but on unload the owner clears this state
 * right after disposing the tab, while a write queued before may still be waiting for that lock.
 *
 * Until [freeze] (which [UiTasks.dispose] calls), [read] returns [live]. [freeze] starts [track]ing
 * changes, then copies [live] once; from then on [read] never calls [live] again and returns that
 * copy with the tracked changes applied: the live state as it was up to the clear, which [track] does
 * not report. A write still queued at the clear therefore saves that state, not an empty list.
 *
 * [track] must report each change before the store records it, so a write that reads the copy just
 * before a change is followed by the store's own write of it, as it would be with [live].
 *
 * @param key identifies an item, for removals and for an item both copied and tracked.
 * @param newestFirst whether [live] lists items newest first (new items join at the front).
 */
internal class StoreSnapshot<T, K>(
    private val live: () -> List<T>,
    private val key: (T) -> K,
    private val newestFirst: Boolean,
    private val track: (added: (T) -> Unit, removed: (K) -> Unit) -> Unit,
) {
    private class Frozen<T, K>(val copy: Result<List<T>>, val changes: ConcurrentLinkedQueue<(MutableMap<K, T>) -> Unit>)

    @Volatile
    private var frozen: Frozen<T, K>? = null

    /** The state to save. After a failed [freeze] this throws, so the write fails rather than read [live]. */
    fun read(): List<T> {
        frozen?.let { return current(it) }
        val value = live()
        // Frozen meanwhile? The owner may have cleared what was just read.
        return frozen?.let { current(it) } ?: value
    }

    /** Idempotent. */
    @Synchronized
    fun freeze() {
        if (frozen != null) return
        val changes = ConcurrentLinkedQueue<(MutableMap<K, T>) -> Unit>()
        val copy = runCatching {
            track(
                { item -> changes.add { items -> items.putIfAbsent(key(item), item) } },
                { k -> changes.add { items -> items.remove(k) } },
            )
            live()
        }
        frozen = Frozen(copy, changes)
    }

    private fun current(f: Frozen<T, K>): List<T> {
        val copy = f.copy.getOrThrow()
        // Oldest first, so a tracked addition joins at the end.
        val items = LinkedHashMap<K, T>()
        (if (newestFirst) copy.asReversed() else copy).forEach { items.putIfAbsent(key(it), it) }
        f.changes.forEach { it(items) }
        val oldestFirst = items.values.toList()
        return if (newestFirst) oldestFirst.asReversed() else oldestFirst
    }
}
