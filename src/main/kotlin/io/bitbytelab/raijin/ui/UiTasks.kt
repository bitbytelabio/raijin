package io.bitbytelab.raijin.ui

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
 *   the one that reaches disk. Writes queued before [dispose] still complete.
 * - After [dispose], new work is ignored, and results and errors of work still running are dropped.
 *
 * [onError] is called on the worker thread with the failed task's description.
 */
internal class UiTasks(private val onError: (desc: String, error: Exception) -> Unit) {
    private val disposed = AtomicBoolean(false)
    private val workers = pool("raijin-ui", WORKERS)
    private val writer = pool("raijin-ui-store", 1)

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

    fun dispose() {
        if (!disposed.compareAndSet(false, true)) return
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
