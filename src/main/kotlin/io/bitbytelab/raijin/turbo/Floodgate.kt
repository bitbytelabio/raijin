package io.bitbytelab.raijin.turbo

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * A named gate that holds queued requests until every waiter is ready, then releases them
 * together (the basis of the single-packet / last-byte-sync techniques).
 */
@Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
class Floodgate(@JvmField var name: String, internal var engine: RequestEngine) {
    @JvmField val remaining = AtomicInteger(1)
    @JvmField val isOpen = AtomicBoolean(false)
    @JvmField val fullyQueued = AtomicBoolean(false)

    // Monitors guarding wait/notify on the two counters (mirrors the original Java, which
    // synchronised on the atomics themselves).
    private val remainingMonitor = remaining as java.lang.Object
    private val openMonitor = isOpen as java.lang.Object

    /**
     * Called by the script thread. Blocks until all waiters are ready, then opens the gate.
     * Returns false without opening when the gate is already open or the run ended first:
     * opening a cancelled run's gate would send the requests the user just stopped.
     */
    @Throws(InterruptedException::class)
    fun open(): Boolean {
        if (isOpen.get()) {
            Utils.out("Gate is already open")
            return false
        }
        fullyQueued.set(true)

        synchronized(remainingMonitor) {
            while (remaining.get() > 0 && !runEnded()) {
                remainingMonitor.wait(WAIT_SLICE_MILLIS)
            }
        }
        if (runEnded()) return false
        makeOpen()
        return true
    }

    private fun makeOpen() {
        synchronized(openMonitor) {
            isOpen.set(true)
            openMonitor.notifyAll()
        }
    }

    fun addWaiter() {
        remaining.incrementAndGet()
    }

    fun hasStartedOpening(): Boolean = fullyQueued.get() || isOpen.get()

    /**
     * Blocks the worker holding a gated request until the gate opens. Throws [InterruptedException]
     * when the run ends first; a cancel before openGate() used to leave the worker parked forever.
     */
    @Throws(InterruptedException::class)
    fun waitForGo() {
        remaining.decrementAndGet()
        synchronized(remainingMonitor) { remainingMonitor.notifyAll() }
        synchronized(openMonitor) {
            while (!isOpen.get()) {
                if (runEnded()) {
                    throw InterruptedException("Gate '$name' was abandoned: the run ended before it opened")
                }
                openMonitor.wait(WAIT_SLICE_MILLIS)
            }
        }
    }

    fun reportReadyWithoutWaiting(): Boolean {
        remaining.decrementAndGet()
        synchronized(remainingMonitor) { remainingMonitor.notifyAll() }
        return remaining.get() == 0 && fullyQueued.get()
    }

    /** Wakes every thread blocked in [open] or [waitForGo], so it sees at once that the run ended. */
    fun wakeWaiters() {
        synchronized(remainingMonitor) { remainingMonitor.notifyAll() }
        synchronized(openMonitor) { openMonitor.notifyAll() }
    }

    private fun runEnded(): Boolean = engine.runState.get() >= 3 || Utils.unloaded

    private companion object {
        /** The longest a waiter can miss the end of a run that nobody woke it for. */
        const val WAIT_SLICE_MILLIS = 100L
    }
}
