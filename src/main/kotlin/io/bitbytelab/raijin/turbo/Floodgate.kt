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

    /** Called by the script thread. Blocks until all waiters are ready, then opens the gate. */
    fun open(): Boolean {
        if (isOpen.get()) {
            Utils.out("Gate is already open")
            return false
        }
        fullyQueued.set(true)

        if (remaining.get() > 0) {
            while (remaining.get() > 0 && engine.runState.get() < 3) {
                synchronized(remainingMonitor) {
                    try {
                        remainingMonitor.wait(100)
                    } catch (e: InterruptedException) {
                        e.printStackTrace()
                    }
                }
            }
        }
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

    @Throws(InterruptedException::class)
    fun waitForGo() {
        remaining.decrementAndGet()
        synchronized(remainingMonitor) { remainingMonitor.notifyAll() }
        synchronized(openMonitor) {
            while (!isOpen.get()) openMonitor.wait()
        }
    }

    fun reportReadyWithoutWaiting(): Boolean {
        remaining.decrementAndGet()
        synchronized(remainingMonitor) { remainingMonitor.notifyAll() }
        return remaining.get() == 0 && fullyQueued.get()
    }
}
