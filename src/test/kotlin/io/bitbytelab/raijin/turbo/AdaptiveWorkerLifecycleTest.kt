package io.bitbytelab.raijin.turbo

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The worker pool ThreadedRequestEngine and BurpRequestEngine share, run without either engine:
 * its workers here idle until they are retired, or until the test lets them go.
 */
class AdaptiveWorkerLifecycleTest {

    private class Unrecoverable : Error("not a capacity failure")

    private val engine = TestRequestEngine()
    private val pools = mutableListOf<AdaptiveWorkerLifecycle>()
    @Volatile private var finished = false

    @AfterEach
    fun letWorkersGo() {
        finished = true
        pools.forEach { it.awaitCompletion(5, TimeUnit.SECONDS) }
    }

    /** Workers that idle until retired, noting each retired worker's handle id in [retired]. */
    private fun idlePool(adaptive: Boolean, size: Int, retired: MutableCollection<Int> = ConcurrentLinkedQueue()): AdaptiveWorkerLifecycle {
        lateinit var pool: AdaptiveWorkerLifecycle
        pool = AdaptiveWorkerLifecycle(engine, adaptive, size) { handle -> idleUntilRetired(pool, handle, retired) }
        pools += pool
        return pool
    }

    private fun idleUntilRetired(pool: AdaptiveWorkerLifecycle, handle: DynamicWorkerRegistry.Handle?, retired: MutableCollection<Int>) {
        while (!finished) {
            if (pool.shouldRetire(handle)) {
                retired += handle!!.id
                return
            }
            Thread.sleep(5)
        }
    }

    /** An adaptive pool whose workers are whatever [starter] makes of them: it starts no thread. */
    private fun starterPool(size: Int, starter: AdaptiveWorkerStarter): AdaptiveWorkerLifecycle =
        AdaptiveWorkerStarterConstructionContext.withStarter(starter) {
            AdaptiveWorkerLifecycle(engine, adaptive = true, initialSize = size) {}
        }

    @Test
    fun `shrinking retires the newest workers, and the pool settles at its new size`() {
        val retired = ConcurrentLinkedQueue<Int>()
        val pool = idlePool(adaptive = true, size = 3, retired = retired)
        pool.startInitial(awaitRunning = true)
        assertEquals(3, pool.liveSize())

        pool.resize(1)

        assertEquals(1, pool.awaitWorkerCount(1, 5, TimeUnit.SECONDS))
        assertEquals(listOf(2, 3), retired.sorted())
        assertEquals(1, pool.targetSize())
        assertEquals(1, pool.liveSize())
        assertTrue(pool.converged())
    }

    @Test
    fun `a worker that cannot be started counts as a transport failure, and anything worse is thrown`() {
        var failure: Throwable? = null
        val started = mutableListOf<Int>()
        val pool = starterPool(size = 1) { handle ->
            failure?.let { throw it }
            started += handle.id
        }
        pool.startInitial(awaitRunning = false)

        failure = OutOfMemoryError("unable to create native thread")
        pool.resize(3)

        // Growing stops at the first worker that cannot be started.
        assertEquals(1, engine.transportFailures.get())
        assertEquals("java.lang.OutOfMemoryError: unable to create native thread", engine.lastError)
        assertEquals(listOf(1), started)

        failure = Unrecoverable()
        assertThrows<Unrecoverable> { pool.resize(3) }
        assertEquals(1, engine.transportFailures.get())
    }

    @Test
    fun `a first start that fails part way cancels the run and closes the workers it started`() {
        val started = mutableListOf<DynamicWorkerRegistry.Handle>()
        val pool = starterPool(size = 3) { handle ->
            if (started.size == 2) throw OutOfMemoryError("unable to create native thread")
            started += handle
        }

        // The engine's construction fails with it, so the failure is thrown rather than counted.
        assertThrows<OutOfMemoryError> { pool.startInitial(awaitRunning = false) }
        pool.abortStart()

        assertEquals(3, engine.runState.get())
        assertEquals(2, started.size)
        assertTrue(started.all { it.isClosed() }, "a started worker was left in the pool")
        assertEquals(0, pool.awaitWorkerCount(0, 0, TimeUnit.SECONDS))
        assertEquals(0, engine.transportFailures.get())
    }

    @Test
    fun `with awaitRunning no adaptive worker starts work until the whole first pool runs`() {
        val seen = ConcurrentLinkedQueue<Int>()
        val entered = CountDownLatch(3)
        lateinit var pool: AdaptiveWorkerLifecycle
        pool = AdaptiveWorkerLifecycle(engine, adaptive = true, initialSize = 3) {
            seen += pool.liveSize()
            entered.countDown()
            while (!finished) Thread.sleep(5)
        }
        pools += pool

        pool.startInitial(awaitRunning = true)

        assertTrue(entered.await(5, TimeUnit.SECONDS))
        // A worker let go before the others ran saw fewer live workers than gates could count on.
        assertEquals(listOf(3, 3, 3), seen.toList())
    }

    @Test
    fun `once every adaptive worker has left, the pool is sealed and a resize starts none`() {
        val pool = idlePool(adaptive = true, size = 2)
        pool.startInitial(awaitRunning = true)
        assertFalse(pool.awaitCompletion(50, TimeUnit.MILLISECONDS), "completed while its workers ran")

        finished = true
        assertTrue(pool.awaitCompletion(5, TimeUnit.SECONDS))
        pool.resize(4)

        assertEquals(0, pool.awaitWorkerCount(0, 0, TimeUnit.SECONDS))
        assertEquals(0, pool.liveSize())
    }

    @Test
    fun `a fixed pool never retires, and each worker's exit counts down the run's latch`() {
        engine.completedLatch = CountDownLatch(2)
        val askedToRetire = ConcurrentLinkedQueue<Boolean>()
        lateinit var pool: AdaptiveWorkerLifecycle
        pool = AdaptiveWorkerLifecycle(engine, adaptive = false, initialSize = 2) { handle ->
            askedToRetire += pool.shouldRetire(handle)
        }

        pool.startInitial(awaitRunning = true)

        assertTrue(pool.awaitCompletion(5, TimeUnit.SECONDS))
        assertEquals(listOf(false, false), askedToRetire.toList())
        assertEquals(2, pool.targetSize())
        assertEquals(2, pool.liveSize())
        assertTrue(pool.converged())
    }

    @Test
    fun `stopAll interrupts the workers still running, which then complete`() {
        engine.completedLatch = CountDownLatch(1)
        val interrupted = CountDownLatch(1)
        val pool = AdaptiveWorkerLifecycle(engine, adaptive = false, initialSize = 1) {
            try {
                CountDownLatch(1).await()
            } catch (_: InterruptedException) {
                interrupted.countDown()
            }
        }
        pool.startInitial(awaitRunning = false)

        pool.stopAll()

        assertTrue(interrupted.await(5, TimeUnit.SECONDS))
        assertTrue(engine.completedLatch.await(5, TimeUnit.SECONDS))
    }
}
