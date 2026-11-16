package io.bitbytelab.raijin.ui

import java.util.Collections
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class UiTasksTest {

    @Test
    fun `compute runs the work off the EDT and delivers the result on it`() {
        val tasks = UiTasks { _, _ -> }
        val workOnEdt = AtomicBoolean(true)
        val resultOnEdt = AtomicBoolean(false)
        val result = AtomicReference<Int>()
        val done = CountDownLatch(1)

        tasks.compute("work", {
            workOnEdt.set(SwingUtilities.isEventDispatchThread())
            42
        }) { value ->
            resultOnEdt.set(SwingUtilities.isEventDispatchThread())
            result.set(value)
            done.countDown()
        }

        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertFalse(workOnEdt.get())
        assertTrue(resultOnEdt.get())
        assertEquals(42, result.get())
        tasks.dispose()
    }

    @Test
    fun `store writes run one at a time in submission order`() {
        val tasks = UiTasks { _, _ -> }
        val order = Collections.synchronizedList(mutableListOf<Int>())
        val done = CountDownLatch(50)

        repeat(50) { i -> tasks.persist("write $i") { order += i; done.countDown() } }

        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertEquals((0 until 50).toList(), order.toList())
        tasks.dispose()
    }

    @Test
    fun `writes queued before dispose still reach the store`() {
        val tasks = UiTasks { _, _ -> }
        val gate = CountDownLatch(1)
        val done = CountDownLatch(2)
        tasks.persist("slow write") { gate.await(5, TimeUnit.SECONDS); done.countDown() }
        tasks.persist("queued write") { done.countDown() }

        tasks.dispose()
        gate.countDown()

        assertTrue(done.await(5, TimeUnit.SECONDS))
    }

    @Test
    fun `the result of work still running at dispose is dropped`() {
        val tasks = UiTasks { _, _ -> }
        val started = CountDownLatch(1)
        val delivered = AtomicBoolean(false)
        tasks.compute("slow fetch", {
            started.countDown()
            Thread.sleep(200)
            "late"
        }) { delivered.set(true) }

        assertTrue(started.await(5, TimeUnit.SECONDS))
        tasks.dispose()
        Thread.sleep(400)
        SwingUtilities.invokeAndWait {}

        assertFalse(delivered.get())
    }

    @Test
    fun `a failure is reported with the task description`() {
        val reported = AtomicReference<String>()
        val done = CountDownLatch(1)
        val tasks = UiTasks { desc, _ -> reported.set(desc); done.countDown() }

        tasks.execute("Fetch proxy history") { throw IllegalStateException("boom") }

        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertEquals("Fetch proxy history", reported.get())
        tasks.dispose()
    }

    @Test
    fun `work submitted after dispose never runs`() {
        val tasks = UiTasks { _, _ -> }
        tasks.dispose()
        val ran = AtomicBoolean(false)

        tasks.execute("late") { ran.set(true) }
        tasks.persist("late write") { ran.set(true) }
        Thread.sleep(200)

        assertFalse(ran.get())
        assertTrue(tasks.isDisposed)
    }

    /** A live list plus the change callbacks a snapshot over it registered, as StateManager's listener lists hold them. */
    private class Tracked {
        val live = CopyOnWriteArrayList<String>()
        var added: ((String) -> Unit)? = null
        var removed: ((String) -> Unit)? = null

        fun snapshot(tasks: UiTasks, newestFirst: Boolean = false) =
            tasks.storeSnapshot({ live.toList() }, { it }, newestFirst) { a, r -> added = a; removed = r }
    }

    @Test
    fun `a store snapshot reads live state until dispose and the state at dispose after it`() {
        val tasks = UiTasks { _, _ -> }
        val state = Tracked()
        val snapshot = state.snapshot(tasks)
        state.live += listOf("a", "b")
        assertEquals(listOf("a", "b"), snapshot.read())
        assertNull(state.added, "nothing is tracked while the tab is up")

        tasks.dispose()
        state.live.clear() // StateManager.cleanup() runs after the tab is disposed

        assertEquals(listOf("a", "b"), snapshot.read())
    }

    @Test
    fun `changes reported after dispose reach the frozen snapshot in the live order`() {
        val tasks = UiTasks { _, _ -> }
        val oldestFirst = Tracked().apply { live += listOf("a", "b") }
        val newestFirst = Tracked().apply { live += listOf("b", "a") }
        val forward = oldestFirst.snapshot(tasks)
        val backward = newestFirst.snapshot(tasks, newestFirst = true)
        tasks.dispose()

        for (state in listOf(oldestFirst, newestFirst)) {
            state.added!!("c")
            state.added!!("b") // added before the copy was taken: already in it
            state.removed!!("a")
            state.live.clear()
        }

        assertEquals(listOf("b", "c"), forward.read())
        assertEquals(listOf("c", "b"), backward.read())
    }

    @Test
    fun `a snapshot that could not be frozen fails the write instead of reading live state`() {
        val tasks = UiTasks { _, _ -> }
        val reads = AtomicBoolean(true)
        val snapshot = tasks.storeSnapshot({ check(reads.get()) { "state unavailable" }; listOf("a") }, { it }, newestFirst = false) { _, _ -> }
        reads.set(false)
        tasks.dispose()
        reads.set(true)

        assertFailsWith<IllegalStateException> { snapshot.read() }
    }

    @Test
    fun `a write queued before dispose saves the frozen state even when it runs after the clear`() {
        val tasks = UiTasks { _, _ -> }
        val state = Tracked().apply { live += listOf("a", "b") }
        val snapshot = state.snapshot(tasks)
        val gate = CountDownLatch(1)
        val saved = AtomicReference<List<String>>()
        val done = CountDownLatch(1)
        tasks.persist("busy store") { gate.await(5, TimeUnit.SECONDS) }
        tasks.persist("Save") { saved.set(snapshot.read()); done.countDown() }

        // dispose() must return while the writer is still blocked: it never waits for queued writes.
        val disposer = Thread { tasks.dispose() }.apply { start(); join(5_000) }
        assertFalse(disposer.isAlive, "dispose blocked on a queued store write")
        state.live.clear()
        gate.countDown()

        assertTrue(done.await(5, TimeUnit.SECONDS))
        assertEquals(listOf("a", "b"), saved.get())
    }
}
