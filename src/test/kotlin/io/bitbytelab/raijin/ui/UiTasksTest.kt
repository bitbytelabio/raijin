package io.bitbytelab.raijin.ui

import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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
}
