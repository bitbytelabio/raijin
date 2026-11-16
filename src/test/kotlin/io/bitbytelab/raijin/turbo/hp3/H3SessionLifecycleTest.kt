package io.bitbytelab.raijin.turbo.hp3

import io.bitbytelab.raijin.turbo.H3Connection
import io.bitbytelab.raijin.turbo.H3Exchange
import io.bitbytelab.raijin.turbo.StagedExchange
import io.bitbytelab.raijin.turbo.gatedRequestMayBeQueued
import io.bitbytelab.raijin.turbo.hp3.quic.KwikThreads
import io.bitbytelab.raijin.turbo.hp3.quic.StreamFragment
import java.io.IOException
import java.util.concurrent.CompletableFuture
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class H3SessionLifecycleTest {

    private val answered: CompletableFuture<H3Exchange>
        get() = CompletableFuture.completedFuture(H3Exchange(ByteArray(0), 0, 0))

    /** The one byte and FIN a datagram release withheld from a stream whose first 10 bytes went out. */
    private val withheld = StreamFragment(0, 10, byteArrayOf(0x41), true)

    @Test
    fun aConnectionThatCannotSetUpHttp3ClosesItsTransport() {
        val transport = MemoryTransport().apply { failUnidirectionalOpens = true }

        assertFailsWith<IOException> { H3Connection.open(transport) }

        assertEquals(1, transport.plainCloses.get())
    }

    @Test
    fun aDatagramReleasedStreamIsFinishedWithTheBytesItsReleaseCarried() {
        val stream = MemoryStream(0, false)
        val staged = StagedExchange(stream, withheld, answered)

        assertTrue(staged.finishStream())

        assertContentEquals(byteArrayOf(0x41), stream.writtenBytes())
        assertTrue(stream.finished)
    }

    @Test
    fun aStreamWhoseResponseNeverArrivedIsNotCompletedLate() {
        val stream = MemoryStream(0, false)
        val staged = StagedExchange(stream, withheld, CompletableFuture())

        assertFalse(staged.finishStream(), "a pending response")
        staged.fail(IOException("response deadline passed"))
        assertFalse(staged.finishStream(), "a failed response")

        assertContentEquals(ByteArray(0), stream.writtenBytes())
        assertFalse(stream.finished)
    }

    @Test
    fun aQpackBlockedStreamHasNothingLeftToFinish() {
        val stream = MemoryStream(0, false)
        val staged = StagedExchange(stream, null, answered)

        assertTrue(staged.finishStream())

        assertContentEquals(ByteArray(0), stream.writtenBytes())
    }

    @Test
    fun aStreamThatRefusesTheWriteCannotBeFinished() {
        val stream = MemoryStream(0, false).apply { refuseWrites = true }

        assertFalse(StagedExchange(stream, withheld, answered).finishStream())
    }

    @Test
    fun aReleaseThatCarriedNoFinCannotBeFinishedHere() {
        val stream = MemoryStream(0, false)
        val withoutFin = StreamFragment(0, 10, byteArrayOf(0x41), false)

        assertFalse(StagedExchange(stream, withoutFin, answered).finishStream())
        assertContentEquals(ByteArray(0), stream.writtenBytes())
    }

    @Test
    fun theQueueIsWalkedForGatedRequestsOnlyWhileOneMayBeInIt() {
        // No gate in flight: nothing is walked, and no gate is even looked at.
        assertFalse(gatedRequestMayBeQueued(0, setOf("done")) { error("no gate should be consulted") })
        // An active gate without a batch has not had a request staged yet, so they are all queued.
        assertTrue(gatedRequestMayBeQueued(1, emptySet()) { 0 })
        assertTrue(gatedRequestMayBeQueued(2, setOf("staging")) { 0 })
        // Every active gate has a batch: walk only while one still has requests to stage.
        assertTrue(gatedRequestMayBeQueued(2, setOf("staged", "staging")) { if (it == "staging") 3 else 0 })
        assertFalse(gatedRequestMayBeQueued(2, setOf("staged", "released")) { 0 })
    }

    @Test
    fun kwikReadersAreVirtualOnlyWhereBlockingInAMonitorDoesNotPin() {
        assertFalse(KwikThreads.prefersVirtualThreads(21))
        assertFalse(KwikThreads.prefersVirtualThreads(23))
        assertTrue(KwikThreads.prefersVirtualThreads(24))

        val thread = KwikThreads.blockingThread("kwik-reader").unstarted {}
        assertEquals(KwikThreads.prefersVirtualThreads(Runtime.version().feature()), thread.isVirtual)
        if (!thread.isVirtual) {
            assertTrue(thread.isDaemon, "a platform reader must not hold the JVM open")
        }
    }
}
