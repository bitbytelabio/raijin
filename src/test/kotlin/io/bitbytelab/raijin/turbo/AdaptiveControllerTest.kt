package io.bitbytelab.raijin.turbo

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class AdaptiveControllerTest {

    /** A pool that never converges, so every sample takes the failure-only path. */
    private class ConvergingTransport : AdaptiveTransport {
        override val autoProtocol = AutoProtocol.HTTP2
        var limits = AdaptiveLimits(8, null)
        var transportFailures = 0
        val resizes = mutableListOf<Int>()

        override fun defaultAdaptiveLimits() = AdaptiveLimits(8, null)

        override fun currentAdaptiveLimits() = limits

        override fun adaptiveMetrics() = AdaptiveMetrics(
            capturedAtNanos = 0,
            successfulResponses = 0,
            transportFailures = transportFailures,
            retryAttempts = 0,
            permanentFailures = 0,
            activeRequests = 0,
            queuedRequests = 0,
            openedConnections = 0,
            retiredConnections = 0,
            limits = limits,
            saturated = true,
            freezeReason = null,
            safeToMeasure = false,
        )

        override fun resizeConcurrency(newLimit: Int) {
            resizes += newLimit
            limits = limits.copy(concurrency = newLimit)
        }

        override fun resizeRequestsPerConnection(newLimit: Int) = false
    }

    @Test
    fun `failures while the pool converges are judged once per window, not at every sample`() {
        val transport = ConvergingTransport()
        var now = 0L
        val controller = AdaptiveController(
            transport,
            AdaptivePolicy(AutoProtocol.HTTP2, transport.defaultAdaptiveLimits()),
            clock = { now },
            transitionLogger = {},
            automaticSampling = false,
        )

        controller.sampleOnce() // baseline
        transport.transportFailures = 1
        for (sample in 1..3) {
            now = sample * 250_000_000L
            controller.sampleOnce()
        }
        assertEquals(emptyList<Int>(), transport.resizes, "backed off before a window had passed")

        now = 1_000_000_000L
        controller.sampleOnce()
        assertEquals(listOf(6), transport.resizes)

        // The failures that backoff causes are judged over the next window too.
        transport.transportFailures = 2
        now = 1_250_000_000L
        controller.sampleOnce()
        assertEquals(listOf(6), transport.resizes)
        now = 2_000_000_000L
        controller.sampleOnce()
        assertEquals(listOf(6, 3), transport.resizes)
    }
}
