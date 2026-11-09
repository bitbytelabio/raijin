package io.bitbytelab.raijin.core

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BehavioralDiffTest {

    @Test
    fun `identical status and body is not changed`() {
        val baseline = ProbeResult(200, "<html>hello world</html>")
        val candidate = ProbeResult(200, "<html>hello world</html>")
        assertFalse(BehavioralDiff.changed(baseline, candidate))
    }

    @Test
    fun `a differing status code is always changed`() {
        val baseline = ProbeResult(404, "not found")
        val candidate = ProbeResult(200, "not found")
        assertTrue(BehavioralDiff.changed(baseline, candidate))
    }

    @Test
    fun `a substantially different body at the same status is changed`() {
        val baseline = ProbeResult(200, "a".repeat(200))
        val candidate = ProbeResult(200, "b".repeat(200))
        assertTrue(BehavioralDiff.changed(baseline, candidate))
    }

    @Test
    fun `minor noise below the similarity threshold is not changed`() {
        val baseline = ProbeResult(200, "the quick brown fox jumps over the lazy dog, request id 1")
        val candidate = ProbeResult(200, "the quick brown fox jumps over the lazy dog, request id 2")
        assertFalse(BehavioralDiff.changed(baseline, candidate))
    }

    @Test
    fun `a byte-length delta beyond the noise threshold is changed even at high similarity`() {
        val baseline = ProbeResult(200, "x".repeat(1000))
        val candidate = ProbeResult(200, "x".repeat(1000) + "y".repeat(50))
        assertTrue(BehavioralDiff.changed(baseline, candidate, noiseThresholdBytes = 10))
    }
}
