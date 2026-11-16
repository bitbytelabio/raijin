package io.bitbytelab.raijin.graphql

import kotlin.test.Test
import kotlin.test.assertFailsWith

class ReachabilityGuardTest {

    @Test
    fun `a first request without a response means the target is unreachable`() {
        val guard = ReachabilityGuard()
        assertFailsWith<TargetUnreachableException> { guard.record(0) }
    }

    @Test
    fun `any HTTP status counts as an answer, including errors`() {
        val guard = ReachabilityGuard()
        listOf(200, 400, 404, 500, 502).forEach { guard.record(it) }
    }

    @Test
    fun `isolated failures after an answer are tolerated`() {
        val guard = ReachabilityGuard(maxConsecutiveFailures = 3)
        guard.record(200)
        repeat(10) {
            guard.record(0)
            guard.record(0)
            guard.record(200) // an answer resets the count
        }
    }

    @Test
    fun `consecutive failures after an answer end the run at the limit`() {
        val guard = ReachabilityGuard(maxConsecutiveFailures = 3)
        guard.record(200)
        guard.record(0)
        guard.record(0)
        assertFailsWith<TargetUnreachableException> { guard.record(0) }
    }
}
