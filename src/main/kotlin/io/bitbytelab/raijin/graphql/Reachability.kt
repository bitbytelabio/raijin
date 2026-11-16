package io.bitbytelab.raijin.graphql

/** Raised once a target counts as unreachable (see [ReachabilityGuard]); the multi-request probes stop on it. */
class TargetUnreachableException(message: String) : RuntimeException(message)

/**
 * Decides when a multi-request probe gives up on a target that returns no HTTP response at all
 * (status 0: connection refused, unresolvable host, timeout). Every such send can cost a full
 * timeout, so a dead target must not be asked the remaining dozens or thousands of questions: the
 * first request failing means unreachable, and so do [maxConsecutiveFailures] failures in a row
 * later on. A single dropped probe in between is tolerated, because a WAF may reset the connection
 * on one malformed query while the target itself is fine.
 */
class ReachabilityGuard(private val maxConsecutiveFailures: Int = DEFAULT_MAX_CONSECUTIVE_FAILURES) {
    private var answered = false
    private var consecutiveFailures = 0

    /**
     * Records the HTTP status of one response (0 = none came back). Throws
     * [TargetUnreachableException] when the target is given up on.
     */
    fun record(status: Int) {
        if (status != 0) {
            answered = true
            consecutiveFailures = 0
            return
        }
        consecutiveFailures++
        if (!answered) throw TargetUnreachableException("the first request got no HTTP response")
        if (consecutiveFailures >= maxConsecutiveFailures) {
            throw TargetUnreachableException("$consecutiveFailures consecutive requests got no HTTP response")
        }
    }

    companion object {
        const val DEFAULT_MAX_CONSECUTIVE_FAILURES = 3
    }
}
