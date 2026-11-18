package io.bitbytelab.raijin.recon

import io.bitbytelab.raijin.core.ProbeResult
import kotlin.math.max
import kotlin.math.min
import kotlin.random.Random

/**
 * Requests a list of paths and keeps the ones the target treats differently from paths that do
 * not exist.
 *
 * What "does not exist" looks like is learned first from made-up paths of several lengths and
 * shapes ([Soft404.calibrationPaths]), so a target that answers 200 to everything, repeats the
 * requested path in its not-found page, or redirects every unknown path yields no finds. A rate
 * limit is waited out and the pace slowed; when it persists, or a WAF starts answering for the
 * target, the scan stops and says where, instead of reporting the block page as content.
 */
class ContentDiscovery(
    private val fetch: Fetch,
    private val random: Random = Random.Default,
    private val sleep: (Long) -> Unit = { Thread.sleep(it) },
) {
    /** GETs one path (leading slash included); null when the target gave no response. */
    fun interface Fetch {
        fun get(path: String): ProbeResult?
    }

    /** A path worth reporting; [index] is its position in the list given to [run]. */
    data class Found(val index: Int, val path: String, val status: Int, val length: Int, val location: String?)

    /**
     * @param tested paths whose answer is settled, counted from the start of the list. When [stopped] is set, the scan is to
     *   continue from index [tested]: the first path not asked for, or the first one a block answered for.
     * @param wildcard the target answered a made-up path with a success status.
     * @param blocked paths answered by a WAF / bot-protection page ([blockedBy]), which says nothing about them.
     * @param catchAllDirectories directories (or `/` for the whole site) found mid-scan to answer any path alike.
     * @param droppedAsCatchAll finds withdrawn because a made-up sibling got the same answer.
     * @param throttled rate-limit responses received.
     */
    class Outcome(
        val error: String?,
        val calibration: List<PathFingerprint>,
        val wildcard: Boolean,
        val found: List<Found>,
        val tested: Int,
        val requests: Int,
        val stopped: String?,
        val blockedBy: String?,
        val blocked: List<String>,
        val catchAllDirectories: List<String>,
        val droppedAsCatchAll: Int,
        val unanswered: Int,
        val throttled: Int,
    )

    private class Hit(val index: Int, val fingerprint: PathFingerprint, val location: String?)

    private val profile = Soft404Profile()
    private val calibration = ArrayList<PathFingerprint>()
    private val found = ArrayList<Hit>()
    private val streak = ArrayList<Hit>()
    private val blocked = ArrayList<String>()
    private val catchAll = LinkedHashSet<String>()
    private var requests = 0
    private var throttled = 0
    private var unanswered = 0
    private var dropped = 0
    private var calm = 0
    private var paceMs = 0L
    private var backoffSpentMs = 0L
    private var stopped: String? = null
    private var blockedBy: String? = null

    /** Where to continue from when a block ended the scan: the first path the block answered for. */
    private var resumeFrom: Int? = null

    fun run(paths: List<String>): Outcome {
        val targets = paths.map { if (it.startsWith("/")) it else "/$it" }

        var blockPages = 0
        for (path in Soft404.calibrationPaths(targets, random)) {
            val response = request(path)
            if (stopped != null) return outcome(null, 0)
            if (response == null) continue
            val waf = BlockSignals.blockedBy(response)
            if (waf != null) {
                blockPages++
                blockedBy = waf
            }
            val sample = Soft404.fingerprint(path, response)
            calibration.add(sample)
            profile.add(Soft404.SITE, sample)
        }
        if (calibration.isEmpty()) return outcome("Target did not answer any calibration request", 0)
        if (blockPages == calibration.size) {
            // Every made-up path got a block page: no answer says anything about its path.
            stopped = STOP_BLOCKED
            return outcome(null, 0)
        }

        var index = 0
        var silent = 0
        var blockRun = 0
        var blockRunStart = 0
        var rewinds = 0
        while (index < targets.size && stopped == null) {
            val path = targets[index]
            val response = request(path)
            if (stopped != null) break
            index++
            if (response == null) {
                unanswered++
                if (++silent >= MAX_SILENT) {
                    stopped = STOP_NO_RESPONSE
                    // Continue from the first path of the silent run: none of them got an answer.
                    resumeFrom = index - silent
                }
                continue
            }
            silent = 0
            val waf = BlockSignals.blockedBy(response)
            if (waf != null) {
                blockedBy = waf
                blocked.add(path)
                streak.clear()
                if (blockRun == 0) blockRunStart = index - 1
                if (++blockRun >= BLOCK_RUN) {
                    blockRun = 0
                    if (!stillServed() && stopped == null) {
                        stopped = STOP_BLOCKED
                        resumeFrom = blockRunStart
                    }
                }
                continue
            }
            blockRun = 0
            val fingerprint = Soft404.fingerprint(path, response)
            // A 404 is the plain "not there", unless made-up paths get a success: then it is the odd one out.
            if (profile.matches(fingerprint) || (fingerprint.status == 404 && !profile.wildcard)) {
                streak.clear()
                continue
            }
            val hit = Hit(index - 1, fingerprint, response.header("location"))
            found.add(hit)
            val resumeAt = checkStreak(hit, rewinds < MAX_REWINDS)
            if (resumeAt != null) {
                index = resumeAt
                rewinds++
            }
        }
        return outcome(null, resumeFrom ?: index)
    }

    /**
     * Several consecutive paths answered alike are either real, or a not-found answer the
     * calibration never saw: a block that began mid-scan, or a directory that returns 403 for
     * anything under it. A made-up path tells which: one at the top of the site for the first,
     * one next to the paths for the second. Returns the index to scan again from when the paths
     * were only refused for a moment, else null.
     */
    private fun checkStreak(hit: Hit, mayRewind: Boolean): Int? {
        val last = streak.lastOrNull()
        if (last != null && (hit.index != last.index + 1 || !last.fingerprint.sameAs(hit.fingerprint))) streak.clear()
        streak.add(hit)
        if (streak.size < STREAK) return null
        val members = streak.toList()
        streak.clear()

        val anywherePath = "/" + ProbeText.token(random, 12)
        val anywhere = request(anywherePath)?.let { Soft404.fingerprint(anywherePath, it) }
        if (anywhere != null && anywhere.sameAs(hit.fingerprint)) {
            // A path that cannot exist gets the same answer anywhere, so these were not finds.
            found.removeAll(members.toSet())
            if (!refuses(anywhere.status)) {
                learn(Soft404.SITE, anywhere, members)
                return null
            }
            // The site now refuses what it answered normally during calibration. Give it a moment.
            sleep(BLOCK_BACKOFF_MS)
            val retryPath = "/" + ProbeText.token(random, 12)
            val retry = request(retryPath)
            if (retry != null && mayRewind && !Soft404.fingerprint(retryPath, retry).sameAs(anywhere)) return members.first().index
            dropped += members.size
            if (stopped == null) {
                stopped = STOP_BLOCKED
                resumeFrom = members.first().index
            }
            return null
        }

        val directory = Soft404.directoryOf(hit.fingerprint.path)
        if (directory == Soft404.SITE || members.any { Soft404.directoryOf(it.fingerprint.path) != directory }) return null
        val siblingPath = Soft404.madeUpSibling(hit.fingerprint.path, random)
        val sibling = request(siblingPath)?.let { Soft404.fingerprint(siblingPath, it) } ?: return null
        if (!sibling.sameAs(hit.fingerprint)) return null
        // Whatever is asked for in this directory gets this answer.
        found.removeAll(members.toSet())
        learn(directory, sibling, members)
        return null
    }

    /** Records the answer [members] and the made-up path [sample] share as the not-found answer under [scope]. */
    private fun learn(scope: String, sample: PathFingerprint, members: List<Hit>) {
        dropped += members.size
        profile.add(scope, sample)
        members.forEach { profile.add(scope, it.fingerprint) }
        catchAll.add(scope)
    }

    /** After a run of block pages: does a made-up path still get the target's own answer? */
    private fun stillServed(): Boolean {
        val first = request("/" + ProbeText.token(random, 12)) ?: return true
        if (BlockSignals.blockedBy(first) == null) return true
        sleep(BLOCK_BACKOFF_MS)
        val second = request("/" + ProbeText.token(random, 12)) ?: return false
        return BlockSignals.blockedBy(second) == null
    }

    private fun refuses(status: Int): Boolean = status == 401 || status == 403 || status == 429 || status >= 500

    /** One GET, waiting out a rate limit and slowing down after it; null without a response or once [stopped] is set. */
    private fun request(path: String): ProbeResult? {
        var attempt = 0
        while (true) {
            if (paceMs > 0) sleep(paceMs)
            requests++
            val response = try { fetch.get(path) } catch (_: Exception) { null }
            if (response == null || response.status <= 0) return null
            val delay = BlockSignals.throttleDelayMs(response, attempt)
            if (delay == null) {
                // The pace eases off again once the target has gone a while without complaining.
                if (paceMs > 0 && ++calm >= CALM_REQUESTS) {
                    calm = 0
                    paceMs = if (paceMs <= MIN_PACE_MS) 0 else paceMs / 2
                }
                return response
            }
            throttled++
            calm = 0
            if (attempt >= MAX_RETRIES || backoffSpentMs + delay > MAX_TOTAL_BACKOFF_MS) {
                stopped = STOP_RATE_LIMITED
                return null
            }
            sleep(delay)
            backoffSpentMs += delay
            paceMs = min(MAX_PACE_MS, max(MIN_PACE_MS, paceMs * 2))
            attempt++
        }
    }

    private fun outcome(error: String?, tested: Int): Outcome = Outcome(
        error = error,
        calibration = calibration,
        wildcard = profile.wildcard,
        found = found.map { Found(it.index, it.fingerprint.path, it.fingerprint.status, it.fingerprint.length, it.location) },
        tested = tested,
        requests = requests,
        stopped = stopped,
        blockedBy = blockedBy,
        blocked = blocked,
        catchAllDirectories = catchAll.toList(),
        droppedAsCatchAll = dropped,
        unanswered = unanswered,
        throttled = throttled,
    )

    companion object {
        const val STOP_RATE_LIMITED = "rate_limited"
        const val STOP_BLOCKED = "blocked"
        const val STOP_NO_RESPONSE = "target_not_responding"

        /** Consecutive like answers in one directory before a made-up sibling is asked for. */
        private const val STREAK = 5

        /** Consecutive block pages before checking whether everything is blocked. */
        private const val BLOCK_RUN = 5
        private const val MAX_SILENT = 5
        private const val MAX_REWINDS = 2
        private const val MAX_RETRIES = 3
        private const val MAX_TOTAL_BACKOFF_MS = 60_000L
        private const val BLOCK_BACKOFF_MS = 5_000L
        private const val MIN_PACE_MS = 250L
        private const val MAX_PACE_MS = 2_000L
        private const val CALM_REQUESTS = 40
    }
}
