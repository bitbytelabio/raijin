package io.bitbytelab.raijin.recon

import io.bitbytelab.raijin.core.BehavioralDiff
import io.bitbytelab.raijin.core.ParamMinerWordlists.Entry
import io.bitbytelab.raijin.core.ProbeResult
import kotlin.math.max
import kotlin.math.min
import kotlin.random.Random

/**
 * Marker values for one probe run. Every value sent gets its own canary under a prefix that is
 * random per run, so a response names exactly the inputs it echoes, and a value stored by an
 * earlier run (or served from a cache) is never mistaken for an echo of this request.
 */
class Canaries(random: Random) {
    /** What every canary of this run starts with. */
    val prefix: String = "zq" + ProbeText.token(random, PREFIX_TOKEN)
    private val upperPrefix = prefix.uppercase()
    private var issued = 0

    fun next(): String = prefix + (issued++).toString(36).padStart(SERIAL_WIDTH, '0')

    /** How often each canary occurs in [text]; keys are canaries as issued, even when echoed in upper case. */
    fun counts(text: String): Map<String, Int> {
        var at = find(text, 0)
        if (at < 0) return emptyMap()
        val counts = HashMap<String, Int>()
        while (at >= 0) {
            val end = at + LENGTH
            if (end <= text.length) {
                val canary = text.substring(at, end).lowercase()
                counts[canary] = (counts[canary] ?: 0) + 1
            }
            at = find(text, at + prefix.length)
        }
        return counts
    }

    /**
     * [text] with every canary of this run removed. Given [names] (canary to the name it was sent
     * under), a name written right before its canary goes too, so an echoed `name=value` pair
     * leaves nothing that differs from one request to the next.
     */
    fun strip(text: String, names: Map<String, String>? = null): String {
        var at = find(text, 0)
        if (at < 0) return text
        val out = StringBuilder(text.length)
        var from = 0
        while (at >= 0) {
            val end = min(at + LENGTH, text.length)
            var cut = at
            if (names != null) {
                val name = names[text.substring(at, end).lowercase()]
                if (name != null) {
                    val start = nameStart(text, at, from, name)
                    if (start >= 0) cut = start
                }
            }
            out.append(text, from, cut)
            from = end
            at = find(text, from)
        }
        return out.append(text, from, text.length).toString()
    }

    /** True when [text] holds a canary right after the name it was sent under (see [strip]). */
    fun echoesPairs(text: String, names: Map<String, String>): Boolean {
        var at = find(text, 0)
        while (at >= 0) {
            val end = at + LENGTH
            if (end <= text.length) {
                val name = names[text.substring(at, end).lowercase()]
                if (name != null && nameStart(text, at, 0, name) >= 0) return true
            }
            at = find(text, at + prefix.length)
        }
        return false
    }

    /** Where [name] starts when it sits at most [MAX_PAIR_GAP] characters (`=`, `%3D`, `":"`) before the canary at [canaryAt]. */
    private fun nameStart(text: String, canaryAt: Int, notBefore: Int, name: String): Int {
        for (gap in 0..MAX_PAIR_GAP) {
            val start = canaryAt - gap - name.length
            if (start < notBefore) return -1
            if (text.regionMatches(start, name, 0, name.length, ignoreCase = true)) return start
        }
        return -1
    }

    /** Next canary at or after [from]: as sent, or upper-cased as some servers echo values. */
    private fun find(text: String, from: Int): Int {
        val lower = text.indexOf(prefix, from)
        val upper = text.indexOf(upperPrefix, from)
        return if (lower < 0) upper else if (upper < 0) lower else min(lower, upper)
    }

    companion object {
        private const val PREFIX_TOKEN = 6
        private const val SERIAL_WIDTH = 5
        private const val MAX_PAIR_GAP = 5

        /** Length of every canary. */
        const val LENGTH = 2 + PREFIX_TOKEN + SERIAL_WIDTH
    }
}

/**
 * Finds the parameter names a target reacts to, the way Param Miner does: many candidates per
 * request, and a binary search inside a bucket only when its response stands out.
 *
 * Each value carries its own canary, so an echoed value names its parameter directly. A response
 * is judged against repeated baseline responses to requests of the same size filled with
 * made-up names, then against a control (the same request with a made-up name in place of each
 * candidate), so whatever the page varies on its own (tokens, timestamps, an echo of the query
 * string, an error for any unknown name) is not reported as the effect of a parameter. A change
 * is credited to one name only after it repeats with that name alone and stays away without it.
 */
class ParamMiner(
    private val candidates: List<Entry>,
    private val config: Config,
    private val transport: Transport,
) {
    /**
     * Sends one request carrying exactly these `name to value` inputs, and the transport's
     * cache-buster query parameter when [cacheBuster] is set; null when the target gave no response.
     */
    fun interface Transport {
        fun send(params: List<Pair<String, String>>, cacheBuster: Boolean): ProbeResult?
    }

    /**
     * @param host target host, for `%h` in value templates.
     * @param reflection report names whose value is echoed.
     * @param diff report names that change the response without being echoed.
     * @param bucketSize candidates per request to start from; halved while the target rejects it.
     * @param maxRequests hard cap on requests; the run stops there and says how far it got.
     * @param ignoreNameCase names differing only in case are the same input (headers).
     * @param cacheBuster the transport can add a cache-buster to every request; the run leaves it
     *   off when the target rejects it.
     */
    class Config(
        val host: String,
        val reflection: Boolean,
        val diff: Boolean,
        val bucketSize: Int,
        val maxRequests: Int,
        val ignoreNameCase: Boolean = false,
        val cacheBuster: Boolean = false,
        val baselineSamples: Int = 3,
        val random: Random = Random.Default,
        val sleep: (Long) -> Unit = { Thread.sleep(it) },
    )

    /** A name the target reacts to: where its value came back, and how the response changed. */
    data class Hit(val candidate: Entry, val reflectedIn: List<String>, val diff: List<String>)

    /**
     * @param tested candidates fully examined, counted from the start of the list.
     * @param responseChanging names that changed the response in a run that only reports echoes.
     * @param echoesValues the target echoes values of names it does not know.
     * @param echoesPairs the target echoes whole `name=value` pairs (the query string, the body).
     * @param rejectsUnknownNames any unknown name changes the status, so candidates went one per request.
     * @param stopped why the run ended before the list did, or null.
     * @param unanswered candidates whose request got no response, so nothing is known about them.
     * @param busterRejectedStatus the status the plain request got with the cache-buster when the
     *   buster alone changed it (and the plain request without it got another); the run then went
     *   without the buster. Null when it kept the buster or never had one.
     */
    class Outcome(
        val error: String?,
        val hits: List<Hit>,
        val responseChanging: List<Entry>,
        val tested: Int,
        val requests: Int,
        val bucketSize: Int,
        val baseline: BehavioralDiff.Baseline?,
        val echoesValues: Boolean,
        val echoesPairs: Boolean,
        val rejectsUnknownNames: Boolean,
        val stopped: String?,
        val unanswered: List<Entry>,
        val canaryPrefix: String,
        val busterRejectedStatus: Int? = null,
    )

    /** One input of a request: a candidate ([index] into the list) or a made-up name ([DECOY]). */
    private class Slot(val index: Int, val name: String, val canary: String, val value: String)

    /** A request's inputs with its response as received and, in [normalized], without what the request itself put there. */
    private class Observation(val slots: List<Slot>, val raw: ProbeResult) {
        lateinit var normalized: ProbeResult
    }

    /**
     * Candidates sent together. [standIns] holds, per candidate, the made-up name of the same
     * length that takes its place in a control; [padding] fills the request up to the bucket
     * size. Both stay the same for every request of the bucket, so two of its requests differ
     * only in the candidates they carry.
     */
    private class Bucket(val indices: List<Int>, val standIns: List<String>, val padding: List<String>)

    private val canaries = Canaries(config.random)
    private var requests = 0
    private var failures = 0
    private var rebaselines = 0
    private val unanswered = ArrayList<Int>()
    private var noise = 0
    private var stopped: String? = null
    private var bucketSize = 0
    private var strict = false
    private var busted = config.cacheBuster
    private var busterRejectedStatus: Int? = null
    private var mirrors = false
    private var profile: BehavioralDiff.Baseline? = null

    // How often a made-up input comes back on its own: the level an echo has to exceed to mean something.
    private var valueEcho = 0
    private var headerEcho = 0
    private var nameEcho = 0

    private val reflected = LinkedHashMap<Int, List<String>>()
    private val changed = LinkedHashMap<Int, List<String>>()
    private val changing = LinkedHashSet<Int>()
    private val singles = HashMap<Int, Observation?>()

    fun run(): Outcome {
        if (candidates.isEmpty()) return outcome(null, 0)

        // The cache-buster is one more query parameter the target does not know. A target that
        // rejects unknown parameters rejects every request carrying it, so the run leaves it off.
        var plain = send(emptyList())
        if (busted && plain != null) plain = withoutRejectedBuster(plain)

        // One unknown name against none: a target that answers the two differently (an API that
        // rejects unknown fields) can only be mined one name per request.
        val reference = listOfNotNull(send(decoys(1)), send(decoys(1)))
        if (reference.isEmpty()) return outcome(baselineError(), 0)
        val referenceStatus = reference.map { it.raw.status }.distinct().singleOrNull()
        strict = plain != null && referenceStatus != null && plain.raw.status != referenceStatus &&
            repeats(plain.raw.status, referenceStatus)

        // The largest bucket the target takes without rejecting the request for its size.
        var size = if (strict) 1 else min(config.bucketSize, candidates.size).coerceAtLeast(1)
        var sample = send(decoys(size))
        while (size > 1 && stopped == null && rejected(sample, referenceStatus)) {
            size = max(1, size / 2)
            sample = send(decoys(size))
        }
        if (sample == null) return outcome(baselineError(), 0)
        bucketSize = size

        val samples = mutableListOf(sample)
        while (samples.size < max(2, config.baselineSamples)) samples.add(send(decoys(size)) ?: break)
        if (samples.size < 2) return outcome(baselineError(), 0)
        establish(samples)

        var tested = 0
        for (bucket in buckets(size)) {
            if (stopped != null) break
            process(bucket)
            singles.clear()
            if (stopped == null) tested += bucket.indices.size
        }
        return outcome(null, tested)
    }

    /**
     * The plain request as the run goes on sending it: [withBuster] itself, or the plain request
     * without the cache-buster when the buster alone turns a page the target serves (2xx, or a
     * redirect) into a rejection or a redirect. After that no request carries the buster. Both
     * statuses have to repeat, so a passing error does not cost the run its cache isolation, and
     * a stale error served from a cache for the plain URL never replaces a fresh page.
     */
    private fun withoutRejectedBuster(withBuster: Observation): Observation {
        if (withBuster.raw.status in 200..299) return withBuster
        val bare = send(emptyList(), cacheBuster = false) ?: return withBuster
        if (bare.raw.status >= 400 || bare.raw.status == withBuster.raw.status) return withBuster
        val bustedAgain = send(emptyList(), cacheBuster = true) ?: return withBuster
        if (bustedAgain.raw.status != withBuster.raw.status) return bustedAgain
        val bareAgain = send(emptyList(), cacheBuster = false) ?: return bustedAgain
        if (bareAgain.raw.status != bare.raw.status) return bustedAgain
        busted = false
        busterRejectedStatus = withBuster.raw.status
        return bareAgain
    }

    /** Whether the plain request and a one-decoy request get [plainStatus] and [decoyStatus] a second time. */
    private fun repeats(plainStatus: Int, decoyStatus: Int): Boolean {
        val plain = send(emptyList()) ?: return false
        val decoy = send(decoys(1)) ?: return false
        return plain.raw.status == plainStatus && decoy.raw.status == decoyStatus
    }

    private fun rejected(sample: Observation?, referenceStatus: Int?): Boolean =
        sample == null || (referenceStatus != null && sample.raw.status != referenceStatus && sample.raw.status >= 400)

    private fun process(bucket: Bucket) {
        val all = bucket.indices.toSet()
        val first = send(slots(bucket, all))
        if (first == null) {
            if (stopped == null) unanswered.addAll(bucket.indices)
            return
        }
        var observation: Observation = first
        if (bucket.indices.size == 1) {
            singles[bucket.indices[0]] = observation
            noteReflections(bucket, observation)
        }
        if (deviation(observation).isEmpty()) {
            noteReflections(bucket, observation)
            return
        }

        // The response stands out. The same request with a made-up name in place of every
        // candidate shows whether the candidates made it so.
        var control = send(slots(bucket, emptySet())) ?: return
        if (disturbed(control)) {
            if (!recover(control.raw)) return
            singles.clear()
            observation = send(slots(bucket, all)) ?: return
            if (deviation(observation).isEmpty()) {
                noteReflections(bucket, observation)
                return
            }
            control = send(slots(bucket, emptySet())) ?: return
            if (disturbed(control)) {
                stopped = STOP_UNSTABLE
                return
            }
        }
        learn(control)
        if (pairDiff(control, observation, bucket.indices).isEmpty()) {
            noise++
            noteReflections(bucket, observation)
            return
        }
        // The same deviation twice before the bucket is taken apart: once is often the page itself.
        val again = send(slots(bucket, all)) ?: return
        if (pairDiff(control, again, bucket.indices).isEmpty() || pairDiff(observation, again, emptyList()).isNotEmpty()) {
            noise++
            noteReflections(bucket, again)
            return
        }

        val culprits = ArrayList<Int>()
        bisect(bucket, bucket.indices, control, culprits)
        if (stopped != null) return
        if (culprits.isEmpty()) {
            noteReflections(bucket, observation)
            return
        }
        if (culprits.size == bucket.indices.size) return
        // A name that changes the whole response hides (or fakes) the echoes of the names sent
        // with it, so echoes are read from the bucket without those names.
        val rest = send(slots(bucket, all - culprits.toSet())) ?: return
        noteReflections(bucket, rest)
    }

    /** Narrows [group], whose presence makes the response differ from [control], down to single names. */
    private fun bisect(bucket: Bucket, group: List<Int>, control: Observation, culprits: MutableList<Int>) {
        if (stopped != null) return
        if (group.size == 1) {
            confirm(bucket, group[0], control, culprits)
            return
        }
        val left = group.subList(0, group.size / 2)
        val right = group.subList(group.size / 2, group.size)
        val leftObservation = send(slots(bucket, left.toSet())) ?: return
        if (pairDiff(control, leftObservation, left).isEmpty()) {
            // The left half alone changes nothing, so the change comes from the right half.
            bisect(bucket, right, control, culprits)
            return
        }
        bisect(bucket, left, control, culprits)
        val rightObservation = send(slots(bucket, right.toSet())) ?: return
        if (pairDiff(control, rightObservation, right).isNotEmpty()) bisect(bucket, right, control, culprits)
    }

    /**
     * Credits a change to candidate [index] when the candidate alone reproduces it in every one
     * of [confirmRounds] further rounds, each against a fresh control, and those responses agree
     * with each other.
     */
    private fun confirm(bucket: Bucket, index: Int, control: Observation, culprits: MutableList<Int>) {
        val kept = listOf(index)
        val first = single(bucket, index) ?: return
        if (pairDiff(control, first, kept).isEmpty()) {
            noise++
            return
        }
        if (!config.diff) {
            changing.add(index)
            culprits.add(index)
            return
        }
        val seen = mutableListOf(first)
        var lastControl = control
        repeat(confirmRounds()) {
            val fresh = send(slots(bucket, emptySet())) ?: return
            if (disturbed(fresh)) {
                recover(fresh.raw)
                return
            }
            learn(fresh)
            val again = send(slots(bucket, setOf(index))) ?: return
            val reproduced = seen.none { pairDiff(fresh, it, kept).isEmpty() } && pairDiff(fresh, again, kept).isNotEmpty()
            if (!reproduced || seen.any { pairDiff(it, again, emptyList()).isNotEmpty() }) {
                noise++
                return
            }
            seen.add(again)
            lastControl = fresh
        }
        changed[index] = pairDiff(lastControl, first, kept)
        culprits.add(index)
    }

    /** More rounds once the target has shown that its responses move on their own. */
    private fun confirmRounds(): Int {
        val baseline = profile
        val moves = noise > 0 || baseline == null || baseline.similarityFloor < 100.0 || baseline.minLength != baseline.maxLength
        return if (moves) NOISY_CONFIRM_ROUNDS else CONFIRM_ROUNDS
    }

    /** The response to candidate [index] with every other candidate of its bucket replaced by its stand-in. */
    private fun single(bucket: Bucket, index: Int): Observation? {
        if (singles.containsKey(index)) return singles[index]
        val observation = send(slots(bucket, setOf(index)))
        singles[index] = observation
        if (observation != null) noteReflections(bucket, observation)
        return observation
    }

    private fun noteReflections(bucket: Bucket, observation: Observation) {
        if (!config.reflection) return
        val found = reflections(observation)
        if (found.isEmpty()) return
        val alone = observation.slots.count { it.index != DECOY } == 1
        for ((index, where) in found) {
            if (index in reflected) continue
            // Echoed among other candidates: ask again with this one alone before crediting it.
            if (alone) {
                reflected[index] = where
            } else {
                single(bucket, index)
            }
        }
    }

    /** Candidates of [observation] whose canary came back more often than a made-up input's does. */
    private fun reflections(observation: Observation): Map<Int, List<String>> {
        val body = canaries.counts(observation.raw.body)
        val headers = observation.raw.headers.mapValues { canaries.counts(it.value) }.filterValues { it.isNotEmpty() }
        if (body.isEmpty() && headers.isEmpty()) return emptyMap()
        val out = LinkedHashMap<Int, List<String>>()
        for (slot in observation.slots) {
            if (slot.index == DECOY) continue
            val where = ArrayList<String>(1)
            if ((body[slot.canary] ?: 0) > valueEcho) where.add("body")
            for ((name, counts) in headers) if ((counts[slot.canary] ?: 0) > headerEcho) where.add("header:$name")
            if (where.isNotEmpty()) out[slot.index] = where
        }
        return out
    }

    // --- baseline -------------------------------------------------------------------------

    private fun establish(samples: List<Observation>) {
        valueEcho = 0
        headerEcho = 0
        nameEcho = 0
        samples.forEach(::noteEchoes)
        mirrors = samples.any { sample -> canaries.echoesPairs(sample.raw.body, sample.slots.associate { it.canary to it.name }) }
        samples.forEach { it.normalized = normalize(it) }
        profile = BehavioralDiff.baseline(samples.map { it.normalized })
    }

    /** Takes a control (a request of made-up names only) as one more baseline response. */
    private fun learn(control: Observation) {
        profile = profile?.plus(control.normalized)
        noteEchoes(control)
    }

    private fun noteEchoes(observation: Observation) {
        val raw = observation.raw
        valueEcho = max(valueEcho, canaries.counts(raw.body).values.maxOrNull() ?: 0)
        for (value in raw.headers.values) headerEcho = max(headerEcho, canaries.counts(value).values.maxOrNull() ?: 0)
        for (slot in observation.slots) nameEcho = max(nameEcho, occurrences(raw.body, slot.name))
    }

    /** The response without this request's canaries and, where the target echoes pairs, without their names. */
    private fun normalize(observation: Observation): ProbeResult {
        val raw = observation.raw
        val names = if (mirrors) observation.slots.associate { it.canary to it.name } else null
        val signals = raw.headers.filterKeys { it in BehavioralDiff.SIGNAL_HEADERS }.mapValues { canaries.strip(it.value, names) }
        return ProbeResult(raw.status, canaries.strip(raw.body, names), signals)
    }

    private fun deviation(observation: Observation): List<String> =
        profile?.let { BehavioralDiff.diff(it, observation.normalized) }.orEmpty()

    /** How [observation] differs from [control]; [kept] are the candidates only [observation] carried. */
    private fun pairDiff(control: Observation, observation: Observation, kept: List<Int>): List<String> {
        val baseline = profile ?: return emptyList()
        // A name shorter than the shortest stand-in is echoed shorter than the stand-in was.
        val slack = if (nameEcho == 0) 0 else nameEcho * kept.sumOf { max(0, MIN_DECOY_LENGTH - candidates[it].name.length) }
        return BehavioralDiff.diff(baseline, control.normalized, observation.normalized, slack)
    }

    /** True when a request of made-up names no longer gets the baseline status: the target changed, not a candidate. */
    private fun disturbed(control: Observation): Boolean {
        val status = profile?.status ?: return false
        return control.raw.status != status
    }

    /**
     * Samples the baseline again after a control came back with another status. Carries on when
     * the target is back to its old status (a passing rate limit); otherwise the run stops, since
     * every later response would be compared against the wrong thing.
     */
    private fun recover(disturbance: ProbeResult): Boolean {
        if (++rebaselines > MAX_REBASELINES) {
            stopped = STOP_UNSTABLE
            return false
        }
        val before = profile?.status
        if (disturbance.status in THROTTLE_STATUSES) config.sleep(retryDelayMs(disturbance))
        val samples = ArrayList<Observation>()
        repeat(max(2, config.baselineSamples)) { send(decoys(bucketSize))?.let(samples::add) }
        if (samples.size < 2) {
            if (stopped == null) stopped = STOP_NO_RESPONSE
            return false
        }
        val statuses = samples.map { it.raw.status }.distinct()
        if (statuses.size != 1 || statuses[0] != before) {
            stopped = if (statuses.any { it in THROTTLE_STATUSES }) STOP_RATE_LIMITED else STOP_BASELINE_CHANGED
            return false
        }
        establish(samples)
        return true
    }

    private fun retryDelayMs(response: ProbeResult): Long {
        val seconds = response.header("retry-after")?.trim()?.toLongOrNull()
        return if (seconds == null) DEFAULT_BACKOFF_MS else (seconds * 1000L).coerceIn(0L, MAX_BACKOFF_MS)
    }

    // --- requests -------------------------------------------------------------------------

    private fun send(slots: List<Slot>, cacheBuster: Boolean = busted): Observation? {
        if (stopped != null) return null
        if (requests >= config.maxRequests) {
            stopped = STOP_BUDGET
            return null
        }
        requests++
        val raw = try { transport.send(slots.map { it.name to it.value }, cacheBuster) } catch (_: Exception) { null }
        if (raw == null || raw.status <= 0) {
            if (++failures >= MAX_FAILURES) stopped = STOP_NO_RESPONSE
            return null
        }
        failures = 0
        val observation = Observation(slots, raw)
        observation.normalized = normalize(observation)
        return observation
    }

    /** The bucket's request with the candidates in [keep] and the stand-in for every other one. */
    private fun slots(bucket: Bucket, keep: Set<Int>): List<Slot> {
        val out = ArrayList<Slot>(bucket.indices.size + bucket.padding.size)
        for ((position, index) in bucket.indices.withIndex()) {
            val entry = candidates[index]
            val canary = canaries.next()
            val value = entry.value(canary, config.host)
            out.add(if (index in keep) Slot(index, entry.name, canary, value) else Slot(DECOY, bucket.standIns[position], canary, value))
        }
        for (name in bucket.padding) {
            val canary = canaries.next()
            out.add(Slot(DECOY, name, canary, canary))
        }
        return out
    }

    private fun bucketOf(indices: List<Int>, size: Int): Bucket {
        val used = HashSet<String>()
        for (index in indices) used.add(key(candidates[index].name))
        val standIns = indices.map { decoy(candidates[it].name.length, used) }
        val padding = List(size - indices.size) { decoy(config.random.nextInt(MIN_PADDING_LENGTH, MAX_PADDING_LENGTH + 1), used) }
        return Bucket(indices, standIns, padding)
    }

    /** A request of [count] made-up names, new ones on every call. */
    private fun decoys(count: Int): List<Slot> = slots(bucketOf(emptyList(), count), emptySet())

    /** A random name of about [length] characters, not yet in [used]. */
    private fun decoy(length: Int, used: MutableSet<String>): String {
        while (true) {
            val name = ProbeText.token(config.random, max(length, MIN_DECOY_LENGTH))
            if (used.add(key(name))) return name
        }
    }

    private fun key(name: String): String = if (config.ignoreNameCase) name.lowercase() else name

    /**
     * Candidates in list order, [size] to a request. A bucket closes early rather than carry the
     * same name twice (a list may give one name two value templates).
     */
    private fun buckets(size: Int): List<Bucket> {
        val out = ArrayList<Bucket>()
        var current = ArrayList<Int>(size)
        var keys = HashSet<String>()
        for (index in candidates.indices) {
            val name = key(candidates[index].name)
            if (current.size == size || name in keys) {
                out.add(bucketOf(current, size))
                current = ArrayList(size)
                keys = HashSet()
            }
            current.add(index)
            keys.add(name)
        }
        if (current.isNotEmpty()) out.add(bucketOf(current, size))
        return out
    }

    private fun occurrences(text: String, needle: String): Int {
        var count = 0
        var at = text.indexOf(needle)
        while (at >= 0) {
            count++
            at = text.indexOf(needle, at + needle.length)
        }
        return count
    }

    private fun baselineError(): String = when (stopped) {
        STOP_BUDGET -> "Request budget of ${config.maxRequests} is too small to sample a baseline"
        else -> "Target did not answer the baseline requests"
    }

    private fun outcome(error: String?, tested: Int): Outcome = Outcome(
        error = error,
        hits = (reflected.keys + changed.keys).sorted().map { Hit(candidates[it], reflected[it].orEmpty(), changed[it].orEmpty()) },
        responseChanging = changing.filter { it !in changed }.sorted().map { candidates[it] },
        tested = tested,
        requests = requests,
        bucketSize = bucketSize,
        baseline = profile,
        echoesValues = valueEcho > 0 || headerEcho > 0,
        echoesPairs = mirrors,
        rejectsUnknownNames = strict,
        stopped = stopped,
        unanswered = unanswered.map { candidates[it] },
        canaryPrefix = canaries.prefix,
        busterRejectedStatus = busterRejectedStatus,
    )

    companion object {
        const val STOP_BUDGET = "request_budget"
        const val STOP_NO_RESPONSE = "target_not_responding"
        const val STOP_UNSTABLE = "unstable_baseline"
        const val STOP_RATE_LIMITED = "rate_limited"
        const val STOP_BASELINE_CHANGED = "baseline_changed"

        private const val DECOY = -1
        private const val CONFIRM_ROUNDS = 2
        private const val NOISY_CONFIRM_ROUNDS = 4
        private const val MAX_FAILURES = 3
        private const val MAX_REBASELINES = 3
        private const val DEFAULT_BACKOFF_MS = 3_000L
        private const val MAX_BACKOFF_MS = 10_000L
        private val THROTTLE_STATUSES = setOf(429, 503)

        // A made-up name of three characters or more is not a parameter the application has.
        private const val MIN_DECOY_LENGTH = 3
        private const val MIN_PADDING_LENGTH = 4
        private const val MAX_PADDING_LENGTH = 14
    }
}
