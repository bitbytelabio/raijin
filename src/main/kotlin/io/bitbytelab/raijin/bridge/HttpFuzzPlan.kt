package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.safety.RequestHygiene
import kotlin.math.min

/**
 * Pure, Montoya-free planning logic for [HttpBridge.fuzz] and [HttpBridge.raceCondition]: where a
 * request's injection points are (FUZZ keyword, marker pairs, offset positions) and which requests
 * a Burp Intruder attack type sends for the payload sets it is given.
 *
 * Planning stays at the String level and the caller sends each request as UTF-8, so astral and
 * multi-byte payloads survive; every planned request gets its Content-Length recomputed for those
 * bytes ([withContentLength]).
 */
internal object HttpFuzzPlan {

    private const val FUZZ_KEYWORD = "FUZZ"

    const val KEYWORD_POSITIONS = "fuzz_keyword"
    const val MARKER_POSITIONS = "marker_pairs"
    const val OFFSET_POSITIONS = "offset"

    /** Burp Intruder's attack types. */
    enum class AttackMode(val id: String) {
        /** One payload set; each position in turn takes every payload while the others keep their value. */
        SNIPER("sniper"),

        /** One payload set; every position takes the same payload. */
        BATTERING_RAM("battering_ram"),

        /** One payload set per position, walked in step: request n uses the n-th payload of each set. */
        PITCHFORK("pitchfork"),

        /** One payload set per position; every combination is sent. */
        CLUSTER_BOMB("cluster_bomb");

        companion object {
            val ids: List<String> = entries.map { it.id }

            fun of(id: String?): AttackMode? = entries.firstOrNull { it.id.equals(id?.trim(), ignoreCase = true) }
        }
    }

    /**
     * A request cut at its injection points: `literals[0] + value + literals[1] + ... + literals[n]`.
     * Slot i is the i-th injection point in text order and `positionOf[i]` the caller's number for
     * it (the two differ only for offset positions given out of order).
     *
     * @param positionMode how the injection points were given: [KEYWORD_POSITIONS], [MARKER_POSITIONS] or [OFFSET_POSITIONS].
     * @param baseValues what each position holds while another one is fuzzed.
     */
    class Template(
        val positionMode: String,
        private val literals: List<String>,
        private val positionOf: List<Int>,
        val baseValues: List<String>,
    ) {
        val positions: Int get() = baseValues.size

        /** The request with `values[p]` at position p. */
        fun render(values: List<String>): String = buildString {
            for (slot in positionOf.indices) {
                append(literals[slot])
                append(values[positionOf[slot]])
            }
            append(literals.last())
        }
    }

    /**
     * One request to send.
     *
     * @param request the request text, payloads placed and Content-Length recomputed.
     * @param payloads the payload placed at each position as the caller gave it (before encoding);
     *   null where the position kept its own value.
     * @param position the position being fuzzed in a sniper attack over markers or offsets; 0 for
     *   the FUZZ keyword (every occurrence is replaced) and -1 when every position takes a payload.
     */
    class AttackRequest(val request: String, val payloads: List<String?>, val position: Int) {
        /** The payloads of this request as one line, for reports. */
        val label: String get() = payloads.filterNotNull().distinct().joinToString(" | ")
    }

    /**
     * @param total requests the attack type defines for these payload sets.
     * @param planned requests that will be produced: [total], capped.
     * @param notes what was adjusted on the way (payload sets reused or ignored, the cap).
     * @param requests the requests in the order Intruder sends them, produced on demand.
     */
    class AttackPlan(
        val mode: AttackMode,
        val positionMode: String,
        val positions: Int,
        val total: Long,
        val planned: Long,
        val notes: List<String>,
        val requests: Sequence<AttackRequest>,
    )

    sealed class AttackResult {
        class Ok(val plan: AttackPlan) : AttackResult()
        class Error(val message: String) : AttackResult()
    }

    private sealed class Resolved {
        class Ok(val template: Template) : Resolved()
        class Error(val message: String) : Resolved()
    }

    /**
     * Plans an attack on a request exactly as the caller typed it: the header block's line endings
     * are canonicalized ([RequestHygiene.normalizeCrlf]) and legacy offset [positions] (which index
     * the text as typed) are moved onto the normalized request.
     *
     * Injection points, in this order of precedence: every `FUZZ` keyword, `marker…marker` pairs
     * (default marker `§`), then [positions] as [start, end) offsets. Payload set i belongs to
     * position i; sniper and battering ram use the first set only, and with fewer sets than
     * positions the last set is reused. A sniper attack over the FUZZ keyword replaces every
     * occurrence at once, as this tool always did.
     *
     * @param encode applied to each payload before it is placed.
     * @param maxRequests cap on the requests produced.
     */
    fun planAttack(
        rawRequest: String,
        positions: List<Pair<Int, Int>>?,
        payloadSets: List<List<String>>,
        marker: String?,
        mode: AttackMode = AttackMode.SNIPER,
        encode: (String) -> String = { it },
        maxRequests: Long = Long.MAX_VALUE,
    ): AttackResult {
        if (payloadSets.isEmpty() || payloadSets.any { it.isEmpty() }) {
            return AttackResult.Error("Every payload set needs at least one payload.")
        }
        val normalized = RequestHygiene.normalizeCrlf(rawRequest)
        var mapped = positions
        if (!positions.isNullOrEmpty() && normalized != rawRequest) {
            // Offset mode validates against the text as typed, so errors quote the caller's numbers.
            val offsetMode = !normalized.contains(FUZZ_KEYWORD) && countOccurrences(normalized, effectiveMarker(marker)) == 0
            if (offsetMode) validatePositions(positions, rawRequest.length)?.let { return AttackResult.Error(it) }
            mapped = positions.map { (start, end) ->
                RequestHygiene.adjustedOffset(rawRequest, start) to RequestHygiene.adjustedOffset(rawRequest, end)
            }
        }
        val template = when (val resolved = resolve(normalized, mapped, marker)) {
            is Resolved.Error -> return AttackResult.Error(resolved.message)
            is Resolved.Ok -> resolved.template
        }

        val count = template.positions
        val notes = ArrayList<String>()
        val multiSet = mode == AttackMode.PITCHFORK || mode == AttackMode.CLUSTER_BOMB
        if (!multiSet && payloadSets.size > 1) {
            notes += "${mode.id} uses one payload set: the first of ${payloadSets.size} was used."
        }
        if (multiSet && payloadSets.size < count) {
            notes += "${payloadSets.size} payload set(s) for $count positions: positions ${payloadSets.size + 1}-$count reuse set ${payloadSets.size}."
        }
        if (multiSet && payloadSets.size > count) {
            notes += "${payloadSets.size} payload sets for $count position(s): sets ${count + 1}-${payloadSets.size} were not used."
        }
        val first = payloadSets[0]
        val perPosition = List(count) { payloadSets[min(it, payloadSets.lastIndex)] }
        fun everywhere(payload: String, position: Int): AttackRequest {
            val encoded = encode(payload)
            return AttackRequest(withContentLength(template.render(List(count) { encoded })), List(count) { payload }, position)
        }
        fun combination(raw: List<String>): AttackRequest =
            AttackRequest(withContentLength(template.render(raw.map(encode))), raw, -1)

        val total: Long
        val requests: Sequence<AttackRequest>
        when (mode) {
            AttackMode.SNIPER -> if (template.positionMode == KEYWORD_POSITIONS) {
                total = first.size.toLong()
                requests = first.asSequence().map { everywhere(it, 0) }
            } else {
                total = count.toLong() * first.size
                requests = sequence {
                    for (position in 0 until count) {
                        for (payload in first) {
                            val values = template.baseValues.toMutableList()
                            values[position] = encode(payload)
                            val placed = MutableList<String?>(count) { null }
                            placed[position] = payload
                            yield(AttackRequest(withContentLength(template.render(values)), placed, position))
                        }
                    }
                }
            }
            AttackMode.BATTERING_RAM -> {
                total = first.size.toLong()
                requests = first.asSequence().map { everywhere(it, -1) }
            }
            AttackMode.PITCHFORK -> {
                val steps = perPosition.minOf { it.size }
                total = steps.toLong()
                requests = (0 until steps).asSequence().map { step -> combination(perPosition.map { it[step] }) }
            }
            AttackMode.CLUSTER_BOMB -> {
                total = perPosition.fold(1L) { product, set -> saturatedProduct(product, set.size.toLong()) }
                requests = sequence {
                    // Position 0 turns fastest, the last position slowest, as in Intruder.
                    val odometer = IntArray(count)
                    while (true) {
                        yield(combination(List(count) { perPosition[it][odometer[it]] }))
                        var wheel = 0
                        while (wheel < count) {
                            odometer[wheel]++
                            if (odometer[wheel] < perPosition[wheel].size) break
                            odometer[wheel] = 0
                            wheel++
                        }
                        if (wheel == count) break
                    }
                }
            }
        }

        val planned = min(total, maxRequests.coerceAtLeast(1))
        if (planned < total) notes += "The attack defines $total requests; only the first $planned are sent (max_requests)."
        val capped = if (planned < total) requests.take(planned.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()) else requests
        return AttackResult.Ok(AttackPlan(mode, template.positionMode, count, total, planned, notes, capped))
    }

    /** `a * b` without overflow: [Long.MAX_VALUE] once the product no longer fits. */
    private fun saturatedProduct(a: Long, b: Long): Long =
        if (a != 0L && b > Long.MAX_VALUE / a) Long.MAX_VALUE else a * b

    /** Finds the injection points of [baseRequest] (already CRLF-normalized, offsets mapped onto it). */
    private fun resolve(baseRequest: String, positions: List<Pair<Int, Int>>?, marker: String?): Resolved {
        val effectiveMarker = effectiveMarker(marker)
        val hasFuzzKeyword = baseRequest.contains(FUZZ_KEYWORD)
        val markerCount = countOccurrences(baseRequest, effectiveMarker)
        if (positions.isNullOrEmpty() && !hasFuzzKeyword && markerCount > 0 && markerCount % 2 != 0) {
            return Resolved.Error(
                "Odd number ($markerCount) of '$effectiveMarker' markers; every injection point needs a closing marker " +
                    "(e.g. ${effectiveMarker}value${effectiveMarker})."
            )
        }
        val hasMarkerPairs = markerCount >= 2

        return when {
            // Every occurrence of the FUZZ keyword is an injection point.
            hasFuzzKeyword && !hasMarkerPairs -> {
                val literals = baseRequest.split(FUZZ_KEYWORD)
                val points = literals.size - 1
                Resolved.Ok(Template(KEYWORD_POSITIONS, literals, List(points) { it }, List(points) { "" }))
            }

            // marker…marker pairs: the text between the markers is the position's own value.
            hasMarkerPairs -> {
                if (markerCount % 2 != 0) {
                    return Resolved.Error(
                        "Odd number ($markerCount) of '$effectiveMarker' markers; every injection point needs a closing marker."
                    )
                }
                val pairs = findMarkerPairs(baseRequest, effectiveMarker)
                if (pairs.isEmpty()) {
                    return Resolved.Error(
                        "Found marker '$effectiveMarker' but could not pair it into injection points. " +
                            "Wrap each value with an opening and closing marker, e.g. ${effectiveMarker}value${effectiveMarker}."
                    )
                }
                val literals = ArrayList<String>(pairs.size + 1)
                val values = ArrayList<String>(pairs.size)
                var cursor = 0
                for ((start, end) in pairs) {
                    literals += baseRequest.substring(cursor, start)
                    values += baseRequest.substring(start + effectiveMarker.length, end - effectiveMarker.length)
                    cursor = end
                }
                literals += baseRequest.substring(cursor)
                Resolved.Ok(Template(MARKER_POSITIONS, literals, List(pairs.size) { it }, values))
            }

            // Legacy [start, end) offsets.
            !positions.isNullOrEmpty() -> {
                validatePositions(positions, baseRequest.length)?.let { return Resolved.Error(it) }
                val inTextOrder = positions.withIndex().sortedWith(compareBy({ it.value.first }, { it.value.second }))
                val literals = ArrayList<String>(positions.size + 1)
                val values = MutableList(positions.size) { "" }
                var cursor = 0
                for ((position, range) in inTextOrder) {
                    literals += baseRequest.substring(cursor, range.first)
                    values[position] = baseRequest.substring(range.first, range.second)
                    cursor = range.second
                }
                literals += baseRequest.substring(cursor)
                Resolved.Ok(Template(OFFSET_POSITIONS, literals, inTextOrder.map { it.index }, values))
            }

            else -> Resolved.Error(
                "No injection points found. Use FUZZ keyword, ${effectiveMarker}marker${effectiveMarker} pairs, or a positions array."
            )
        }
    }

    /**
     * Request texts for one `http_race` batch: one per payload with every `FUZZ` replaced when
     * [payloads] is non-empty (it wins over [count]), else [count] copies of the request. Line
     * endings and Content-Length are handled as in [planAttack].
     */
    fun raceRequests(rawRequest: String, count: Int, payloads: List<String>?): List<String> {
        val base = RequestHygiene.normalizeCrlf(rawRequest)
        if (!payloads.isNullOrEmpty()) return payloads.map { withContentLength(base.replace(FUZZ_KEYWORD, it)) }
        val fixed = withContentLength(base)
        return List(count) { fixed }
    }

    /**
     * [request] with an unambiguous Content-Length set to its body's UTF-8 byte count (the charset
     * fuzz and race send with). CL.TE / TE.CL / CL.CL shapes are left alone.
     */
    fun withContentLength(request: String): String =
        RequestHygiene.fixContentLength(request, utf8Body = true).request

    /** A blank marker would match everywhere; it means "use the default `§`". */
    private fun effectiveMarker(marker: String?): String = marker?.takeIf { it.isNotEmpty() } ?: "§"

    /** Counts non-overlapping occurrences of [needle] in [haystack]. Empty needle yields 0. */
    fun countOccurrences(haystack: String, needle: String): Int {
        if (needle.isEmpty()) return 0
        var count = 0
        var idx = haystack.indexOf(needle)
        while (idx >= 0) {
            count++
            idx = haystack.indexOf(needle, idx + needle.length)
        }
        return count
    }

    /**
     * Finds [start, end) pairs delimiting each `marker…marker` region (end is exclusive and
     * includes the closing marker so the whole `§value§` span is replaced by the payload).
     */
    fun findMarkerPairs(baseRequest: String, marker: String): List<Pair<Int, Int>> {
        val positions = mutableListOf<Pair<Int, Int>>()
        var searchFrom = 0
        while (true) {
            val openIdx = baseRequest.indexOf(marker, searchFrom)
            if (openIdx < 0) break
            val closeIdx = baseRequest.indexOf(marker, openIdx + marker.length)
            if (closeIdx < 0) break
            positions.add(openIdx to (closeIdx + marker.length))
            searchFrom = closeIdx + marker.length
        }
        return positions
    }

    /**
     * Validates legacy offset pairs against [length]. Returns an error message describing the
     * first bad or overlapping pair, or null when every pair is valid.
     */
    fun validatePositions(positions: List<Pair<Int, Int>>, length: Int): String? {
        positions.forEachIndexed { i, (start, end) ->
            if (start < 0 || end < 0) {
                return "positions[$i] = [$start, $end] is invalid: offsets must be non-negative."
            }
            if (start > end) {
                return "positions[$i] = [$start, $end] is invalid: start ($start) must be <= end ($end). " +
                    "Offsets are [start, end) into the request string."
            }
            if (end > length) {
                return "positions[$i] = [$start, $end] is out of bounds: end ($end) exceeds request length ($length)."
            }
        }
        val indexed = positions.withIndex().sortedWith(compareBy({ it.value.first }, { it.value.second }))
        for (i in 1 until indexed.size) {
            val prev = indexed[i - 1]
            val curr = indexed[i]
            if (curr.value.first < prev.value.second) {
                return "positions[${prev.index}] = [${prev.value.first}, ${prev.value.second}] overlaps with " +
                    "positions[${curr.index}] = [${curr.value.first}, ${curr.value.second}]."
            }
        }
        return null
    }
}
