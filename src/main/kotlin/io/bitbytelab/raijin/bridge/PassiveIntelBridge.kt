package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpMessage
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.recon.SecretPatterns
import io.bitbytelab.raijin.safety.SafeRegex
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.math.min

/** Scans traffic already in proxy history for secrets and other telling strings ([SecretPatterns]). */
class PassiveIntelBridge(private val api: MontoyaApi) {

    companion object {
        /** Body characters scanned per message; a secret sits in a response's text, not megabytes into a download. */
        const val MAX_BODY_CHARS = 200_000
        private const val MAX_HEAD_CHARS = 64_000

        /** Distinct values kept per category; the rest are counted in `omitted`. */
        const val MAX_PER_CATEGORY = 100

        /** Places listed per value: where it was first seen and the next few (`also_seen`). */
        const val MAX_PLACES_PER_VALUE = 5

        /** Time all patterns together may spend on one history item, and the whole scan in total. */
        private const val ITEM_BUDGET_MS = 2_000L
        private const val SCAN_BUDGET_MS = 60_000L
    }

    /**
     * The part of a message that is scanned: its start line and headers, and its body unless
     * that is binary, cut at [MAX_BODY_CHARS].
     */
    private class Scannable(val text: String, val binaryBody: Boolean, val truncated: Boolean)

    private fun scannable(message: HttpMessage, mime: String?): Scannable {
        val bytes = message.toByteArray()
        val total = bytes.length()
        val offset = message.bodyOffset().coerceIn(0, total)
        val head = if (offset == 0) "" else bytes.subArray(0, min(offset, MAX_HEAD_CHARS)).toString()
        val bodyLength = total - offset
        if (bodyLength == 0) return Scannable(head, binaryBody = false, truncated = false)
        val kept = min(bodyLength, MAX_BODY_CHARS)
        val body = bytes.subArray(offset, offset + kept).toString()
        if (BodyText.isBinaryMime(mime) || BodyText.isProbablyBinary(body)) return Scannable(head, binaryBody = true, truncated = false)
        return Scannable(head + body, binaryBody = false, truncated = kept < bodyLength)
    }

    /**
     * Scan proxy history for sensitive data patterns.
     *
     * @param maxItems Max proxy history items to scan
     * @param inScopeOnly Only scan in-scope items
     * @param categories Optional list of pattern categories to check (default: all but the opt-in ones)
     * @param hostFilter Optional hostname filter
     * @return JSON with the findings grouped by category, one per distinct value ([IntelFindings])
     */
    fun extractIntel(
        maxItems: Int,
        inScopeOnly: Boolean,
        categories: List<String>?,
        hostFilter: String?
    ): JsonObject {
        return try {
            val selection = SecretPatterns.select(categories)
            if (selection.unknown.isNotEmpty()) {
                return buildJsonObject {
                    put("error", "Unknown categories: ${selection.unknown.joinToString(", ")}. Available: ${SecretPatterns.ALL.keys.joinToString(", ")}")
                }
            }
            if (hostFilter != null) {
                SafeRegex.validate(hostFilter, ignoreCase = true)?.let { err ->
                    return buildJsonObject { put("error", "Invalid host_filter regex: $err") }
                }
            }

            var items = api.proxy().history().toList()
            if (inScopeOnly) {
                items = items.filter {
                    try { api.scope().isInScope(it.finalRequest().url()) } catch (_: Exception) { false }
                }
            }
            if (hostFilter != null) {
                items = items.filter {
                    val h = try { it.finalRequest().httpService().host() } catch (_: Exception) { "" }
                    SafeRegex.containsMatchIn(hostFilter, h, ignoreCase = true)
                }
            }
            items = items.takeLast(maxItems.coerceAtLeast(0))

            val deadline = System.nanoTime() + SCAN_BUDGET_MS * 1_000_000
            val findings = IntelFindings()
            val timedOut = LinkedHashSet<String>()
            var itemsScanned = 0
            var binarySkipped = 0
            var truncated = 0
            var outOfTime = false

            for (item in items) {
                val now = System.nanoTime()
                if (now > deadline) {
                    outOfTime = true
                    break
                }
                itemsScanned++
                val url = try { item.finalRequest().url() } catch (_: Exception) { continue }
                val host = try { item.finalRequest().httpService().host() } catch (_: Exception) { "" }
                val itemDeadline = min(deadline, now + ITEM_BUDGET_MS * 1_000_000)

                val request = try { scannable(item.finalRequest(), null) } catch (_: Exception) { null }
                val response = try {
                    if (!item.hasResponse()) {
                        null
                    } else {
                        val resp = item.originalResponse()
                        scannable(resp, try { resp.mimeType().name } catch (_: Exception) { null })
                    }
                } catch (_: Exception) { null }

                for ((part, location) in listOf(request to "request", response to "response")) {
                    if (part == null) continue
                    if (part.binaryBody) binarySkipped++
                    if (part.truncated) truncated++
                    val result = SecretPatterns.scan(part.text, selection.patterns, itemDeadline)
                    timedOut.addAll(result.timedOut)
                    for ((pattern, value) in result.matches) findings.add(pattern, value, url, location, host)
                }
            }

            buildJsonObject {
                put("items_scanned", itemsScanned)
                findings.writeTo(this)
                if (binarySkipped > 0) put("binary_bodies_skipped", binarySkipped)
                if (truncated > 0) put("bodies_truncated", truncated)
                if (timedOut.isNotEmpty()) put("patterns_timed_out", buildJsonArray { timedOut.forEach { add(it) } })
                if (outOfTime) {
                    put("stopped", "time_budget")
                    put("items_not_scanned", items.size - itemsScanned)
                }

                // Available pattern categories
                put("available_categories", buildJsonArray {
                    SecretPatterns.ALL.keys.forEach { add(it) }
                })
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Passive intel extraction failed: ${e.message}") }
        }
    }
}

/**
 * What one scan found, by category and then by distinct value: where a value was first seen, how
 * many places (a URL's request or response) carry it, and a few more of them. The cap per
 * category counts distinct values, so a session token sent on every page takes one slot and a
 * different token found once still gets its own.
 */
internal class IntelFindings(
    private val maxPerCategory: Int = PassiveIntelBridge.MAX_PER_CATEGORY,
    private val maxPlaces: Int = PassiveIntelBridge.MAX_PLACES_PER_VALUE,
) {
    private class Place(val url: String, val location: String, val host: String)

    private class Sighting(val first: Place) {
        val places = HashSet<Pair<String, String>>()
        val more = ArrayList<Place>()
    }

    private val categories = LinkedHashMap<String, LinkedHashMap<String, Sighting>>()
    private val omitted = LinkedHashMap<String, MutableSet<String>>()

    /** Records [value] of [pattern] in the [location] (request or response) of [url]. */
    fun add(pattern: String, value: String, url: String, location: String, host: String) {
        val values = categories.getOrPut(pattern) { LinkedHashMap() }
        val sighting = values[value] ?: run {
            if (values.size >= maxPerCategory) {
                omitted.getOrPut(pattern) { HashSet() }.add(value)
                return
            }
            Sighting(Place(url, location, host)).also { values[value] = it }
        }
        if (sighting.places.add(url to location) && sighting.places.size > 1 && sighting.more.size < maxPlaces - 1) {
            sighting.more.add(Place(url, location, host))
        }
    }

    /** Puts `total_findings`, `categories_with_findings`, `summary`, `findings` and, when a cap was hit, `omitted`. */
    fun writeTo(out: JsonObjectBuilder) {
        out.put("total_findings", categories.values.sumOf { it.size })
        out.put("categories_with_findings", categories.size)
        out.putJsonObject("summary") { categories.forEach { (category, values) -> put(category, values.size) } }
        out.putJsonObject("findings") {
            categories.forEach { (category, values) ->
                putJsonArray(category) {
                    values.forEach { (value, sighting) ->
                        addJsonObject {
                            put("pattern", category)
                            put("match", value)
                            put("location", sighting.first.location)
                            put("url", sighting.first.url)
                            put("host", sighting.first.host)
                            put("occurrences", sighting.places.size)
                            if (sighting.more.isNotEmpty()) {
                                putJsonArray("also_seen") {
                                    sighting.more.forEach { place ->
                                        addJsonObject {
                                            put("url", place.url)
                                            put("location", place.location)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if (omitted.isNotEmpty()) out.putJsonObject("omitted") { omitted.forEach { (category, values) -> put(category, values.size) } }
    }
}
