package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpMessage
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.recon.SecretPatterns
import io.bitbytelab.raijin.safety.SafeRegex
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.math.min

/** Scans traffic already in proxy history for secrets and other telling strings ([SecretPatterns]). */
class PassiveIntelBridge(private val api: MontoyaApi) {

    companion object {
        /** Body characters scanned per message; a secret sits in a response's text, not megabytes into a download. */
        const val MAX_BODY_CHARS = 200_000
        private const val MAX_HEAD_CHARS = 64_000

        /** Findings kept per category; the rest are counted in `omitted`. */
        const val MAX_PER_CATEGORY = 100

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
     * @return JSON with all findings grouped by category, one per (match, url, location)
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
            val findings = LinkedHashMap<String, MutableList<JsonObject>>()
            val seen = HashSet<List<String>>()
            val omitted = LinkedHashMap<String, Int>()
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
                    for ((pattern, value) in result.matches) {
                        if (!seen.add(listOf(pattern, value, url, location))) continue
                        val list = findings.getOrPut(pattern) { mutableListOf() }
                        if (list.size >= MAX_PER_CATEGORY) {
                            omitted[pattern] = (omitted[pattern] ?: 0) + 1
                            continue
                        }
                        list.add(buildJsonObject {
                            put("pattern", pattern)
                            put("match", value)
                            put("location", location)
                            put("url", url)
                            put("host", host)
                        })
                    }
                }
            }

            buildJsonObject {
                put("items_scanned", itemsScanned)
                put("total_findings", findings.values.sumOf { it.size })
                put("categories_with_findings", findings.size)

                // Summary by category
                put("summary", buildJsonObject {
                    findings.forEach { (cat, matches) ->
                        put(cat, matches.size)
                    }
                })

                // Detailed findings
                put("findings", buildJsonObject {
                    findings.forEach { (cat, matches) ->
                        put(cat, buildJsonArray { matches.forEach { add(it) } })
                    }
                })

                if (omitted.isNotEmpty()) {
                    put("omitted", buildJsonObject { omitted.forEach { (cat, count) -> put(cat, count) } })
                }
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
