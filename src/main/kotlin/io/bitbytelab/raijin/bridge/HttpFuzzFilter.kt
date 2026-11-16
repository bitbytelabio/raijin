package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.core.asIntSafe
import io.bitbytelab.raijin.safety.SafeRegex
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * Which responses of a fuzz run are listed in its results. A hidden response is still counted and
 * clustered, so the summary covers the whole run while the list stays readable.
 *
 * @param hideStatus status codes to leave out (0 = no response).
 * @param hideLengths body lengths (in bytes) to leave out.
 * @param grepRegex when set, only responses it matches are listed.
 * @param hideRegex when set, responses it matches are left out.
 */
internal class FuzzResponseFilter(
    private val hideStatus: Set<Int> = emptySet(),
    private val hideLengths: List<IntRange> = emptyList(),
    private val grepRegex: String? = null,
    private val hideRegex: String? = null,
) {
    val active: Boolean
        get() = hideStatus.isNotEmpty() || hideLengths.isNotEmpty() || grepRegex != null || hideRegex != null

    /**
     * Whether a response is listed. [text] (status line, headers and body) is only built when a
     * regex has to look at it; a response without one (status 0) matches no regex.
     */
    fun keeps(status: Int, bodyLength: Int, text: () -> String): Boolean {
        if (status in hideStatus) return false
        if (hideLengths.any { bodyLength in it }) return false
        if (grepRegex == null && hideRegex == null) return true
        val full = text()
        val searched = if (full.length > SafeRegex.DEFAULT_MAX_INPUT_LEN) full.substring(0, SafeRegex.DEFAULT_MAX_INPUT_LEN) else full
        if (grepRegex != null && !SafeRegex.containsMatchIn(grepRegex, searched)) return false
        if (hideRegex != null && SafeRegex.containsMatchIn(hideRegex, searched)) return false
        return true
    }

    companion object {
        val NONE = FuzzResponseFilter()

        /**
         * Body lengths from a list of integers and `"min-max"` strings; a single value or a
         * comma-separated string is read as a list.
         * @throws IllegalArgumentException naming the item that is neither.
         */
        fun parseLengths(element: JsonElement?, name: String = "filter_length"): List<IntRange> =
            items(element).flatMap { it.split(',') }.map { it.trim() }.filter { it.isNotEmpty() }.map { item ->
                val exact = item.toIntOrNull()
                if (exact != null) return@map exact..exact
                // The dash that separates the bounds is the first one after the first digit.
                val dash = item.indexOf('-', 1)
                val low = if (dash > 0) item.substring(0, dash).trim().toIntOrNull() else null
                val high = if (dash > 0) item.substring(dash + 1).trim().toIntOrNull() else null
                require(low != null && high != null) { "$name item '$item' must be an integer or a 'min-max' range" }
                minOf(low, high)..maxOf(low, high)
            }

        /**
         * Status codes from a list of integers (a single value is read as a list).
         * @throws IllegalArgumentException naming a value that is not an integer.
         */
        fun parseStatuses(element: JsonElement?, name: String): Set<Int> {
            if (element == null || element is JsonNull) return emptySet()
            val values = if (element is JsonArray) element.toList() else listOf(element)
            return values.mapTo(LinkedHashSet<Int>()) { value ->
                value.asIntSafe() ?: throw IllegalArgumentException("$name must be an array of integer status codes (got $value)")
            }
        }

        private fun items(element: JsonElement?): List<String> = when (element) {
            null, JsonNull -> emptyList()
            is JsonArray -> element.map { (it as? JsonPrimitive)?.contentOrNull ?: it.toString() }
            is JsonPrimitive -> listOf(element.contentOrNull ?: "")
            else -> listOf(element.toString())
        }
    }
}
