package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.state.WebSocketMessage
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import java.security.MessageDigest
import java.util.HexFormat

/**
 * Groups the responses of a WebSocket fuzz run, so the caller reads "17 payloads got this error,
 * 2 got that one, 1 got no reply" instead of comparing every frame.
 *
 * Two responses fall in the same cluster when they have the same outcome (error, closed or not),
 * the same number of frames, and frame by frame the same signature. What a signature keeps depends
 * on the [Level]: the finest level that does not leave most responses alone in their cluster is used.
 */
internal object WebSocketFuzzClusters {

    /**
     * One payload's response as the clustering sees it.
     *
     * @property message the message that was sent (the payload placed in its template).
     * @property frames the response frames that were kept, in order.
     * @property frameCount how many response frames arrived, kept or not.
     */
    class Response(
        val payload: String,
        val message: String,
        val frames: List<WebSocketMessage>,
        val frameCount: Int,
        val closed: Boolean,
        val error: String?,
    )

    /**
     * @property basis name of the level the clusters were built on.
     * @property clusters positions (in the input list) of each cluster's members, largest cluster first.
     * @property clusterOf for each input position, the index of its cluster in [clusters].
     */
    class Clustering(val basis: String, val clusters: List<List<Int>>, val clusterOf: IntArray)

    /** How much of a text frame its signature keeps, finest first. */
    internal enum class Level(val label: String) {
        /** The text, with the echoed payload and volatile tokens (timestamps, UUIDs, long ids) masked. */
        CONTENT("content"),

        /** As [CONTENT] with every run of digits masked too: for counters and sequence numbers. */
        DIGITS("content_digits_masked"),

        /** Only the structure: the keys and value types of a JSON frame, "text" for anything else. */
        SHAPE("shape"),
    }

    /** Up to this many clusters are always accepted, however small the run. */
    private const val ALWAYS_ACCEPTED = 5

    /** A payload shorter than this is not searched for in the responses: it would match by chance. */
    private const val MIN_REFLECTION_CHARS = 3

    /** Only this much of a text frame goes into its signature. */
    private const val MAX_SIGNATURE_CHARS = 20_000

    /** Only the first frames of a response go into its signature; the frame count covers the rest. */
    private const val MAX_SIGNATURE_FRAMES = 20

    private const val MAX_SHAPE_DEPTH = 6
    private const val MAX_SHAPE_KEYS = 50

    private val TIMESTAMP = Regex("""\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?""")
    private val UUID = Regex("""[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}""")
    private val LONG_TOKEN = Regex("""\b(?:[0-9a-fA-F]{16,}|\d{6,})\b""")
    private val DIGIT_RUN = Regex("""\d+""")

    fun cluster(responses: List<Response>): Clustering {
        var basis = Level.CONTENT
        var groups: Map<String, List<Int>> = emptyMap()
        for (level in Level.entries) {
            val byKey = LinkedHashMap<String, MutableList<Int>>()
            responses.forEachIndexed { position, response ->
                byKey.getOrPut(digest(signature(response, level))) { ArrayList() }.add(position)
            }
            basis = level
            groups = byKey
            if (!mostlySingletons(byKey.size, responses.size)) break
        }
        // Largest first; clusters of equal size in the order their first payload was sent.
        val clusters = groups.values.sortedWith(compareByDescending<List<Int>> { it.size }.thenBy { it[0] })
        val clusterOf = IntArray(responses.size)
        clusters.forEachIndexed { id, members -> members.forEach { clusterOf[it] = id } }
        return Clustering(basis.label, clusters, clusterOf)
    }

    /** True when [clusters] over [responses] responses says little: more than a handful, averaging under two members. */
    private fun mostlySingletons(clusters: Int, responses: Int): Boolean =
        clusters > ALWAYS_ACCEPTED && clusters * 2 > responses

    internal fun signature(response: Response, level: Level): String {
        // An error message names connections and indices; only its wording matters.
        if (response.error != null) return "error|" + DIGIT_RUN.replace(response.error, "0")
        val reflections = if (level == Level.SHAPE) emptyList() else reflections(response)
        val out = StringBuilder(if (response.closed) "closed" else "open").append('|').append(response.frameCount)
        for (frame in response.frames.take(MAX_SIGNATURE_FRAMES)) {
            out.append('\u0001').append(frameSignature(frame, reflections, level))
        }
        return out.toString()
    }

    /** A fixed-size key for [signature], so a large response does not stay in memory as a map key. */
    private fun digest(signature: String): String =
        HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(signature.toByteArray(Charsets.UTF_8)))

    private fun frameSignature(frame: WebSocketMessage, reflections: List<String>, level: Level): String {
        if (WebSocketFrames.isBinary(frame.type)) {
            return if (level == Level.SHAPE) "binary" else "binary:${frame.length}:${frame.payload.hashCode()}"
        }
        if (level == Level.SHAPE) return shape(frame.payload)
        var text = if (frame.payload.length > MAX_SIGNATURE_CHARS) frame.payload.substring(0, MAX_SIGNATURE_CHARS) else frame.payload
        for (reflection in reflections) text = text.replace(reflection, "{PAYLOAD}")
        text = TIMESTAMP.replace(text, "{TIME}")
        text = UUID.replace(text, "{UUID}")
        text = LONG_TOKEN.replace(text, "{ID}")
        if (level == Level.DIGITS) text = DIGIT_RUN.replace(text, "0")
        return "text:$text"
    }

    /**
     * The forms in which a server is likely to echo what it was sent: the whole message and the
     * payload, raw, JSON-escaped and HTML-escaped. Longest first, so a form is never masked in part
     * by a shorter one it contains.
     */
    private fun reflections(response: Response): List<String> {
        val forms = LinkedHashSet<String>()
        for (sent in arrayOf(response.message, response.payload)) {
            forms += sent
            forms += WebSocketFuzzPlan.jsonEscape(sent)
            forms += htmlEscape(sent, apostrophe = false)
            forms += htmlEscape(sent, apostrophe = true)
        }
        return forms.filter { it.length >= MIN_REFLECTION_CHARS }.sortedByDescending { it.length }
    }

    private fun htmlEscape(text: String, apostrophe: Boolean): String {
        val out = StringBuilder(text.length + 16)
        for (ch in text) {
            when {
                ch == '&' -> out.append("&amp;")
                ch == '<' -> out.append("&lt;")
                ch == '>' -> out.append("&gt;")
                ch == '"' -> out.append("&quot;")
                ch == '\'' && apostrophe -> out.append("&#39;")
                else -> out.append(ch)
            }
        }
        return out.toString()
    }

    /** The structure of a text frame: its JSON skeleton when it is a JSON object or array, else "text". */
    private fun shape(text: String): String {
        val first = text.firstOrNull { !it.isWhitespace() }
        if ((first != '{' && first != '[') || text.length > MAX_SIGNATURE_CHARS) return "text"
        val parsed = try {
            Json.parseToJsonElement(text)
        } catch (_: Exception) {
            return "text"
        }
        return "json:" + StringBuilder().also { skeleton(parsed, 0, it) }
    }

    /** Appends the keys (sorted) and value types of [element]; an array is described by its first element. */
    private fun skeleton(element: JsonElement, depth: Int, out: StringBuilder) {
        when (element) {
            is JsonObject -> {
                out.append('{')
                if (depth < MAX_SHAPE_DEPTH) {
                    element.keys.sorted().take(MAX_SHAPE_KEYS).forEach { key ->
                        out.append(key).append(':')
                        skeleton(element.getValue(key), depth + 1, out)
                        out.append(',')
                    }
                }
                out.append('}')
            }
            is JsonArray -> {
                out.append('[')
                if (depth < MAX_SHAPE_DEPTH && element.isNotEmpty()) skeleton(element[0], depth + 1, out)
                out.append(']')
            }
            is JsonNull -> out.append("null")
            is JsonPrimitive -> out.append(
                when {
                    element.isString -> "s"
                    element.booleanOrNull != null -> "b"
                    else -> "n"
                }
            )
        }
    }
}
