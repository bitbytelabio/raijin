package io.bitbytelab.raijin.recon

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import java.net.URI
import java.net.URLDecoder
import java.util.Base64

/**
 * JavaScript source maps: where a script says its map is, and what a map gives away. A map lists
 * the original source files and usually embeds their text, which holds the routes and API calls
 * the minified bundle obscures.
 */
object SourceMaps {
    /** Largest map text parsed; a bigger one is skipped rather than held in memory twice over. */
    const val MAX_MAP_CHARS = 16_000_000

    /** Time spent harvesting endpoints from one map's embedded sources. */
    const val DEFAULT_BUDGET_MS = 5_000L

    private const val MARKER = "sourceMappingURL="
    private const val MAX_SECTION_DEPTH = 2

    /**
     * @param sources original file names the map lists (`webpack:///./src/api/users.js`).
     * @param sourcesWithContent how many of them come with their text embedded.
     * @param endpoints endpoints found in the embedded source text.
     * @param complete false when the time ran out before every source was read.
     */
    data class Parsed(val sources: List<String>, val sourcesWithContent: Int, val endpoints: Set<String>, val complete: Boolean)

    /**
     * The map reference in a script or stylesheet: the value of its last `//# sourceMappingURL=`
     * comment (also the older `//@` form and `/*# ... */`), or null when it has none.
     */
    fun reference(text: String): String? {
        val at = text.lastIndexOf(MARKER)
        if (at < 0) return null
        var before = at - 1
        while (before >= 0 && (text[before] == ' ' || text[before] == '\t')) before--
        if (before < 2 || (text[before] != '#' && text[before] != '@')) return null
        val opener = text.substring(before - 2, before)
        if (opener != "//" && opener != "/*") return null
        val start = at + MARKER.length
        var end = start
        while (end < text.length && !text[end].isWhitespace()) end++
        return text.substring(start, end).removeSuffix("*/").ifEmpty { null }
    }

    /** The map reference a response announces in its `SourceMap` (or older `X-SourceMap`) header. */
    fun headerReference(headers: Map<String, String>): String? =
        (headers["sourcemap"] ?: headers["x-sourcemap"])?.lineSequence()?.firstOrNull()?.trim()?.ifEmpty { null }

    /** True when [url]'s path names a source map file. */
    fun isMapUrl(url: String): Boolean = url.substringBefore('?').substringBefore('#').endsWith(".map", ignoreCase = true)

    /** Absolute URL of the map [reference] found in the script at [scriptUrl]; null for a `data:` reference or one that is not http(s). */
    fun resolve(scriptUrl: String, reference: String): String? {
        val ref = reference.trim()
        if (ref.isEmpty() || ref.startsWith("data:", ignoreCase = true)) return null
        val resolved = try {
            URI(scriptUrl).resolve(ref).toString()
        } catch (_: Exception) {
            // A URL java.net.URI rejects (a raw `|` or `{`): resolve it as text.
            val base = UrlParts.parse(scriptUrl) ?: return null
            when {
                ref.startsWith("http://", ignoreCase = true) || ref.startsWith("https://", ignoreCase = true) -> ref
                ref.startsWith("//") -> base.scheme + ":" + ref
                ref.startsWith("/") -> base.origin + ref
                else -> base.origin + base.directory + ref.removePrefix("./")
            }
        }
        return resolved.takeIf { it.startsWith("http://", ignoreCase = true) || it.startsWith("https://", ignoreCase = true) }
    }

    /** The map text carried inside a `data:` [reference] (base64 or percent-encoded); null when it is not one or does not decode. */
    fun inline(reference: String): String? {
        if (!reference.startsWith("data:", ignoreCase = true)) return null
        val comma = reference.indexOf(',')
        if (comma < 0) return null
        val payload = reference.substring(comma + 1)
        if (payload.length > MAX_MAP_CHARS * 2L) return null
        return try {
            if (reference.substring(0, comma).contains(";base64", ignoreCase = true)) {
                String(Base64.getMimeDecoder().decode(payload), Charsets.UTF_8)
            } else {
                URLDecoder.decode(payload, Charsets.UTF_8)
            }
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Reads a source map (version 3, including an index map with `sections`): its source file
     * names, and the endpoints in the source text it embeds. Null when [json] is not a source map
     * or is larger than [MAX_MAP_CHARS].
     */
    fun parse(json: String, budgetMs: Long = DEFAULT_BUDGET_MS): Parsed? {
        if (json.length > MAX_MAP_CHARS) return null
        // Some servers prefix JSON with an anti-hijacking line: )]}'
        val text = json.trimStart().let { if (it.startsWith(")]}")) it.substringAfter('\n', "") else it }
        val root = try { Json.parseToJsonElement(text) as? JsonObject } catch (_: Exception) { null } ?: return null
        if (root["mappings"] == null && root["sections"] == null && root["sources"] == null) return null

        val deadline = System.nanoTime() + budgetMs * 1_000_000
        val sources = ArrayList<String>()
        val endpoints = LinkedHashSet<String>()
        var withContent = 0
        var complete = true

        fun read(map: JsonObject, depth: Int) {
            val sourceRoot = (map["sourceRoot"] as? JsonPrimitive)?.contentOrNull.orEmpty()
            val prefix = if (sourceRoot.isEmpty() || sourceRoot.endsWith("/")) sourceRoot else "$sourceRoot/"
            (map["sources"] as? JsonArray)?.forEach { name ->
                (name as? JsonPrimitive)?.contentOrNull?.let { sources.add(prefix + it) }
            }
            (map["sourcesContent"] as? JsonArray)?.forEach { content ->
                val source = (content as? JsonPrimitive)?.takeIf { it.isString }?.content ?: return@forEach
                withContent++
                val leftMs = (deadline - System.nanoTime()) / 1_000_000
                if (leftMs <= 0) {
                    complete = false
                    return@forEach
                }
                val scan = JsEndpoints.scan(source, leftMs)
                endpoints.addAll(scan.endpoints)
                if (!scan.complete) complete = false
            }
            if (depth < MAX_SECTION_DEPTH) {
                (map["sections"] as? JsonArray)?.forEach { section ->
                    ((section as? JsonObject)?.get("map") as? JsonObject)?.let { read(it, depth + 1) }
                }
            }
        }
        read(root, 0)
        return Parsed(sources, withContent, endpoints, complete)
    }
}
