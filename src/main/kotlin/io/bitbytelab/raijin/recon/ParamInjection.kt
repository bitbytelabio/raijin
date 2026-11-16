package io.bitbytelab.raijin.recon

import io.bitbytelab.raijin.core.JsonBodyMerge
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import java.net.URLDecoder

/**
 * Where parameter mining places candidate names.
 *
 * @param bucketSize how many candidates share one request by default; smaller where servers cap
 *   the size of what carries them (one Cookie line, the header block).
 * @param ignoresNameCase whether two names differing only in case are the same input there.
 */
enum class ParamLocation(val id: String, val bucketSize: Int, val method: String, val ignoresNameCase: Boolean) {
    QUERY("query", 64, "GET", false),
    BODY("body", 128, "POST", false),
    JSON_BODY("json_body", 128, "POST", false),
    COOKIE("cookie", 32, "GET", false),
    HEADER("header", 20, "GET", true);

    companion object {
        val IDS: List<String> = entries.map { it.id }

        fun of(id: String): ParamLocation? = entries.firstOrNull { it.id.equals(id.trim(), ignoreCase = true) }
    }
}

/** Places a bucket of `name=value` candidates into a request, one way per [ParamLocation]. */
object ParamInjection {

    /**
     * Headers that describe the message framing or the connection itself. A canary there does not
     * test a hidden input: it makes the request invalid, or the exchange hang, and takes the rest
     * of its bucket down with it. A bundled wordlist run leaves them out; candidates the caller
     * names are sent as given.
     */
    val FRAMING_HEADERS: Set<String> = setOf(
        "content-length", "transfer-encoding", "connection", "keep-alive", "proxy-connection",
        "upgrade", "te", "trailer", "expect", "http2-settings",
    )

    /**
     * [base] carrying [params] at [location]. With no [params] the request still gets the body
     * and Content-Type the location implies, so it differs from a mined request in the names only.
     */
    fun inject(base: ProbeRequest, location: ParamLocation, params: List<Pair<String, String>>): ProbeRequest {
        return when (location) {
            ParamLocation.QUERY -> base.withQuery(ProbeText.pairs(params, "&"))
            ParamLocation.BODY -> {
                val existing = base.body.trim().trimEnd('&')
                val added = ProbeText.pairs(params, "&")
                val request = base.withBody(if (existing.isEmpty() || added.isEmpty()) existing + added else "$existing&$added")
                if (request.header("Content-Type") == null) request.withHeader("Content-Type", "application/x-www-form-urlencoded") else request
            }
            ParamLocation.JSON_BODY ->
                base.withBody(mergeJson(base.body, params)).withHeader("Content-Type", "application/json")
            ParamLocation.COOKIE -> base.withCookies(ProbeText.pairs(params, "; "))
            // A candidate naming a header the request already has takes that header over.
            ParamLocation.HEADER -> base.withHeaders(params)
        }
    }

    /**
     * Names [base] already carries at [location]. Mining them would only overwrite a known input,
     * so they are skipped. Headers are not listed: a header candidate replaces the existing one.
     */
    fun existingNames(base: ProbeRequest, location: ParamLocation): Set<String> = when (location) {
        ParamLocation.QUERY -> pairNames(base.query.orEmpty(), '&')
        ParamLocation.BODY -> pairNames(base.body, '&')
        ParamLocation.JSON_BODY -> jsonObject(base.body)?.keys.orEmpty()
        ParamLocation.COOKIE -> pairNames(base.header("Cookie").orEmpty(), ';')
        ParamLocation.HEADER -> emptySet()
    }

    /**
     * [body] as a JSON object with [params] added as top-level string members ([JsonBodyMerge]).
     * A missing, empty or non-object body counts as `{}`: the base request for
     * `inject_in=json_body` often has no body.
     */
    fun mergeJson(body: String, params: List<Pair<String, String>>): String =
        params.fold(jsonObject(body)?.toString() ?: "{}") { merged, (name, value) -> JsonBodyMerge.mergeKey(merged, name, value) }

    private fun jsonObject(body: String): JsonObject? {
        val trimmed = body.trim()
        if (!trimmed.startsWith("{")) return null
        return try { Json.parseToJsonElement(trimmed) as? JsonObject } catch (_: Exception) { null }
    }

    /** Names in a `a=1&b=2` / `a=1; b=2` list, both as written and percent-decoded. */
    private fun pairNames(text: String, separator: Char): Set<String> {
        val names = LinkedHashSet<String>()
        for (pair in text.split(separator)) {
            val name = pair.substringBefore('=').trim()
            if (name.isEmpty()) continue
            names += name
            try { names += URLDecoder.decode(name, Charsets.UTF_8) } catch (_: Exception) {}
        }
        return names
    }
}
