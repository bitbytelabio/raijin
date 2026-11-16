package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.core.asStringMap
import io.bitbytelab.raijin.safety.RequestHygiene
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import java.util.TreeMap

/**
 * The one implementation of "send this raw request as that identity", shared by `auth_diff`,
 * the access-control sweep and IDOR hunt (and written for the live Autorize replay to adopt).
 *
 * An identity is `{name, header_name?, header_value?, headers?, remove_headers?}`:
 *  - every header it names REPLACES the request's header of that name: all existing occurrences
 *    are removed and one is written back, so a second `Cookie` / `Authorization` line is never
 *    appended next to the captured one;
 *  - an identity named none / unauth / anonymous additionally loses every credential header
 *    ([CREDENTIAL_HEADERS]) and every header the other identities of the same run use to carry
 *    theirs, so it cannot leave still authenticated through a custom header. Headers it names
 *    itself (a guest cookie, a deliberately invalid token) are written after that;
 *  - the result carries a `Content-Length` that matches its body.
 *
 * Pure text in, text out (no Montoya types), so it is unit tested and usable from any bridge.
 */
object AuthIdentityApplier {

    /**
     * Request headers that are credentials whatever the application. CSRF tokens are left out on
     * purpose: one without its session proves nothing, and dropping it would turn a missing
     * authorization check into a CSRF rejection.
     */
    val CREDENTIAL_HEADERS: List<String> = listOf(
        "Authorization", "Proxy-Authorization", "Cookie", "Cookie2",
        "X-API-Key", "X-Auth-Token", "X-Access-Token", "X-Session-Token", "X-Amz-Security-Token",
    )

    private val CREDENTIAL_KEYS: Set<String> = CREDENTIAL_HEADERS.mapTo(HashSet()) { it.lowercase() }

    private val UNAUTHENTICATED_NAMES = listOf("none", "unauth", "anonymous")

    /** True for the level names that mean "no credentials": none / unauth / anonymous (any case). */
    fun isUnauthenticated(name: String?): Boolean =
        name != null && UNAUTHENTICATED_NAMES.any { it.equals(name, ignoreCase = true) }

    /**
     * @param headers headers this identity sends, one entry per header name.
     * @param removeHeaders further headers this identity must not send.
     */
    data class Identity(
        val name: String,
        val headers: List<Pair<String, String>> = emptyList(),
        val removeHeaders: List<String> = emptyList(),
    ) {
        /** Named as the no-credentials baseline. */
        val unauthenticated: Boolean get() = isUnauthenticated(name)

        /**
         * Changes nothing about the request and is not the no-credentials baseline: the request
         * goes out with whatever credentials it already carries.
         */
        val sendsRequestUnchanged: Boolean
            get() = !unauthenticated && headers.isEmpty() && removeHeaders.isEmpty()
    }

    /**
     * Reads an identity object. `header_name` + `header_value` (both needed) and the `headers`
     * map (any shape [asStringMap] accepts) are merged; a later entry replaces an earlier one of
     * the same name. [defaultName] names an identity that has no `name`.
     */
    fun parse(identity: JsonObject, defaultName: String = "unknown"): Identity {
        val headers = LinkedHashMap<String, Pair<String, String>>()
        fun setHeader(rawName: String, value: String) {
            val name = cleanName(rawName)
            if (name.isNotEmpty()) headers[name.lowercase()] = name to value
        }
        val headerName = identity.string("header_name")
        val headerValue = identity.string("header_value")
        if (headerName != null && headerValue != null) setHeader(headerName, headerValue)
        identity["headers"].asStringMap()?.forEach { (name, value) -> setHeader(name, value) }
        val remove = identity["remove_headers"].asStringList().orEmpty().map(::cleanName).filter { it.isNotEmpty() }
        return Identity(identity.string("name") ?: defaultName, headers.values.toList(), remove)
    }

    /**
     * Lowercase names of every header the identities of one run set or remove: the
     * identity-specific headers an unauthenticated level must not keep.
     */
    fun identityHeaders(identities: Collection<Identity>): Set<String> =
        identities.flatMapTo(LinkedHashSet()) { identity ->
            identity.headers.map { it.first.lowercase() } + identity.removeHeaders.map { it.lowercase() }
        }

    /**
     * Two identities that change nothing about the request would send the very same request and
     * differ by name only, so any comparison would "find" that they match. Returns the error to
     * report for such a set, or null when at most one identity sends the request unchanged.
     */
    fun indistinguishableError(identities: Collection<Identity>): String? {
        val unchanged = identities.filter { it.sendsRequestUnchanged }.map { it.name }
        if (unchanged.size < 2) return null
        return "Identities ${unchanged.joinToString(", ") { "'$it'" }} set no header and are not named none/unauth/anonymous, " +
            "so they would all send the request unchanged: give each one its credentials (header_name + header_value, or headers)."
    }

    /**
     * @param request the request to send: CRLF header block, identity applied, `Content-Length` corrected.
     * @param removed names of the headers taken out without a replacement, as they were written.
     * @param set names of the headers written for the identity.
     * @param keptCredentials credential or identity-specific headers still in the request that the
     *   identity did not set itself. Never populated for an unauthenticated identity; for an
     *   authenticated one it shows which captured credentials travel along with its own.
     */
    data class Applied(
        val request: String,
        val removed: List<String> = emptyList(),
        val set: List<String> = emptyList(),
        val keptCredentials: List<String> = emptyList(),
    )

    /**
     * Applies [identity] to [rawRequest].
     *
     * @param identityHeaders [identityHeaders] of the whole run, so an unauthenticated identity
     *   also drops the headers its peers authenticate with.
     */
    fun apply(rawRequest: String, identity: Identity, identityHeaders: Collection<String> = emptyList()): Applied {
        if (rawRequest.isBlank()) return Applied(rawRequest)
        val request = RequestHygiene.normalizeCrlf(rawRequest)
        val boundary = request.indexOf("\r\n\r\n")
        val head = if (boundary >= 0) request.substring(0, boundary) else request.trimEnd('\r', '\n')
        val body = if (boundary >= 0) request.substring(boundary + 4) else ""
        val lines = head.split("\r\n")

        val setKeys = identity.headers.mapTo(HashSet()) { it.first.lowercase() }
        val specific = identityHeaders.mapTo(HashSet()) { it.lowercase() }
        val strip = HashSet<String>()
        identity.removeHeaders.forEach { strip += it.lowercase() }
        if (identity.unauthenticated) {
            strip += CREDENTIAL_KEYS
            strip += specific
        }

        val kept = ArrayList<String>(lines.size)
        val removed = LinkedHashMap<String, String>()
        // Header the identity sets -> where its first occurrence stood, so the replacement keeps that place.
        val slots = HashMap<String, Int>()
        var dropping = false
        for (line in lines.drop(1)) {
            // A folded continuation line belongs to the header before it.
            if (dropping && (line.startsWith(" ") || line.startsWith("\t"))) continue
            val name = headerName(line)
            val key = name?.lowercase()
            dropping = key != null && (key in strip || key in setKeys)
            if (name == null || key == null || !dropping) {
                kept += line
                continue
            }
            if (key in setKeys) slots.putIfAbsent(key, kept.size) else removed.putIfAbsent(key, name)
        }

        val inserts = TreeMap<Int, MutableList<String>>()
        for ((name, value) in identity.headers) {
            inserts.getOrPut(slots[name.lowercase()] ?: kept.size) { mutableListOf() } += "$name: $value"
        }
        val headerLines = ArrayList<String>(kept.size + identity.headers.size)
        for (i in 0..kept.size) {
            inserts[i]?.let { headerLines += it }
            if (i < kept.size) headerLines += kept[i]
        }

        val rebuilt = buildString(request.length + 64) {
            append(lines.first())
            for (line in headerLines) append("\r\n").append(line)
            append("\r\n\r\n").append(body)
        }

        val keptCredentials = LinkedHashMap<String, String>()
        for (line in kept) {
            val name = headerName(line) ?: continue
            val key = name.lowercase()
            if (key in CREDENTIAL_KEYS || key in specific) keptCredentials.putIfAbsent(key, name)
        }
        return Applied(
            request = withContentLength(rebuilt),
            removed = removed.values.toList(),
            set = identity.headers.map { it.first },
            keptCredentials = keptCredentials.values.toList(),
        )
    }

    /**
     * [request] with a `Content-Length` that matches its body, counted in the charset it is sent
     * with ([wireBytes]). A wrong value is rewritten and a missing one added for a non-blank body;
     * a request framed by `Transfer-Encoding` or by several `Content-Length` headers is left as
     * written ([RequestHygiene.fixContentLength]).
     */
    internal fun withContentLength(request: String): String {
        val utf8 = RequestHygiene.wireCharset(request) == Charsets.UTF_8
        val fixed = RequestHygiene.fixContentLength(request, utf8Body = utf8).request
        val boundary = fixed.indexOf("\r\n\r\n")
        if (boundary < 0) return fixed
        val body = fixed.substring(boundary + 4)
        if (body.isBlank()) return fixed
        val framed = fixed.substring(0, boundary).split("\r\n").drop(1).any { line ->
            val name = line.substringBefore(':').lowercase()
            "content-length" in name || "transfer-encoding" in name
        }
        if (framed) return fixed
        val length = body.toByteArray(if (utf8) Charsets.UTF_8 else Charsets.ISO_8859_1).size
        return fixed.substring(0, boundary) + "\r\nContent-Length: $length\r\n\r\n" + body
    }

    /** Bytes of an applied request, in the charset its `Content-Length` was counted in. */
    fun wireBytes(request: String): ByteArray = request.toByteArray(RequestHygiene.wireCharset(request))

    private fun headerName(line: String): String? {
        val colon = line.indexOf(':')
        return if (colon <= 0) null else line.substring(0, colon).trim()
    }

    /** A header name as callers write it, tolerating the trailing colon of `"Authorization:"`. */
    private fun cleanName(name: String): String = name.trim().trimEnd(':').trim()

    private fun JsonObject.string(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull
}
