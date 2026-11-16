package io.bitbytelab.raijin.bridge

/**
 * Pure, Burp-independent IDOR-hunting logic, distilled from the combined
 * IDOR/BOLA/BFLA methodology (the lossless union of the system's idor-agent
 * knowledge base, the auth-authz skill, and the API/auth/business-logic agents).
 *
 * This is the engine behind the `idor_hunt` MCP tool. It is deliberately kept
 * free of the Montoya API (which is compileOnly and cannot be instantiated in
 * tests) so every classification / transformation / verdict rule is unit tested.
 * The [IdorHuntBridge] supplies the live HTTP replay around this core.
 *
 * What it adds over the existing identity-only [AuthDiffVerdict] engine — which
 * varies the *auth identity* while holding the object reference CONSTANT — is:
 *   1. object-reference DETECTION + format classification (§1/§2 of the methodology),
 *   2. object-id TRANSFORMATION generation (the §2 encoding/HPP/type-juggle cheat-sheet),
 *   3. the flagship HORIZONTAL object-id swap with CANARY confirmation and
 *      own-data-reflection false-positive filtering (§25) — turning a candidate
 *      into a CONFIRMED cross-user read. The swap replaces the id at its parameter
 *      boundary only (one path segment, one parameter / cookie / header value, one
 *      JSON value located by parsing the body),
 *   4. the verdict for transformed ids: a response is placed by similarity (own view,
 *      "no such object" answer, another identity's view) and confirmed by a canary.
 */
object IdorHunt {

    // ---------------------------------------------------------------------
    // 1. Object-reference format recognition (methodology §1 / §2.1)
    // ---------------------------------------------------------------------

    enum class IdFormat {
        INT, UUID_V1, UUID_V4, UUID_V7, UUID_OTHER, OBJECTID, SNOWFLAKE,
        HASH_MD5, HASH_SHA1, HASH_SHA256, BASE64, GID, SLUG, UNKNOWN
    }

    /** @param confidence 0..100; @param decoded the underlying value for opaque refs (base64/gid). */
    data class IdClassification(
        val format: IdFormat,
        val confidence: Int,
        val note: String,
        val decoded: String? = null
    )

    private val HEX = Regex("^[0-9a-fA-F]+$")
    private val UUID = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    private val INT_RE = Regex("^-?\\d+$")
    private val BASE64_RE = Regex("^[A-Za-z0-9+/]{4,}={0,2}$")
    private val BASE64URL_RE = Regex("^[A-Za-z0-9_-]{4,}={0,2}$")
    private val GID_RE = Regex("^gid://[A-Za-z][A-Za-z0-9_]*/.+$")
    private val SLUG_RE = Regex("^[a-z0-9]+(?:[-_][a-z0-9]+)*$")

    /** Classify a single reference string into its most likely object-id format. */
    fun classify(raw: String): IdClassification {
        val v = raw.trim()
        if (v.isEmpty()) return IdClassification(IdFormat.UNKNOWN, 0, "empty value")

        // gid://Type/ID (Relay/GitHub-style global ids)
        if (GID_RE.matches(v)) return IdClassification(IdFormat.GID, 95, "GraphQL/Relay global id (gid://Type/ID)", v.substringAfterLast('/'))

        // UUID (version nibble is the first char of the 3rd group → index 14)
        if (UUID.matches(v)) {
            return when (v[14]) {
                '1' -> IdClassification(IdFormat.UUID_V1, 95, "UUID v1 — timestamp+MAC, predictable; harvest and window (guidtool/reset-tolkien)")
                '4' -> IdClassification(IdFormat.UUID_V4, 90, "UUID v4 — random; still harvest cross-endpoint refs and test nil/max")
                '7' -> IdClassification(IdFormat.UUID_V7, 92, "UUID v7 — unix-ms prefix, narrow the random tail")
                else -> IdClassification(IdFormat.UUID_OTHER, 80, "UUID v${v[14]} (v3/v5 namespace-hashed if 3/5)")
            }
        }

        // Pure hex: ObjectID (24) or hash (32/40/64). Check BEFORE int so hex-only digits aren't misread.
        if (HEX.matches(v)) {
            when (v.length) {
                24 -> return IdClassification(IdFormat.OBJECTID, 90, "MongoDB ObjectID — 4B ts | 5B machine | 3B counter; sweep ts+counter")
                32 -> return IdClassification(IdFormat.HASH_MD5, 75, "MD5-length hex — confirm own id then hash the input space (hashcat -m0)")
                40 -> return IdClassification(IdFormat.HASH_SHA1, 75, "SHA1-length hex — confirm own id then hash input space (hashcat -m100)")
                64 -> return IdClassification(IdFormat.HASH_SHA256, 75, "SHA256-length hex — confirm own id then hash input space (hashcat -m1400)")
            }
        }

        // Integer: distinguish plain auto-increment from Snowflake (very large).
        if (INT_RE.matches(v)) {
            val digits = v.trimStart('-').length
            val big = v.toLongOrNull()
            return if (digits >= 17 && big != null && big > 4_000_000_000_000_000L) {
                IdClassification(IdFormat.SNOWFLAKE, 70, "Snowflake-scale id — ts=(id>>22)+epoch; brute low 22 bits (worker+seq)")
            } else {
                IdClassification(IdFormat.INT, 90, "Sequential integer — enumerate ±1/±10/±100, boundaries, zero-pad")
            }
        }

        // Opaque base64 (standard or url-safe): decode-modify-re-encode candidate.
        if (BASE64_RE.matches(v) || BASE64URL_RE.matches(v)) {
            val decoded = tryDecodeBase64(v)
            if (decoded != null) {
                // base64('Type:ID') → treat as a Relay node id
                if (decoded.contains(':') && decoded.substringBefore(':').all { it.isLetterOrDigit() || it == '_' }) {
                    return IdClassification(IdFormat.GID, 80, "Base64 node id (decodes to '$decoded') — decode/inc/re-encode", decoded)
                }
                if (decoded.all { it.code in 32..126 }) {
                    return IdClassification(IdFormat.BASE64, 70, "Base64 opaque ref (decodes to '$decoded') — decode/modify/re-encode", decoded)
                }
            }
            return IdClassification(IdFormat.BASE64, 45, "Base64-shaped opaque ref — try decode/modify/re-encode")
        }

        // Predictable slug (usernames/titles): dictionary-enumerable.
        if (SLUG_RE.matches(v) && v.length <= 40) {
            return IdClassification(IdFormat.SLUG, 40, "Slug/keyword ref — dictionary-enumerate (admin/test/demo/me)")
        }

        return IdClassification(IdFormat.UNKNOWN, 10, "Unrecognized reference — try the generic encoding/HPP/type-juggle set")
    }

    private fun tryDecodeBase64(v: String): String? = try {
        val norm = v.replace('-', '+').replace('_', '/')
        val padded = norm.padEnd((norm.length + 3) / 4 * 4, '=')
        String(java.util.Base64.getDecoder().decode(padded), Charsets.UTF_8)
    } catch (_: Exception) { null }

    // ---------------------------------------------------------------------
    // 2. ID transformation generation (methodology §2 cheat-sheet)
    // ---------------------------------------------------------------------

    data class Mutation(val value: String, val technique: String)

    /**
     * Generate a bounded, de-duplicated transformation set for a reference,
     * tuned by its detected format. Covers the §2 library: numeric neighbours &
     * boundaries, encodings (base64/hex/url/double-url), type-juggling,
     * value-terminating tricks (null-byte, whitespace, extension), and
     * decode-modify-re-encode for opaque refs.
     */
    fun mutations(raw: String, cls: IdClassification = classify(raw), max: Int = 64): List<Mutation> {
        val v = raw.trim()
        val out = LinkedHashMap<String, Mutation>()
        fun add(value: String, technique: String) {
            if (value.isNotEmpty() && value != v && !out.containsKey(value)) out[value] = Mutation(value, technique)
        }

        when (cls.format) {
            IdFormat.INT, IdFormat.SNOWFLAKE -> {
                val n = v.toLongOrNull()
                if (n != null) {
                    listOf(n - 1, n + 1, n - 10, n + 10, n - 100, n + 100, n * 2).forEach { add(it.toString(), "numeric-neighbor") }
                    add("0", "boundary"); add("1", "boundary"); add("-1", "negative")
                    add("2147483647", "int32-max"); add("2147483648", "int32-overflow")
                    add("9223372036854775807", "int64-max")
                    add("0$v", "zero-pad"); add("00$v", "zero-pad"); add("$v.0", "float-coerce")
                    add("${v}e0", "scientific"); add("0x${n.toString(16)}", "hex-literal")
                }
            }
            IdFormat.UUID_V1, IdFormat.UUID_V4, IdFormat.UUID_V7, IdFormat.UUID_OTHER -> {
                add("00000000-0000-0000-0000-000000000000", "uuid-nil")
                add("ffffffff-ffff-ffff-ffff-ffffffffffff", "uuid-max")
                add("00000000-0000-0000-0000-000000000001", "uuid-one")
                // decrement / increment the last group
                bumpUuidTail(v, -1)?.let { add(it, "uuid-tail-decrement") }
                bumpUuidTail(v, +1)?.let { add(it, "uuid-tail-increment") }
            }
            IdFormat.OBJECTID -> {
                bumpHexTail(v, -1)?.let { add(it, "objectid-counter-decrement") }
                bumpHexTail(v, +1)?.let { add(it, "objectid-counter-increment") }
                add("000000000000000000000000", "objectid-nil")
            }
            IdFormat.GID, IdFormat.BASE64 -> {
                cls.decoded?.let { dec ->
                    // decode → mutate the numeric tail → re-encode
                    val tail = Regex("(\\d+)\\s*$").find(dec)
                    if (tail != null) {
                        val num = tail.groupValues[1].toLongOrNull()
                        if (num != null) {
                            listOf(num - 1, num + 1).forEach { newNum ->
                                val newDec = dec.substring(0, tail.range.first) + newNum
                                add(reencodeBase64(raw, newDec), "decode-modify-reencode")
                            }
                        }
                    }
                }
            }
            else -> {
                add("admin", "slug-dictionary"); add("me", "alias"); add("0", "boundary")
            }
        }

        // Generic transforms applicable to any reference (§2 encodings + terminators).
        add(base64(v), "base64-encode")
        add(v.let { java.net.URLEncoder.encode(it, "UTF-8") }, "url-encode")
        add(doubleUrlEncode(v), "double-url-encode")
        add("$v%00", "null-byte-append")
        add("$v ", "trailing-space")
        add(" $v", "leading-space")
        add("$v.json", "extension-append")
        add("$v/../$v", "path-traversal-noop")
        add("[\"$v\"]", "array-type-juggle")

        return out.values.take(max)
    }

    private fun base64(s: String) = java.util.Base64.getEncoder().encodeToString(s.toByteArray(Charsets.UTF_8))
    private fun doubleUrlEncode(s: String): String =
        java.net.URLEncoder.encode(java.net.URLEncoder.encode(s, "UTF-8"), "UTF-8")

    private fun reencodeBase64(original: String, newDecoded: String): String {
        val urlSafe = original.contains('-') || original.contains('_')
        val enc = if (urlSafe) java.util.Base64.getUrlEncoder() else java.util.Base64.getEncoder()
        var s = enc.encodeToString(newDecoded.toByteArray(Charsets.UTF_8))
        if (!original.endsWith("=")) s = s.trimEnd('=')
        return s
    }

    private fun bumpUuidTail(uuid: String, delta: Long): String? {
        val idx = uuid.lastIndexOf('-')
        if (idx < 0) return null
        val head = uuid.substring(0, idx + 1)
        val tail = uuid.substring(idx + 1)
        val n = tail.toBigIntegerOrNull(16) ?: return null
        val bumped = (n + delta.toBigInteger())
        if (bumped.signum() < 0) return null
        return head + bumped.toString(16).padStart(tail.length, '0').takeLast(tail.length)
    }

    private fun bumpHexTail(hex: String, delta: Long): String? {
        if (hex.length < 6) return null
        val head = hex.substring(0, hex.length - 6)
        val tail = hex.substring(hex.length - 6)
        val n = tail.toLongOrNull(16) ?: return null
        val bumped = n + delta
        if (bumped < 0) return null
        return head + bumped.toString(16).padStart(6, '0').takeLast(6)
    }

    private fun String.toBigIntegerOrNull(radix: Int): java.math.BigInteger? =
        try { java.math.BigInteger(this, radix) } catch (_: Exception) { null }

    // ---------------------------------------------------------------------
    // 3. Object-reference location in a raw HTTP request (methodology §0)
    // ---------------------------------------------------------------------

    /**
     * @param location path / query / header / cookie / body-json / body-form.
     * @param name the parameter, header or cookie name; a JSON path (`user.id`, `items[0].id`) for
     *   a JSON body; `segment` for a path segment.
     * @param index for a `path` ref, the 0-based position among the non-empty path segments (two
     *   segments can hold the same value); -1 everywhere else.
     */
    data class ObjectRef(
        val location: String,
        val name: String,
        val value: String,
        val format: IdFormat,
        val index: Int = -1
    )

    private val ID_PARAM_HINT = Regex(
        "(^|[_\\-.])(id|ids|uid|guid|uuid|user_?id|account_?id|owner_?id|org_?id|" +
            "member_?id|group_?id|doc(ument)?_?id|order_?id|invoice_?id|ticket_?id|" +
            "customer_?id|profile_?id|file_?id|object_?id|resource_?id|tenant_?id|" +
            "workspace_?id|team_?id|project_?id|number|ref|key|token|slug)$",
        RegexOption.IGNORE_CASE
    )
    private val AUTH_HEADERS = setOf("authorization", "cookie", "x-api-key", "x-auth-token")

    private val HEAD_END = Regex("\r?\n\r?\n")
    private val ABSOLUTE_PREFIX = Regex("^[A-Za-z][A-Za-z0-9+.-]*://[^/?#]*")

    // What can follow the id inside one path segment: a file extension, matrix parameters.
    private val SEGMENT_SUFFIX = Regex("(?:\\.[A-Za-z][A-Za-z0-9]{0,5})?(?:;.*)?$")

    // Best effort for a body that looks like JSON but does not parse.
    private val JSON_FIELD = Regex("\"([A-Za-z0-9_]+)\"\\s*:\\s*\"?([^\",}\\]]+)\"?")

    /** Where a ref is looked for when its location is not one of the known ones, and how locations rank. */
    private val LOCATIONS = listOf("path", "query", "body-json", "body-form", "cookie", "header")

    /**
     * A raw request cut at its parameter boundaries. Everything that is not replaced is kept as
     * written (line endings included), so [render] returns the original bytes around one new value.
     */
    private class RawRequest(raw: String) {
        private val separator: String
        private val eol: String
        val lines: MutableList<String>
        var body: String

        init {
            val end = HEAD_END.find(raw)
            val head = if (end != null) raw.substring(0, end.range.first) else raw
            separator = end?.value.orEmpty()
            body = if (end != null) raw.substring(end.range.last + 1) else ""
            eol = if (head.contains("\r\n")) "\r\n" else "\n"
            lines = head.split(eol).toMutableList()
        }

        fun render(): String = lines.joinToString(eol) + separator + body
    }

    /** `METHOD target HTTP/x`: the version keeps its leading space, and is empty when there is none. */
    private fun splitRequestLine(line: String): Triple<String, String, String>? {
        val first = line.indexOf(' ')
        if (first <= 0) return null
        val last = line.lastIndexOf(' ')
        return if (last > first && line.startsWith("HTTP/", last + 1)) {
            Triple(line.substring(0, first), line.substring(first + 1, last), line.substring(last))
        } else {
            Triple(line.substring(0, first), line.substring(first + 1), "")
        }
    }

    /** A request target: `prefix` is the scheme://authority of an absolute-form target, else empty. */
    private class Target(val prefix: String, val path: String, val query: String?, val fragment: String?) {
        fun render(path: String = this.path, query: String? = this.query): String =
            prefix + path + (query?.let { "?$it" } ?: "") + (fragment?.let { "#$it" } ?: "")
    }

    private fun splitTarget(target: String): Target {
        val prefix = ABSOLUTE_PREFIX.find(target)?.value.orEmpty()
        val rest = target.substring(prefix.length)
        val hash = rest.indexOf('#')
        val beforeFragment = if (hash >= 0) rest.substring(0, hash) else rest
        val mark = beforeFragment.indexOf('?')
        return Target(
            prefix = prefix,
            path = if (mark >= 0) beforeFragment.substring(0, mark) else beforeFragment,
            query = if (mark >= 0) beforeFragment.substring(mark + 1) else null,
            fragment = if (hash >= 0) rest.substring(hash + 1) else null
        )
    }

    private fun decodeQuery(s: String): String =
        try { java.net.URLDecoder.decode(s, "UTF-8") } catch (_: Exception) { s }

    /** Like [decodeQuery], except that `+` in a path is a plus sign, not a space. */
    private fun decodePath(s: String): String = decodeQuery(s.replace("+", "%2B"))

    /** Where the id of a path segment ends: before a trailing `.ext` and/or `;matrix` part. */
    private fun segmentIdEnd(segment: String): Int {
        val suffix = SEGMENT_SUFFIX.find(segment)?.range?.first ?: segment.length
        return if (suffix > 0) suffix else segment.length
    }

    /**
     * The part of [segment] to keep after the id when the segment holds [value] (`""` for a whole
     * segment, `.json` for `1002.json`), or null when it holds something else.
     */
    private fun segmentSuffix(segment: String, value: String): String? {
        if (segment == value || decodePath(segment) == value) return ""
        val end = segmentIdEnd(segment)
        if (end == segment.length) return null
        val id = segment.substring(0, end)
        return if (id == value || decodePath(id) == value) segment.substring(end) else null
    }

    /**
     * One value of a request that sits between parameter boundaries.
     * @param hint the name the id-parameter heuristic looks at (the innermost key of a JSON path).
     * @param whole for a path segment, the whole segment when [value] is its id part only
     *   (`report.pdf` for `report`): the segment is a boundary too, and may itself be the id.
     */
    private class Param(
        val location: String,
        val name: String,
        val value: String,
        val index: Int = -1,
        val hint: String = name,
        val whole: String = value
    )

    /** `a=1&b=2` as (name, value) pairs; a piece without `=` is not a parameter with a value. */
    private fun pairs(text: String): List<Pair<String, String>> =
        text.split("&").mapNotNull { kv ->
            val eq = kv.indexOf('=')
            if (eq < 0) null else kv.substring(0, eq) to kv.substring(eq + 1)
        }

    /** Every boundary-delimited value of [rawRequest], in the order path, query, headers, cookies, body. */
    private fun params(rawRequest: String): List<Param> {
        val request = RawRequest(rawRequest)
        val out = ArrayList<Param>()

        splitRequestLine(request.lines[0])?.let { (_, rawTarget, _) ->
            val target = splitTarget(rawTarget)
            var n = 0
            for (segment in target.path.split("/")) {
                if (segment.isEmpty()) continue
                out += Param("path", "segment", segment.substring(0, segmentIdEnd(segment)), n++, whole = segment)
            }
            target.query?.let { query -> pairs(query).forEach { (name, value) -> out += Param("query", name, value) } }
        }

        for (i in 1 until request.lines.size) {
            val line = request.lines[i]
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            val name = line.substring(0, colon).trim()
            val value = line.substring(colon + 1).trim()
            if (name.equals("cookie", true)) {
                for (cookie in value.split(";")) {
                    val eq = cookie.indexOf('=')
                    if (eq > 0) out += Param("cookie", cookie.substring(0, eq).trim(), cookie.substring(eq + 1).trim())
                }
            } else if (name.lowercase() !in AUTH_HEADERS) {
                out += Param("header", name, value)
            }
        }

        val body = request.body.trim()
        if (body.startsWith("{") || body.startsWith("[")) {
            val leaves = JsonLeafSpans.scan(request.body)
            if (leaves != null) {
                // true / false / null are never object references.
                leaves.filter { it.quoted || JsonLeafSpans.isNumber(it.value) }
                    .mapTo(out) { Param("body-json", it.path, it.value, hint = it.key) }
            } else {
                JSON_FIELD.findAll(body).forEach { m -> out += Param("body-json", m.groupValues[1], m.groupValues[2].trim()) }
            }
        } else if (body.contains("=") && !body.startsWith("<") && !body.contains('\n')) {
            pairs(body).forEach { (name, value) -> out += Param("body-form", name, value) }
        }
        return out
    }

    /**
     * Locate candidate object references across every injection location the
     * methodology says to test: path segments, query params, JSON/form body
     * fields, identity-style custom headers, and cookies. Auth-bearing headers
     * are skipped (those are the *identity*, not the object under test).
     */
    fun locateRefs(rawRequest: String): List<ObjectRef> {
        val refs = LinkedHashMap<String, ObjectRef>()
        for (p in params(rawRequest)) {
            if (p.value.isEmpty()) continue
            val cls = classify(p.value)
            if (cls.format == IdFormat.UNKNOWN || cls.confidence < 40) continue
            val idLike = when (p.location) {
                "path" -> cls.confidence >= 60 && cls.format != IdFormat.SLUG
                "header" -> ID_PARAM_HINT.containsMatchIn(p.name) || p.name.startsWith("x-", true) && looksLikeId(p.value)
                else -> ID_PARAM_HINT.containsMatchIn(p.hint) || looksLikeId(p.value)
            }
            if (idLike) refs.putIfAbsent("${p.location}|${p.name}|${p.value}|${p.index}", p.toRef(cls.format))
        }
        return refs.values.toList()
    }

    private fun Param.toRef(format: IdFormat = classify(value).format) = ObjectRef(location, name, value, format, index)

    private fun looksLikeId(v: String): Boolean {
        val c = classify(v)
        return c.confidence >= 60 && c.format in setOf(
            IdFormat.INT, IdFormat.SNOWFLAKE, IdFormat.UUID_V1, IdFormat.UUID_V4,
            IdFormat.UUID_V7, IdFormat.UUID_OTHER, IdFormat.OBJECTID, IdFormat.GID
        )
    }

    /**
     * Chooses the reference to swap.
     *
     *  1. A pin by [idValue] and/or [idName] (optionally within [idLocation]) must be found at a
     *     parameter boundary of the request: null when it is not, never a guess.
     *  2. Otherwise the id one of the identities says it owns ([ownedIds]), when the request holds
     *     it in a path segment or an id-named parameter.
     *  3. Otherwise the strongest auto-detected reference (within [idLocation] when given).
     *
     * Where one value sits in several places, a path segment wins over a query parameter, over a
     * body field, over a cookie, over a header; among path segments the last one wins, so the
     * `1` of `/api/1/users/1` is the user and not the API version.
     *
     * @param idName the parameter / cookie / header name, a JSON path or key, or for a path the
     *   0-based segment index.
     */
    fun resolveRef(
        rawRequest: String,
        idLocation: String? = null,
        idValue: String? = null,
        idName: String? = null,
        ownedIds: List<String> = emptyList()
    ): ObjectRef? {
        val all = params(rawRequest).filter {
            it.value.isNotEmpty() && (idLocation == null || it.location.equals(idLocation, true))
        }
        // [p] when it holds [value]; the value may be given decoded where the request carries it
        // URL-encoded, and a whole path segment may be meant where only its id part was recorded.
        fun holding(p: Param, value: String): Param? = when {
            p.value == value -> p
            p.location == "path" && decodePath(p.value) == value -> p
            p.location == "path" && (p.whole == value || decodePath(p.whole) == value) ->
                Param(p.location, p.name, p.whole, p.index, p.hint)
            (p.location == "query" || p.location == "body-form") && decodeQuery(p.value) == value -> p
            else -> null
        }
        fun named(p: Param, name: String) = when (p.location) {
            "path" -> name.toIntOrNull() == p.index || name.equals(p.name, true)
            "header" -> p.name.equals(name, true)
            else -> p.name == name || p.hint == name
        }
        fun best(candidates: List<Param>): ObjectRef? = candidates.maxWithOrNull(
            compareBy<Param>(
                { -LOCATIONS.indexOf(it.location) },
                { if (ID_PARAM_HINT.containsMatchIn(it.hint)) 1 else 0 },
                { it.index }
            )
        )?.toRef()

        if (idValue != null || idName != null) {
            val pinned = if (idValue == null) all else all.mapNotNull { holding(it, idValue) }
            return best(pinned.filter { idName == null || named(it, idName) })
        }
        // An owned id counts on its own where ids live (a path segment, an id-named parameter);
        // an id-less match such as `page=1` for the owned id `1` only when nothing else is found.
        val owned = ownedIds.flatMap { id -> all.mapNotNull { holding(it, id) } }
        best(owned.filter { it.location == "path" || ID_PARAM_HINT.containsMatchIn(it.hint) })?.let { return it }
        return locateRefs(rawRequest)
            .filter { idLocation == null || it.location.equals(idLocation, true) }
            .maxWithOrNull(compareBy<ObjectRef>({ classify(it.value).confidence }, { it.index }))
            ?: best(owned)
    }

    private const val PATH_RESERVED = "?#"
    private const val QUERY_RESERVED = "&#+"
    private const val COOKIE_RESERVED = ";,"
    private const val HEX_DIGITS = "0123456789ABCDEF"

    /**
     * Percent-encodes only what would break the syntax around a swapped value: whitespace,
     * control and non-ASCII characters, plus [reserved]. `%` is left alone, so a mutation that is
     * already encoded (`%00`, a double URL-encoding) reaches the wire as written.
     */
    private fun percentEncode(value: String, reserved: String): String {
        if (value.all { it.code in 0x21..0x7E && it !in reserved }) return value
        val out = StringBuilder(value.length + 8)
        var i = 0
        while (i < value.length) {
            val codePoint = value.codePointAt(i)
            val width = Character.charCount(codePoint)
            if (codePoint in 0x21..0x7E && codePoint.toChar() !in reserved) {
                out.append(codePoint.toChar())
            } else {
                for (b in value.substring(i, i + width).toByteArray(Charsets.UTF_8)) {
                    out.append('%').append(HEX_DIGITS[(b.toInt() shr 4) and 0xF]).append(HEX_DIGITS[b.toInt() and 0xF])
                }
            }
            i += width
        }
        return out.toString()
    }

    /**
     * Replace a located object reference's value with [newValue] at its parameter boundary: the
     * path segment, the value of the query / form parameter or cookie, the header value, or the
     * JSON value found by parsing the body. Nothing else in the request changes, so `1` -> `2` in
     * `/v1/users/1` gives `/v1/users/2`, and `id=1` never touches `user_id=1` or `id=12`. Used by
     * the bridge to swap the object id for a cross-identity replay while leaving the identity
     * (auth) untouched.
     *
     * Returns [rawRequest] unchanged when the reference is not in the request. `Content-Length`
     * is the sender's job ([AuthIdentityApplier.apply] recomputes it).
     */
    fun applySwap(rawRequest: String, ref: ObjectRef, newValue: String): String {
        val request = RawRequest(rawRequest)
        val location = ref.location.lowercase()
        val changed = if (location in LOCATIONS) {
            swapAt(request, location, ref, newValue)
        } else {
            LOCATIONS.any { swapAt(request, it, ref, newValue) }
        }
        return if (changed) request.render() else rawRequest
    }

    private fun swapAt(request: RawRequest, location: String, ref: ObjectRef, newValue: String): Boolean = when (location) {
        "path" -> swapPath(request, ref, newValue)
        "query" -> swapQuery(request, ref, newValue)
        "header" -> swapHeader(request, ref, newValue)
        "cookie" -> swapCookie(request, ref, newValue)
        "body-json" -> swapJsonBody(request, ref, newValue)
        "body-form" -> swapFormBody(request, ref, newValue)
        else -> false
    }

    private fun swapPath(request: RawRequest, ref: ObjectRef, newValue: String): Boolean {
        val (method, rawTarget, version) = splitRequestLine(request.lines[0]) ?: return false
        val target = splitTarget(rawTarget)
        var n = -1
        var changed = false
        val path = target.path.split("/").joinToString("/") { segment ->
            if (segment.isEmpty()) return@joinToString segment
            n++
            if (ref.index >= 0 && ref.index != n) return@joinToString segment
            val suffix = segmentSuffix(segment, ref.value) ?: return@joinToString segment
            changed = true
            percentEncode(newValue, PATH_RESERVED) + suffix
        }
        if (changed) request.lines[0] = "$method ${target.render(path = path)}$version"
        return changed
    }

    private fun swapQuery(request: RawRequest, ref: ObjectRef, newValue: String): Boolean {
        val (method, rawTarget, version) = splitRequestLine(request.lines[0]) ?: return false
        val target = splitTarget(rawTarget)
        val swapped = swapPairs(target.query ?: return false, ref, newValue) ?: return false
        request.lines[0] = "$method ${target.render(query = swapped)}$version"
        return true
    }

    /** [text] (`a=1&b=2`) with the value of each pair that is [ref] replaced, or null when none is. */
    private fun swapPairs(text: String, ref: ObjectRef, newValue: String): String? {
        var changed = false
        val out = text.split("&").joinToString("&") { kv ->
            val eq = kv.indexOf('=')
            if (eq < 0) return@joinToString kv
            val name = kv.substring(0, eq)
            val value = kv.substring(eq + 1)
            val sameName = ref.name.isEmpty() || name == ref.name || decodeQuery(name) == ref.name
            if (!sameName || (value != ref.value && decodeQuery(value) != ref.value)) return@joinToString kv
            changed = true
            name + "=" + percentEncode(newValue, QUERY_RESERVED)
        }
        return if (changed) out else null
    }

    private fun swapHeader(request: RawRequest, ref: ObjectRef, newValue: String): Boolean {
        for (i in 1 until request.lines.size) {
            val line = request.lines[i]
            val colon = line.indexOf(':')
            if (colon <= 0) continue
            val name = line.substring(0, colon).trim()
            val wanted = if (ref.name.isEmpty()) name.lowercase() !in AUTH_HEADERS else name.equals(ref.name, true)
            val value = line.substring(colon + 1)
            if (!wanted || value.trim() != ref.value) continue
            request.lines[i] = line.substring(0, colon + 1) + value.substring(0, value.length - value.trimStart().length) + newValue
            return true
        }
        return false
    }

    private fun swapCookie(request: RawRequest, ref: ObjectRef, newValue: String): Boolean {
        var changed = false
        for (i in 1 until request.lines.size) {
            val line = request.lines[i]
            val colon = line.indexOf(':')
            if (colon <= 0 || !line.substring(0, colon).trim().equals("cookie", true)) continue
            val cookies = line.substring(colon + 1).split(";").joinToString(";") { cookie ->
                val eq = cookie.indexOf('=')
                if (eq < 0) return@joinToString cookie
                val value = cookie.substring(eq + 1)
                val sameName = ref.name.isEmpty() || cookie.substring(0, eq).trim() == ref.name
                if (!sameName || value.trim() != ref.value) return@joinToString cookie
                changed = true
                cookie.substring(0, eq + 1) + percentEncode(newValue, COOKIE_RESERVED) + value.substring(value.trimEnd().length)
            }
            request.lines[i] = line.substring(0, colon + 1) + cookies
        }
        return changed
    }

    private fun swapJsonBody(request: RawRequest, ref: ObjectRef, newValue: String): Boolean {
        val leaves = JsonLeafSpans.scan(request.body) ?: return swapJsonText(request, ref, newValue)
        val holding = leaves.filter { it.value == ref.value }
        val targets = holding.filter { it.path == ref.name }
            .ifEmpty { holding.filter { it.key == ref.name } }
            .ifEmpty { if (ref.name.isEmpty()) holding else emptyList() }
        if (targets.isEmpty()) return false
        val body = StringBuilder(request.body)
        // Last span first, so the spans still to be replaced keep their offsets.
        for (leaf in targets.sortedByDescending { it.start }) {
            body.replace(leaf.start, leaf.end, JsonLeafSpans.render(leaf, newValue))
        }
        request.body = body.toString()
        return true
    }

    /** For a body that is JSON-like but does not parse: the field `"name": value`, at value boundaries. */
    private fun swapJsonText(request: RawRequest, ref: ObjectRef, newValue: String): Boolean {
        val key = ref.name.substringAfterLast('.')
        if (key.isEmpty()) return false
        val old = Regex.escape(ref.value)
        val field = Regex("(\"${Regex.escape(key)}\"\\s*:\\s*)(\"$old\"|$old(?![\\w.-]))")
        var changed = false
        val body = field.replace(request.body) { m ->
            changed = true
            val bare = !m.groupValues[2].startsWith("\"") && JsonLeafSpans.isNumber(newValue)
            m.groupValues[1] + if (bare) newValue else JsonLeafSpans.quote(newValue)
        }
        if (changed) request.body = body
        return changed
    }

    private fun swapFormBody(request: RawRequest, ref: ObjectRef, newValue: String): Boolean {
        val form = request.body.trim()
        if (form.isEmpty() || form.startsWith("{") || form.startsWith("[") || form.startsWith("<")) return false
        val swapped = swapPairs(form, ref, newValue) ?: return false
        val start = request.body.indexOf(form)
        request.body = request.body.substring(0, start) + swapped + request.body.substring(start + form.length)
        return true
    }

    // ---------------------------------------------------------------------
    // 4. Canary / signature verdict for HORIZONTAL IDOR (methodology §25)
    // ---------------------------------------------------------------------

    /**
     * One cross-identity read: [reader] requested an object owned by [owner]
     * ([targetId]) and got [status]/[body]. [ownerCanary] is a token that should
     * appear ONLY in the owner's own data; [readerCanary] is the reader's own
     * token (used to catch own-data reflection false positives).
     */
    data class CanaryProbe(
        val reader: String,
        val owner: String,
        val targetId: String,
        val status: Int,
        val body: String,
        val ownerCanary: String?,
        val readerCanary: String?
    )

    data class Finding(val severity: String, val id: String, val detail: String)

    /**
     * True when [canary] appears in [body]. Also matches a body that is raw UTF-8 held one char
     * per byte (how Burp hands a body over), where a non-ASCII canary would otherwise never be found.
     */
    fun containsCanary(body: String, canary: String?): Boolean {
        if (canary.isNullOrBlank()) return false
        if (body.contains(canary)) return true
        if (canary.all { it.code < 0x80 }) return false
        return body.contains(String(canary.toByteArray(Charsets.UTF_8), Charsets.ISO_8859_1))
    }

    /**
     * Grade horizontal-IDOR canary probes. This is the confirmation step the
     * identity-only auth_diff engine cannot do: it asserts that account A's
     * response literally contains account B's canary (A read B's data), while
     * filtering the dominant false positive — the app ignoring the id and just
     * echoing the reader's own data.
     */
    fun assessCanary(probes: List<CanaryProbe>): List<Finding> {
        val findings = mutableListOf<Finding>()
        for (p in probes) {
            if (p.reader == p.owner) continue // baseline / own read
            val sawOwner = containsCanary(p.body, p.ownerCanary)
            val sawReaderOwn = containsCanary(p.body, p.readerCanary)
            // A 2xx that only carries a login page or a denial message is a refusal, unless the
            // owner's canary proves data came back with it.
            val refused = p.status in 200..299 && !sawOwner && AuthDenialHeuristic.looksDenied(p.body)
            val ok = p.status in 200..299 && !refused

            when {
                ok && sawOwner && !sawReaderOwn ->
                    findings.add(Finding("critical", "confirmed_horizontal_idor",
                        "CONFIRMED: '${p.reader}' read '${p.owner}'s object ${p.targetId} — the response contains ${p.owner}'s canary and not ${p.reader}'s own. Cross-user data exposure (IDOR/BOLA)."))
                ok && sawOwner ->
                    findings.add(Finding("high", "canary_ambiguous",
                        "'${p.reader}' → ${p.owner}'s object ${p.targetId} returned 2xx containing BOTH canaries — likely a shared/merged view; verify manually whether ${p.owner}'s private fields leaked."))
                ok && sawReaderOwn ->
                    findings.add(Finding("info", "own_data_reflection_fp",
                        "'${p.reader}' → ${p.owner}'s object ${p.targetId} returned the reader's OWN data (own canary, not the owner's) — the app ignores the object id; not an IDOR. Try a different injection location."))
                ok && p.ownerCanary.isNullOrBlank() ->
                    findings.add(Finding("high", "candidate_needs_canary",
                        "'${p.reader}' → ${p.owner}'s object ${p.targetId} returned ${p.status} but no canary was provided to confirm ownership — CANDIDATE; supply an owner canary to promote to confirmed."))
                ok ->
                    findings.add(Finding("high", "candidate_2xx_no_leak",
                        "'${p.reader}' → ${p.owner}'s object ${p.targetId} returned ${p.status} but the owner canary was absent — candidate: response may be a stub/empty; inspect body."))
                refused ->
                    findings.add(Finding("info", "soft_denied",
                        "'${p.reader}' → ${p.owner}'s object ${p.targetId} returned ${p.status}, but the body is a login page or a denial message — treated as denied."))
                p.status in 401..403 -> {} // properly denied — no finding
                else ->
                    findings.add(Finding("info", "denied_or_error",
                        "'${p.reader}' → ${p.owner}'s object ${p.targetId} returned ${p.status} — not accessible; if 404 try a status/timing/error oracle for blind IDOR."))
            }
        }
        return findings
    }

    // ---------------------------------------------------------------------
    // 5. Verdict for id TRANSFORMATIONS (neighbours, encodings, type juggling)
    // ---------------------------------------------------------------------

    /** Body similarity (0-100) from which a transformed-id response counts as the reader's own view. */
    const val OWN_VIEW_SIMILARITY = 95.0

    /** Body similarity from which a response counts as the server's "no such object" answer. */
    const val MISS_SIMILARITY = 95.0

    /** Body similarity from which a response counts as another identity's view of its own object. */
    const val OTHER_VIEW_SIMILARITY = 90.0

    /**
     * Another identity of the run.
     * @param canary a string only in that identity's own data.
     * @param ownView what that identity gets for its own object, when it was fetched.
     */
    data class OtherIdentity(val name: String, val canary: String?, val ownView: String? = null)

    /**
     * What a transformed-id response is measured against.
     * @param ownBody the reader's response to the unmodified request (its own object); null when
     *   that request was not served.
     * @param missBody a 2xx answer to an id that cannot exist (servers that say "not found" with
     *   a 200); null when unknown ids are refused by status.
     * @param readerCanary a string only in the reader's own data.
     */
    data class TransformBaseline(
        val ownBody: String?,
        val missBody: String?,
        val readerCanary: String?,
        val others: List<OtherIdentity>
    )

    /**
     * @param severity critical / high / medium for a result worth reporting, `info` or `none` otherwise.
     * @param candidate the response is data the reader should not have got, or may be.
     * @param similarityToOwn body similarity to the reader's own view, when there is one.
     * @param matchedIdentity the identity whose data or view the response matches.
     */
    data class TransformVerdict(
        val id: String,
        val severity: String,
        val candidate: Boolean,
        val detail: String,
        val similarityToOwn: Double? = null,
        val matchedIdentity: String? = null
    )

    /**
     * Grades one transformed-id replay ([technique] produced [value]; [reader] got [status] / [body]).
     *
     * A 2xx alone means nothing here: most mutations make the server normalise the id back to the
     * reader's own object, ignore it, or answer "not found" with a 200. So the response is first
     * placed by similarity (own view, "no such object" answer, another identity's own view) and
     * a cross-user read is only confirmed by a canary: data that belongs to another identity, and
     * is not part of the reader's own view, actually appears in it.
     */
    fun assessTransform(
        reader: String,
        technique: String,
        value: String,
        status: Int,
        body: String,
        baseline: TransformBaseline,
        similarity: (String, String) -> Double
    ): TransformVerdict {
        val own = baseline.ownBody
        val simOwn = own?.let { similarity(body, it) }
        val probe = "$technique '$value'"
        fun verdict(id: String, severity: String, candidate: Boolean, detail: String, matched: String? = null) =
            TransformVerdict(id, severity, candidate, detail, simOwn, matched)

        if (status == 0) return verdict("no_response", "none", false, "$probe: no response.")
        if (status !in 200..299) return verdict("denied", "none", false, "$probe returned $status — not served.")

        val sawOwn = containsCanary(body, baseline.readerCanary)
        // A canary the reader's own view carries too is shared data, not proof of a foreign read.
        val foreign = baseline.others.firstOrNull {
            containsCanary(body, it.canary) && !(own != null && containsCanary(own, it.canary))
        }
        if (foreign != null) {
            return if (!sawOwn) {
                verdict(
                    "confirmed_cross_identity_read", "critical", true,
                    "CONFIRMED: $probe made '$reader' receive '${foreign.name}'s data — the response contains ${foreign.name}'s canary and not $reader's own. Cross-user data exposure (IDOR/BOLA).",
                    foreign.name
                )
            } else {
                verdict(
                    "canary_ambiguous", "high", true,
                    "$probe returned $status containing BOTH '$reader's and '${foreign.name}'s canaries — likely a shared/merged view; verify manually whether ${foreign.name}'s private fields leaked.",
                    foreign.name
                )
            }
        }
        if (AuthDenialHeuristic.looksDenied(body)) {
            return verdict("soft_denied", "none", false, "$probe returned $status, but the body is a login page or a denial message — treated as denied.")
        }
        if (sawOwn || (own != null && body == own)) {
            return verdict("own_object", "info", false, "$probe returned '$reader's own data — the server resolves it to the same object or ignores the id.")
        }
        if (body.isBlank()) return verdict("empty_response", "none", false, "$probe returned $status with an empty body.")
        val miss = baseline.missBody
        if (miss != null && similarity(body, miss) >= MISS_SIMILARITY) {
            return verdict("not_found_like", "none", false, "$probe returned $status, but the body is the server's answer for an id that does not exist.")
        }

        val closest = baseline.others
            .mapNotNull { other -> other.ownView?.let { other to similarity(body, it) } }
            .maxByOrNull { it.second }
        if (closest != null && closest.second >= OTHER_VIEW_SIMILARITY && closest.second > (simOwn ?: 0.0)) {
            val (other, score) = closest
            return verdict(
                "matches_other_identity_view", "high", true,
                "$probe returned $status with a body $score% similar to what '${other.name}' gets for its own object — '$reader' appears to read ${other.name}'s data. No canary confirms it; supply one for '${other.name}'.",
                other.name
            )
        }
        // Without a usable canary of the reader, a near-copy of its own view is taken as its own object.
        val ownCanaryUsable = own != null && containsCanary(own, baseline.readerCanary)
        if (!ownCanaryUsable && simOwn != null && simOwn >= OWN_VIEW_SIMILARITY) {
            return verdict("own_object", "info", false, "$probe returned a body $simOwn% similar to '$reader's own view — the same object, or a look-alike that only a canary can tell apart.")
        }
        return verdict(
            "unverified_object", "medium", true,
            "$probe returned $status with a body that is neither '$reader's own view nor a not-found answer — another object was served, but no canary shows whose. Candidate: inspect it, or give the identities canaries."
        )
    }

    /**
     * An id shaped like [value] that should not exist, to learn what the server answers for an
     * unknown object. Integers go above the given id (lower ones belong to older objects) and
     * stay within 32 bits while the given id does, so the probe is not rejected as out of range.
     */
    fun missProbeValue(
        value: String,
        cls: IdClassification = classify(value),
        random: kotlin.random.Random = kotlin.random.Random.Default
    ): String {
        val v = value.trim()
        fun randomOf(alphabet: String, length: Int) = buildString(length) { repeat(length) { append(alphabet[random.nextInt(alphabet.length)]) } }
        fun hex(length: Int) = randomOf("0123456789abcdef", length)
        fun slug() = "zz-" + randomOf("abcdefghijklmnopqrstuvwxyz", 12)
        return when (cls.format) {
            IdFormat.INT, IdFormat.SNOWFLAKE -> {
                val n = v.toLongOrNull()?.let { if (it < 0) -it else it }?.takeIf { it >= 0 } ?: 0L
                val floor = when {
                    n < 190_000_000L -> 1_900_000_000L
                    n < 2_100_000_000L -> 2_100_000_000L
                    n > Long.MAX_VALUE / 10 -> Long.MAX_VALUE - 1_000_000L
                    else -> n * 10
                }
                (floor + random.nextInt(1_000_000)).toString()
            }
            IdFormat.UUID_V1, IdFormat.UUID_V4, IdFormat.UUID_V7, IdFormat.UUID_OTHER -> "ffffffff-ffff-4fff-bfff-${hex(12)}"
            IdFormat.OBJECTID -> "ffffffff${hex(16)}"
            IdFormat.HASH_MD5, IdFormat.HASH_SHA1, IdFormat.HASH_SHA256 -> hex(v.length)
            IdFormat.GID, IdFormat.BASE64 -> {
                val decoded = cls.decoded
                val tail = decoded?.let { Regex("(\\d+)\\s*$").find(it) }
                when {
                    GID_RE.matches(v) -> v.substringBeforeLast('/') + "/" + missProbeValue(v.substringAfterLast('/'), random = random)
                    decoded != null && tail != null ->
                        reencodeBase64(v, decoded.substring(0, tail.range.first) + missProbeValue(tail.groupValues[1], random = random))
                    else -> reencodeBase64(v, slug())
                }
            }
            IdFormat.SLUG, IdFormat.UNKNOWN -> slug()
        }
    }

    /** Highest severity present, for a one-line summary. */
    fun topSeverity(findings: List<Finding>): String = when {
        findings.any { it.severity == "critical" } -> "critical"
        findings.any { it.severity == "high" } -> "high"
        findings.any { it.severity == "medium" } -> "medium"
        findings.any { it.severity == "low" } -> "low"
        findings.any { it.severity == "info" } -> "info"
        else -> "none"
    }
}
