package io.bitbytelab.raijin.bridge

/**
 * Pure broken-access-control verdict for auth-diff results. Improves on the old
 * inline check (which only flagged an exact `status == 200` match) by reasoning
 * across the 2xx/3xx range and using body similarity, so it catches an
 * unauthenticated/lower-privilege identity that can read a protected resource.
 */
object AuthDiffVerdict {

    data class LevelResult(val name: String, val status: Int, val body: String, val contentType: String? = null) {
        /** Levels named none/unauth/anonymous are treated as the lower-privilege baseline. */
        val isAuthLevel: Boolean
            get() = !name.equals("none", true) && !name.equals("unauth", true) && !name.equals("anonymous", true)
        val isSuccess: Boolean get() = status in 200..399
    }

    data class Finding(val severity: String, val id: String, val detail: String)

    /**
     * @param similarity returns 0..100 body similarity (the bridge supplies its
     *   bigram-Dice metric; tests supply an exact-match stub).
     * @param url The (single, shared) target URL all [results] were probed against — auth_diff
     *   sends the same request under different identities, so this is one value, not per-level.
     *   Used only for the static-asset downgrade (file extension fallback when content-type is
     *   missing/generic); omit it and the downgrade falls back to content-type alone. Appended
     *   after [similarity], not between it and [results], so existing positional call sites
     *   (`assess(results, similarityFn)`) keep compiling unchanged.
     * @param allSimilarThreshold Body-similarity percent (0-100) above which every level is considered
     *   "near-identical" for the `all_identical` verdict. Defaults to the historical 95.0; callers that
     *   want a stricter/looser bar (e.g. a live Autorize-style tap tuning sensitivity per rule) can override it.
     * @param unauthMatchThreshold Body-similarity percent (0-100) above which an unauthenticated level's body is
     *   considered a match of an authed level's body for the `unauth_reads_protected` verdict. Defaults to the
     *   historical 90.0.
     */
    fun assess(
        results: List<LevelResult>,
        similarity: (String, String) -> Double,
        url: String? = null,
        allSimilarThreshold: Double = 95.0,
        unauthMatchThreshold: Double = 90.0,
    ): List<Finding> {
        val findings = mutableListOf<Finding>()
        if (results.size < 2) return findings

        val statuses = results.map { it.status }.distinct()
        val allSameStatus = statuses.size == 1
        val firstBody = results.first().body
        val allSimilar = results.all { similarity(firstBody, it.body) >= allSimilarThreshold }

        // Dominant case: every level gets the same status + near-identical body. Correct signal
        // for a protected resource; a false positive for a static asset (CSS/JS/image/font) that
        // every auth level is *expected* to see identically — downgrade that case instead of
        // flagging it the same as a leaked protected endpoint.
        if (allSameStatus && allSimilar) {
            val target = results.first()
            if (StaticAssetHeuristic.looksStatic(target.contentType, url)) {
                findings.add(
                    Finding(
                        "info", "all_identical_static_asset",
                        "All auth levels return the same status and near-identical bodies, but this looks like a " +
                            "static asset (content-type '${target.contentType ?: "unknown"}') — expected, not a " +
                            "vulnerability unless the asset itself is sensitive."
                    )
                )
            } else {
                findings.add(
                    Finding(
                        "critical", "all_identical",
                        "All auth levels return the same status and near-identical bodies — likely missing authorization checks."
                    )
                )
            }
            return findings
        }

        val authLevels = results.filter { it.isAuthLevel }
        val unauthLevels = results.filter { !it.isAuthLevel }

        // Pairwise cross-identity match: does ANY two different-named levels share a status and a
        // near-identical body? Covers both "an unauth level reads what an authed level reads"
        // (existing) AND the case the old unauth-only loop missed entirely — two DIFFERENT
        // authenticated identities (e.g. "captured"/the browsing session, and a lower-privilege
        // "low_priv" identity) getting the same protected content, while an unrelated third level
        // (e.g. "none") differs in status. That third level pulls allSameStatus false, so the
        // all-identical branch above never fires, but captured/low_priv matching each other is
        // still exactly the broken-access-control signal Autorize's documented
        // "low-priv identity + none" setup is supposed to catch.
        val matchedNames = mutableSetOf<String>()
        for (i in results.indices) {
            for (j in i + 1 until results.size) {
                val a = results[i]
                val b = results[j]
                if (a.name.equals(b.name, true)) continue
                if (a.status != b.status || !a.isSuccess) continue
                if (similarity(a.body, b.body) < unauthMatchThreshold) continue
                matchedNames.add(a.name)
                matchedNames.add(b.name)
                if (!a.isAuthLevel || !b.isAuthLevel) {
                    val unauthSide = if (!a.isAuthLevel) a else b
                    val authSide = if (a.isAuthLevel) a else b
                    findings.add(
                        Finding(
                            "critical", "unauth_reads_protected",
                            "'${unauthSide.name}' returns ${unauthSide.status} with a body ~matching authed level '${authSide.name}' — broken access control: the protected resource is served without proper authorization."
                        )
                    )
                } else {
                    findings.add(
                        Finding(
                            "critical", "cross_identity_match",
                            "'${a.name}' and '${b.name}' both return status ${a.status} with near-identical bodies — broken access control: '${b.name}' may be able to access data belonging to '${a.name}'."
                        )
                    )
                }
            }
        }

        for (u in unauthLevels) {
            if (!u.isSuccess || u.name in matchedNames) continue
            findings.add(
                Finding(
                    "high", "unauth_accessible",
                    "'${u.name}' returns ${u.status} (2xx/3xx) — the endpoint is reachable without authentication; confirm it is meant to be public."
                )
            )
        }

        // Same status across multiple authed identities but differing bodies → classic IDOR shape.
        // (allSimilar is already known false here: the allSameStatus&&allSimilar case returned above.)
        if (allSameStatus && authLevels.size >= 2) {
            findings.add(
                Finding(
                    "info", "same_status_diff_body",
                    "All levels share status ${statuses.first()} but bodies differ — if these are different identities, confirm each only sees its own data (IDOR check)."
                )
            )
        }
        return findings
    }
}

/**
 * Pure "does this look like a static asset" heuristic used by [AuthDiffVerdict]'s
 * `all_identical` downgrade — a CSS/JS/image/font file is *expected* to read identically
 * across every auth level; a protected API resource reading identically is the signal worth
 * flagging as `critical` instead.
 */
object StaticAssetHeuristic {

    private val staticContentTypePrefixes = listOf("text/css", "javascript", "image/", "font/")

    private val staticExtensions = setOf(
        "css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif",
        "woff", "woff2", "ttf", "otf", "eot"
    )

    /**
     * True when [contentType] (a response `Content-Type` value, with or without a charset
     * suffix) or [url]'s file extension indicates a static asset. Either signal alone is
     * sufficient — a CDN sometimes serves `.css` as `text/plain`, and a content-type can be
     * missing entirely on some responses.
     */
    fun looksStatic(contentType: String?, url: String? = null): Boolean {
        val type = contentType?.substringBefore(';')?.trim()?.lowercase()
        if (type != null && staticContentTypePrefixes.any { type.contains(it) }) return true

        val path = url?.substringBefore('?')?.substringBefore('#')
        val ext = path?.substringAfterLast('.', missingDelimiterValue = "")?.lowercase()
        return !ext.isNullOrEmpty() && ext in staticExtensions
    }
}
