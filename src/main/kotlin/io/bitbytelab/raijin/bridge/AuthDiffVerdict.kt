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
     */
    fun assess(results: List<LevelResult>, similarity: (String, String) -> Double, url: String? = null): List<Finding> {
        val findings = mutableListOf<Finding>()
        if (results.size < 2) return findings

        val statuses = results.map { it.status }.distinct()
        val allSameStatus = statuses.size == 1
        val firstBody = results.first().body
        val allSimilar = results.all { similarity(firstBody, it.body) >= 95.0 }

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

        for (u in unauthLevels) {
            if (!u.isSuccess) continue
            val match = authLevels.firstOrNull { a -> a.isSuccess && similarity(a.body, u.body) >= 90.0 }
            if (match != null) {
                findings.add(
                    Finding(
                        "critical", "unauth_reads_protected",
                        "'${u.name}' returns ${u.status} with a body ~matching authed level '${match.name}' — broken access control: the protected resource is served without proper authorization."
                    )
                )
            } else {
                findings.add(
                    Finding(
                        "high", "unauth_accessible",
                        "'${u.name}' returns ${u.status} (2xx/3xx) — the endpoint is reachable without authentication; confirm it is meant to be public."
                    )
                )
            }
        }

        // Same status across multiple authed identities but differing bodies → classic IDOR shape.
        if (allSameStatus && authLevels.size >= 2 && !allSimilar) {
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
