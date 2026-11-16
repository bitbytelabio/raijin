package io.bitbytelab.raijin.bridge

/**
 * Pure broken-access-control verdict for auth-diff results. Improves on the old
 * inline check (which only flagged an exact `status == 200` match) by reasoning
 * across the 2xx/3xx range and using body similarity, so it catches an
 * unauthenticated/lower-privilege identity that can read a protected resource.
 *
 * A critical or high finding always needs a level that was actually *granted* something: a 2xx,
 * or a redirect that does not lead to a login page ([LevelResult.isSuccess]), whose body is not
 * itself a refusal (the `denied` predicate of [assess]). Levels that are refused alike, by status,
 * by a bounce to the login page or by a "200 + please log in" body, only ever yield `info`.
 */
object AuthDiffVerdict {

    // Unambiguous login words count anywhere in a path segment: wp-login.php, user_login, sign_in.
    private val LOGIN_WORD = Regex("(?i)(?:^|[/_.-])(?:log[-_]?[io]n|sign[-_]?[io]n)(?:[/_.;-]|$)")

    // Short or generic names only count as a whole path segment (an extension may follow).
    private val AUTH_SEGMENT = Regex(
        "(?i)(?:^|/)(?:auth|authn|authenticate|authori[sz]e|oauth2?|oidc|sso|cas|saml2?|adfs|session|sessions/new|" +
            "unauthori[sz]ed|unauthenticated|forbidden|access[-_]?denied|denied)(?:[/.;]|$)"
    )

    // Identity-provider hosts: a login-ish first label, or a hosted IdP domain.
    private val AUTH_HOST = Regex(
        "(?i)^(?:login|logon|signin|auth|sso|idp|identity)\\.|" +
            "(?:^|\\.)(?:auth0\\.com|okta\\.com|oktapreview\\.com|onelogin\\.com|b2clogin\\.com|" +
            "microsoftonline\\.com|amazoncognito\\.com|pingone\\.com)$"
    )

    // A query parameter carrying the URL to come back to: the redirect is a wall in front of the resource.
    private val RETURN_PARAM = Regex(
        "(?i)(?:^|&)(?:return[-_]?(?:url|uri|to|path)?|redirect(?:[-_]?(?:url|uri|to|path))?|redir|next|continue|goto|" +
            "dest(?:ination)?|back[-_]?url|came[-_]?from|target[-_]?url|relaystate|service)=(?:/|%2f|https?(?::|%3a))"
    )

    // A login page selected by a query parameter: ?action=login, ?route=account/login.
    private val LOGIN_PARAM = Regex("(?i)(?:^|&)[^=&]*=(?:[^&]*[/=])?(?:log[-_]?[io]n|sign[-_]?[io]n)(?:&|$)")

    private val ABSOLUTE_URL = Regex("^(?:[A-Za-z][A-Za-z0-9+.-]*:)?//([^/?#]*)(.*)$")

    /** A `Location` value cut into the parts the redirect rules look at. */
    private class RedirectTarget(val host: String, val path: String, val query: String, val fragment: String)

    private fun redirectTarget(location: String?): RedirectTarget {
        val target = location.orEmpty().trim()
        val absolute = ABSOLUTE_URL.find(target)
        val host = absolute?.groupValues?.get(1)?.substringAfterLast('@')?.substringBefore(':')?.lowercase().orEmpty()
        val rest = absolute?.groupValues?.get(2) ?: target
        val beforeFragment = rest.substringBefore('#')
        return RedirectTarget(
            host = host,
            path = beforeFragment.substringBefore('?'),
            query = beforeFragment.substringAfter('?', ""),
            fragment = rest.substringAfter('#', ""),
        )
    }

    /**
     * True when [location] sends the client to authenticate (or to a "denied" page) instead of
     * to the resource: a login / SSO path, an identity-provider host, a single-page-app login
     * route in the fragment, or a query carrying the URL to return to.
     *
     * @param requestHost the host the request went to, when known. A redirect that stays on it is
     *   not judged by its host name: an application served from `auth.example.com` redirects to
     *   itself all the time.
     */
    internal fun isAuthRedirect(location: String?, requestHost: String? = null): Boolean {
        if (location.isNullOrBlank()) return false
        val target = redirectTarget(location)
        if (!target.host.equals(requestHost, ignoreCase = true) && AUTH_HOST.containsMatchIn(target.host)) return true
        // Single-page apps route in the fragment: /#/login, /app#!/signin?next=...
        val route = target.fragment.removePrefix("!")
        val routePath = route.substringBefore('?').takeIf { it.startsWith("/") }.orEmpty()
        if (listOf(target.path, routePath).any { LOGIN_WORD.containsMatchIn(it) || AUTH_SEGMENT.containsMatchIn(it) }) return true
        return listOf(target.query, route.substringAfter('?', "")).any {
            RETURN_PARAM.containsMatchIn(it) || LOGIN_PARAM.containsMatchIn(it)
        }
    }

    /**
     * Two levels with the same 3xx status only got the same answer when they are sent to the same
     * place. Compared by path (and host when both give one); the query is ignored because it
     * often carries per-session noise.
     */
    private fun sameRedirectTarget(a: LevelResult, b: LevelResult): Boolean {
        if (a.status !in 300..399) return true
        val ta = redirectTarget(a.location)
        val tb = redirectTarget(b.location)
        if (ta.path.trimEnd('/') != tb.path.trimEnd('/')) return false
        return ta.host.isEmpty() || tb.host.isEmpty() || ta.host == tb.host
    }

    data class LevelResult(
        val name: String,
        val status: Int,
        val body: String,
        val contentType: String? = null,
        val location: String? = null
    ) {
        /** Levels named none/unauth/anonymous are treated as the lower-privilege baseline. */
        val isAuthLevel: Boolean
            get() = !AuthIdentityApplier.isUnauthenticated(name)
        /** A 2xx, or a 3xx that does not send the client to authenticate. */
        val isSuccess: Boolean
            get() = isSuccessOn(null)

        /** [isSuccess] for a request known to have gone to [requestHost] (see [isAuthRedirect]). */
        fun isSuccessOn(requestHost: String?): Boolean = when (status) {
            in 200..299 -> true
            in 300..399 -> !isAuthRedirect(location, requestHost)
            else -> false
        }
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
     * @param denied Says whether a level with a success status was refused all the same (a login
     *   page or an error message served with 200). Defaults to [AuthDenialHeuristic]; a caller that
     *   knows the application's denial fingerprint adds it here.
     */
    fun assess(
        results: List<LevelResult>,
        similarity: (String, String) -> Double,
        url: String? = null,
        allSimilarThreshold: Double = 95.0,
        unauthMatchThreshold: Double = 90.0,
        denied: (LevelResult) -> Boolean = { AuthDenialHeuristic.looksDenied(it.body) },
    ): List<Finding> {
        val findings = mutableListOf<Finding>()
        if (results.size < 2) return findings

        val requestHost = url?.let { redirectTarget(it).host }?.takeIf { it.isNotEmpty() }
        val success = results.map { it.isSuccessOn(requestHost) }
        val softDenied = results.indices.map { success[it] && denied(results[it]) }
        val granted = results.indices.map { success[it] && !softDenied[it] }
        val anyRefused = granted.any { !it }

        val statuses = results.map { it.status }.distinct()
        val allSameStatus = statuses.size == 1
        val first = results.first()
        val allSimilar = results.all { similarity(first.body, it.body) >= allSimilarThreshold }

        // Dominant case: every level gets the same status + near-identical body. Correct signal
        // for a protected resource; a false positive for a static asset (CSS/JS/image/font) that
        // every auth level is *expected* to see identically — downgrade that case instead of
        // flagging it the same as a leaked protected endpoint. And no signal at all when what
        // every level got is a refusal.
        if (allSameStatus && allSimilar) {
            if (granted.none { it }) {
                findings.add(uniformRefusal(first, softlyRefused = success.any { it }))
                return findings
            }
            if (!anyRefused && results.any { it.isAuthLevel } && results.all { sameRedirectTarget(first, it) }) {
                if (StaticAssetHeuristic.looksStatic(first.contentType, url)) {
                    findings.add(
                        Finding(
                            "info", "all_identical_static_asset",
                            "All auth levels return the same status and near-identical bodies, but this looks like a " +
                                "static asset (content-type '${first.contentType ?: "unknown"}') — expected, not a " +
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
            // Same status and body, yet not the same answer for everyone: one level was sent to
            // the login page, the redirects point to different places, or there is no
            // authenticated level to compare with. Judged pair by pair below.
        }

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
        var staticAsset = false
        for (i in results.indices) {
            for (j in i + 1 until results.size) {
                val a = results[i]
                val b = results[j]
                if (a.name.equals(b.name, true)) continue
                // Two unauthenticated baselines agreeing says nothing about access control.
                if (!a.isAuthLevel && !b.isAuthLevel) continue
                if (a.status != b.status || !granted[i] || !granted[j]) continue
                if (!sameRedirectTarget(a, b)) continue
                if (similarity(a.body, b.body) < unauthMatchThreshold) continue
                matchedNames.add(a.name)
                matchedNames.add(b.name)
                // Static only when nobody was refused: an asset one level is denied is protected.
                if (!anyRefused && StaticAssetHeuristic.looksStatic(a.contentType ?: b.contentType, url)) {
                    staticAsset = true
                    continue
                }
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

        results.forEachIndexed { i, u ->
            if (u.isAuthLevel || !success[i] || u.name in matchedNames) return@forEachIndexed
            when {
                softDenied[i] -> findings.add(
                    Finding(
                        "info", "unauth_soft_denial",
                        "'${u.name}' returns ${u.status}, but the body is a login page or a denial message — treated as denied. Check the body preview if the endpoint should be judged on its status alone."
                    )
                )
                u.status in 300..399 && !u.location.isNullOrBlank() -> findings.add(
                    Finding(
                        "info", "unauth_redirected",
                        "'${u.name}' is redirected (${u.status}) to '${u.location}', where no authenticated level is sent — usually a bounce for the missing session, not access. Follow the redirect to confirm."
                    )
                )
                !anyRefused && StaticAssetHeuristic.looksStatic(u.contentType, url) -> staticAsset = true
                else -> findings.add(
                    Finding(
                        "high", "unauth_accessible",
                        "'${u.name}' returns ${u.status} — the endpoint is reachable without authentication; confirm it is meant to be public."
                    )
                )
            }
        }

        if (staticAsset) {
            findings.add(
                Finding(
                    "info", "static_asset_accessible",
                    "Levels can fetch this without being refused, but it looks like a static asset (content type or file extension) — expected, not a vulnerability unless the asset itself is sensitive."
                )
            )
        }

        // Same status across multiple authed identities but differing bodies → classic IDOR shape.
        if (allSameStatus && !allSimilar && !anyRefused && results.count { it.isAuthLevel } >= 2) {
            findings.add(
                Finding(
                    "info", "same_status_diff_body",
                    "All levels share status ${statuses.first()} but bodies differ — if these are different identities, confirm each only sees its own data (IDOR check)."
                )
            )
        }
        return findings
    }

    /**
     * The `info` finding for levels that were all refused in the same way.
     * @param softlyRefused the status was a success one and the refusal is in the body.
     */
    private fun uniformRefusal(first: LevelResult, softlyRefused: Boolean): Finding = when {
        softlyRefused -> Finding(
            "info", "all_identical_soft_denial",
            "All auth levels return ${first.status} with near-identical bodies, and that body is a login page or a denial message — every level is refused; check that the authenticated sessions are still valid."
        )
        first.status in 300..399 -> Finding(
            "info", "all_identical_non_success",
            "All auth levels are redirected (${first.status}) to a login or access-denied page — every level is refused; check that the authenticated sessions are still valid."
        )
        first.status == 0 -> Finding(
            "info", "all_identical_non_success",
            "No auth level received an HTTP response (status 0) — nothing to compare."
        )
        else -> Finding(
            "info", "all_identical_non_success",
            "All auth levels return the same non-success status (${first.status}) and near-identical bodies — endpoint appears to deny or fail uniformly across identities."
        )
    }
}

/**
 * Pure "this success response is itself a refusal" heuristic used by [AuthDiffVerdict]: many
 * applications answer `200` with a login form or an error document instead of 401/403/302, and
 * judged on status alone every such endpoint looks open to everyone.
 *
 * Deliberately narrow, because a response wrongly taken for a denial hides a real finding:
 *  - a denial *message* is only recognised in a short body (an error document, not a data page
 *    that happens to mention the word);
 *  - a login *page* needs a password field AND a login title or login form target, so a
 *    "create user" or "change password" page is not mistaken for one.
 */
object AuthDenialHeuristic {

    /** Longest body judged as a bare denial message; a longer one is a page or a data document. */
    private const val MESSAGE_MAX_CHARS = 2_000

    /** How much of a page is searched for a login form. */
    private const val PAGE_SCAN_CHARS = 100_000

    // Denial words must stand alone and be a value: `is_forbidden`, `forbidden_words` and a JSON
    // key `"forbidden": false` are field names, not refusals.
    private const val NOT_IN_WORD_BEFORE = "(?<![A-Za-z0-9_-])"
    private const val NOT_IN_WORD_AFTER = "(?![A-Za-z0-9_-])(?!\"\\s*:)"

    private val DENIAL_PHRASE = Regex(
        "(?i)$NOT_IN_WORD_BEFORE(?:" +
            "unauthori[sz]ed|unauthenticated|forbidden|" +
            "not[ _-](?:authori[sz]ed|authenticated|allowed|permitted|logged[ _-]in)|" +
            "(?:access|permission)[ _-](?:is[ _-]|was[ _-])?denied|" +
            "insufficient[ _-](?:permissions?|privileges?|rights|scope)|" +
            "(?:authentication|authorization|login|log[ _-]in|sign[ _-]in)[ _-](?:is[ _-])?required|" +
            "authentication[ _-]failed|" +
            "(?:please|must|need[ _-]to|have[ _-]to)[ _-](?:log|sign)[ _-]?in|" +
            "(?:invalid|expired|missing|no)[ _-](?:access[ _-])?(?:token|session|credentials|api[ _-]?key)|" +
            "(?:token|session)[ _-](?:has[ _-]|is[ _-])?(?:expired|invalid)|" +
            "credentials[ _-]were[ _-]not[ _-]provided" +
            ")$NOT_IN_WORD_AFTER"
    )

    // {"code":401,...} / {"status":"403"}: the real status moved into a 200 body.
    private val DENIAL_CODE = Regex(
        "(?i)\"(?:code|status|status_?code|err(?:or)?_?(?:code|no)?)\"\\s*:\\s*\"?40[13]\"?\\s*[,}]"
    )

    private val PASSWORD_FIELD = Regex("(?i)<input\\b[^>]*\\btype\\s*=\\s*[\"']?password\\b")
    private val LOGIN_TITLE = Regex(
        "(?i)<title\\b[^>]*>[^<]*\\b(?:log[ -]?[io]n|sign[ -]?[io]n|authenticat\\w*|single sign[ -]on)\\b[^<]*</title>"
    )
    private val LOGIN_FORM = Regex(
        "(?i)<form\\b[^>]*\\baction\\s*=\\s*[\"']?[^\"'>\\s]*(?:log[-_]?[io]n|sign[-_]?[io]n|authenticate|/auth\\b|/session\\b|/sso\\b)"
    )

    /** True when [body] reads as a refusal: a short denial message or a login page. */
    fun looksDenied(body: String): Boolean = isDenialMessage(body) || isLoginPage(body)

    /** A short body (JSON error, plain text, small error page) that says access was refused. */
    fun isDenialMessage(body: String): Boolean {
        val text = body.trim()
        if (text.isEmpty() || text.length > MESSAGE_MAX_CHARS) return false
        return DENIAL_PHRASE.containsMatchIn(text) || DENIAL_CODE.containsMatchIn(text)
    }

    /** An HTML page with a password field that is titled, or posts, as a login. */
    fun isLoginPage(body: String): Boolean {
        val page = if (body.length > PAGE_SCAN_CHARS) body.substring(0, PAGE_SCAN_CHARS) else body
        return PASSWORD_FIELD.containsMatchIn(page) &&
            (LOGIN_TITLE.containsMatchIn(page) || LOGIN_FORM.containsMatchIn(page))
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
