package io.bitbytelab.raijin.webprobe

import io.bitbytelab.raijin.recon.UrlParts

/**
 * Pure CORS verdicts: which Origin values to send for a target, and what the response's
 * Access-Control-* headers mean for each.
 */
object CorsAnalysis {
    data class Verdict(val severity: String, val id: String, val detail: String)

    /** One Origin to send and the allowlist mistake it tests for ([kind]). */
    data class OriginTest(val kind: String, val origin: String)

    /** What a preflight (OPTIONS) response said. */
    data class Preflight(
        val status: Int,
        val acao: String?,
        val acac: String?,
        val allowMethods: String?,
        val allowHeaders: String?,
    )

    /** An unrelated origin: echoed back when the server reflects whatever it is sent. */
    const val ARBITRARY = "arbitrary"

    /** The `null` origin, sent by sandboxed iframes and `data:` documents. */
    const val NULL = "null"

    /** `https://<host>.<other domain>`: passes a check that the origin starts with the trusted host. */
    const val TARGET_AS_PREFIX = "target_as_prefix"

    /** `https://<junk><domain>`: passes a check that the origin ends with the trusted domain. */
    const val TARGET_AS_SUFFIX = "target_as_suffix"

    /** The host with a dot replaced by a letter: passes a regex whose dots are not escaped. */
    const val UNESCAPED_DOT = "unescaped_dot"

    /** `https://<host>_.<other domain>`: passes a regex that takes `_` for the end of the host name. */
    const val UNDERSCORE = "underscore"

    /** A made-up subdomain of the host: trusted when every subdomain is. */
    const val SUBDOMAIN = "subdomain"

    /** The host over plain http: trusted when the scheme is not checked. */
    const val HTTP_DOWNGRADE = "http_downgrade"

    /** Reserved domain (RFC 2606) the crafted origins live under; nobody can register it. */
    const val PROBE_DOMAIN = "raijin-cors-probe.example"
    private const val PROBE_LABEL = "raijin-cors-probe"

    /** Method and header a preflight is asked to approve: neither is allowed without one. */
    const val PREFLIGHT_METHOD = "PUT"
    const val PREFLIGHT_HEADER = "x-raijin-probe"

    private val SECOND_LEVEL = setOf("co", "com", "org", "net", "gov", "edu", "ac")

    /**
     * The origins worth sending for [targetUrl]: an unrelated one and `null`, then ones built
     * from the target's own host, each shaped to slip through one common allowlist mistake.
     */
    fun origins(targetUrl: String): List<OriginTest> {
        val out = mutableListOf(OriginTest(ARBITRARY, "https://$PROBE_DOMAIN"), OriginTest(NULL, "null"))
        val target = UrlParts.parse(targetUrl) ?: return out
        val scheme = target.scheme
        val host = target.host
        out.add(OriginTest(TARGET_AS_PREFIX, "$scheme://$host.$PROBE_DOMAIN"))
        // The rest only make sense for a DNS name: an IP address has no domain or subdomains.
        if (host.contains('.') && host.any { it.isLetter() } && !host.startsWith("[")) {
            out.add(OriginTest(TARGET_AS_SUFFIX, "$scheme://$PROBE_LABEL${registrable(host)}"))
            val firstDot = host.indexOf('.')
            if (firstDot != host.lastIndexOf('.')) {
                out.add(OriginTest(UNESCAPED_DOT, "$scheme://" + host.replaceRange(firstDot, firstDot + 1, "x")))
            }
            out.add(OriginTest(UNDERSCORE, "$scheme://${host}_.$PROBE_DOMAIN"))
            out.add(OriginTest(SUBDOMAIN, "$scheme://$PROBE_LABEL.$host"))
        }
        if (target.secure) out.add(OriginTest(HTTP_DOWNGRADE, "http://$host"))
        return out
    }

    /** The part of [host] someone registers: its last two labels, or three under a `co.uk`-style suffix. */
    internal fun registrable(host: String): String {
        val labels = host.split('.')
        if (labels.size <= 2) return host
        val twoLevelSuffix = labels.last().length == 2 && labels[labels.size - 2] in SECOND_LEVEL
        return labels.takeLast(if (twoLevelSuffix) 3 else 2).joinToString(".")
    }

    /** Verdict for a plain reflection check: [sentOrigin] against the response's ACAO / ACAC. */
    fun assess(sentOrigin: String, acao: String?, acac: String?): Verdict? =
        assess(OriginTest(if (sentOrigin.trim().equals("null", ignoreCase = true)) NULL else ARBITRARY, sentOrigin), acao, acac)

    /**
     * Verdict for one crafted origin. Access-Control-Allow-Origin is compared trimmed and without
     * regard to case: a server that normalizes the value still allowed the origin.
     */
    fun assess(test: OriginTest, acao: String?, acac: String?): Verdict? {
        val allowed = acao?.trim() ?: return null
        val creds = acac?.trim().equals("true", ignoreCase = true)
        val echoed = allowed.equals(test.origin.trim(), ignoreCase = true)
        val withCreds = if (creds) " with credentials (ACAC=true)" else ""
        return when {
            // Check the null origin first: "null" == "null" is technically a reflection,
            // but it is its own (distinct, attacker-reachable) misconfiguration.
            echoed && test.kind == NULL -> Verdict(
                "high", "null_origin_allowed",
                "ACAO allows the 'null' origin — reachable from sandboxed iframes / data: URLs; with credentials this is exploitable."
            )
            echoed && test.kind == TARGET_AS_PREFIX -> Verdict(
                if (creds) "critical" else "high", "allowlist_bypass_target_as_prefix",
                "ACAO accepts ${test.origin}$withCreds — the allowlist only checks that the origin starts with the trusted host, so any domain of the form <host>.<attacker domain> can read responses."
            )
            echoed && test.kind == TARGET_AS_SUFFIX -> Verdict(
                if (creds) "critical" else "high", "allowlist_bypass_target_as_suffix",
                "ACAO accepts ${test.origin}$withCreds — the allowlist only checks that the origin ends with the trusted domain, so a registrable look-alike domain can read responses."
            )
            echoed && test.kind == UNESCAPED_DOT -> Verdict(
                if (creds) "critical" else "high", "allowlist_bypass_unescaped_dot",
                "ACAO accepts ${test.origin}$withCreds — a dot in the allowlist regex is not escaped, so a registrable domain with any character in its place can read responses."
            )
            echoed && test.kind == UNDERSCORE -> Verdict(
                if (creds) "critical" else "high", "allowlist_bypass_underscore",
                "ACAO accepts ${test.origin}$withCreds — the allowlist regex treats '_' as the end of the host name, so <host>_.<attacker domain> can read responses."
            )
            echoed && test.kind == SUBDOMAIN -> Verdict(
                if (creds) "medium" else "low", "any_subdomain_trusted",
                "ACAO accepts ${test.origin}$withCreds — every subdomain is trusted, so an XSS or takeover on any one of them reads responses here."
            )
            echoed && test.kind == HTTP_DOWNGRADE -> Verdict(
                if (creds) "medium" else "low", "http_origin_trusted",
                "ACAO accepts ${test.origin}$withCreds — the plain-http origin is trusted, so a network attacker who can inject into http traffic reads responses here."
            )
            echoed && creds -> Verdict(
                "critical", "reflected_origin_with_creds",
                "ACAO reflects the request Origin AND ACAC=true — any site can read authenticated responses (account takeover / data theft)."
            )
            echoed -> Verdict(
                "high", "reflected_origin",
                "ACAO reflects the request Origin (no credentials) — any site can read this response cross-origin."
            )
            allowed == "*" && creds -> Verdict(
                "medium", "wildcard_with_creds",
                "ACAO=* together with ACAC=true is an invalid/over-permissive combination; some non-browser clients honor it."
            )
            allowed == "*" -> Verdict(
                "low", "wildcard",
                "ACAO=* — wildcard CORS without credentials; acceptable only for genuinely public data."
            )
            else -> null
        }
    }

    /** True when a `Vary` header value lists `Origin` (or `*`). */
    fun variesOnOrigin(vary: String?): Boolean =
        vary?.split(',', '\n')?.any { it.trim().equals("origin", ignoreCase = true) || it.trim() == "*" } == true

    /**
     * A response whose ACAO follows the request Origin has to say so in `Vary`: otherwise a shared
     * cache hands one origin's CORS headers to the next. Null when ACAO does not echo [test], or
     * `Vary` covers it.
     */
    fun missingVary(test: OriginTest, acao: String?, vary: String?): Verdict? {
        if (acao?.trim().equals(test.origin.trim(), ignoreCase = true).not() || variesOnOrigin(vary)) return null
        return Verdict(
            "low", "missing_vary_origin",
            "ACAO changes with the request Origin but the response has no 'Vary: Origin' — a shared cache can serve these CORS headers to another origin (or store a poisoned variant)."
        )
    }

    /**
     * Verdict for a preflight: the origin verdict, when the response also approves the unsafe
     * [method] or the custom [header] it was asked about with a success status. Null otherwise,
     * since a browser then never sends the actual request.
     */
    fun assessPreflight(
        test: OriginTest,
        preflight: Preflight,
        method: String = PREFLIGHT_METHOD,
        header: String = PREFLIGHT_HEADER,
    ): Verdict? {
        if (preflight.status !in 200..299) return null
        val origin = assess(test, preflight.acao, preflight.acac) ?: return null
        val methods = tokens(preflight.allowMethods)
        val headers = tokens(preflight.allowHeaders)
        val approved = buildList {
            if ("*" in methods || method.lowercase() in methods) add("method $method")
            if ("*" in headers || header.lowercase() in headers) add("header $header")
        }
        if (approved.isEmpty()) return null
        return Verdict(
            origin.severity, "preflight_" + origin.id,
            "Preflight approves ${approved.joinToString(" and ")} for this origin, so it can send more than simple requests. " + origin.detail
        )
    }

    private fun tokens(value: String?): Set<String> =
        value.orEmpty().split(',', '\n').map { it.trim().lowercase() }.filter { it.isNotEmpty() }.toSet()
}
