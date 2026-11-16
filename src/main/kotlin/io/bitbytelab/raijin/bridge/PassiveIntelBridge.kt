package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.safety.InterruptibleCharSequence
import io.bitbytelab.raijin.safety.RegexTimeoutException
import io.bitbytelab.raijin.safety.SafeRegex
import kotlinx.serialization.json.*

class PassiveIntelBridge(private val api: MontoyaApi) {

    // Pre-compiled regex patterns for sensitive data
    private val patterns = mapOf(
        // Cloud credentials
        "aws_access_key" to Regex("(?i)AKIA[0-9A-Z]{16}"),
        "aws_secret_key" to Regex("(?i)(aws_secret_access_key|aws_secret_key|secret_access_key)[\\s]*[=:][\\s]*['\"]?([A-Za-z0-9/+=]{40})"),
        "google_api_key" to Regex("AIza[0-9A-Za-z\\-_]{35}"),
        "google_oauth_token" to Regex("ya29\\.[0-9A-Za-z\\-_]+"),
        "github_token" to Regex("(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"),
        "slack_token" to Regex("xox[bpors]-[0-9a-zA-Z]{10,}"),
        "stripe_key" to Regex("(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}"),
        "heroku_api_key" to Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),

        // Tokens and secrets
        "jwt_token" to Regex("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"),
        "bearer_token" to Regex("(?i)bearer\\s+[a-zA-Z0-9_\\-\\.]+"),
        "basic_auth" to Regex("(?i)basic\\s+[A-Za-z0-9+/=]{10,}"),
        "private_key" to Regex("-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"),

        // Personal data
        "email_address" to Regex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"),
        "ipv4_internal" to Regex("(?:10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)[0-9]+\\.[0-9]+"),
        "phone_number" to Regex("(?:\\+?1[-.\\s]?)?\\(?[0-9]{3}\\)?[-.\\s]?[0-9]{3}[-.\\s]?[0-9]{4}"),

        // Cloud resources
        "s3_bucket" to Regex("(?i)(?:https?://)?[a-z0-9][a-z0-9.-]+\\.s3[.-](?:us|eu|ap|sa|ca|me|af)-[a-z]+-[0-9]+\\.amazonaws\\.com|s3://[a-z0-9][a-z0-9.-]+"),
        "azure_storage" to Regex("(?i)[a-z0-9]+\\.blob\\.core\\.windows\\.net"),
        "gcs_bucket" to Regex("(?i)storage\\.googleapis\\.com/[a-z0-9][a-z0-9._-]+"),

        // URLs and endpoints
        "internal_url" to Regex("(?i)https?://(?:localhost|127\\.0\\.0\\.1|10\\.[0-9.]+|172\\.(?:1[6-9]|2[0-9]|3[01])\\.[0-9.]+|192\\.168\\.[0-9.]+)[:/][^\\s'\"<>]+"),
        "graphql_endpoint" to Regex("(?i)/graphql(?:/|\\?|$)"),
        "api_endpoint" to Regex("(?i)/api/(?:v[0-9]+/)?[a-z_-]+"),

        // Error patterns
        "stack_trace" to Regex("(?i)(?:at\\s+[a-z]+\\.[a-z]+\\.[a-z]+|Traceback \\(most recent|Exception in thread|Fatal error:|SQLSTATE\\[)"),
        "sql_error" to Regex("(?i)(?:mysql_|pg_|sqlite_|ORA-[0-9]+|SQL syntax|syntax error at|unterminated quoted string)"),
        "debug_info" to Regex("(?i)(?:DEBUG|TRACE|stack_trace|backtrace|phpinfo\\(\\)|server_info)"),

        // Version/technology fingerprints
        "server_version" to Regex("(?i)(?:apache|nginx|iis|tomcat|express|flask|django|spring|rails)[/\\s-]+[0-9]+\\.[0-9]+"),
        "framework_version" to Regex("(?i)(?:x-powered-by|x-aspnet-version|x-runtime|x-generator)[:\\s]+[^\\r\\n]+"),
        "php_version" to Regex("(?i)PHP/[0-9]+\\.[0-9]+\\.[0-9]+"),

        // Sensitive paths
        "sensitive_path" to Regex("(?i)/(?:admin|debug|test|staging|internal|backup|config|setup|install|phpinfo|server-status|server-info|\\.env|\\.git|wp-admin|actuator)(?:/|$)")
    )

    /**
     * High-false-positive patterns excluded from the default scan; reported only
     * when explicitly named in `categories` (e.g. UUIDs, emails, phone numbers
     * appear everywhere and are rarely the secret you're hunting).
     */
    private val optInOnly = setOf("email_address", "phone_number", "heroku_api_key")

    /**
     * Patterns whose match must clear a Shannon-entropy bar (bits/char) to be
     * reported — kills "bearer test" / "basic dGVzdA==" style noise while keeping
     * real high-entropy tokens.
     */
    private val entropyGate = mapOf("bearer_token" to 3.0, "basic_auth" to 3.0)

    /**
     * Scan proxy history for sensitive data patterns.
     *
     * @param maxItems Max proxy history items to scan
     * @param inScopeOnly Only scan in-scope items
     * @param categories Optional list of pattern categories to check (default: all)
     * @param hostFilter Optional hostname filter
     * @return JSON with all findings grouped by category
     */
    fun extractIntel(
        maxItems: Int,
        inScopeOnly: Boolean,
        categories: List<String>?,
        hostFilter: String?
    ): JsonObject {
        return try {
            val history = api.proxy().history()
            var items = history.toList()

            // Apply filters
            if (inScopeOnly) {
                items = items.filter {
                    try { api.scope().isInScope(it.finalRequest().url()) } catch (_: Exception) { false }
                }
            }
            if (hostFilter != null) {
                SafeRegex.validate(hostFilter, ignoreCase = true)?.let { err ->
                    return buildJsonObject { put("error", "Invalid host_filter regex: $err") }
                }
                items = items.filter {
                    val h = try { it.finalRequest().httpService().host() } catch (_: Exception) { "" }
                    SafeRegex.containsMatchIn(hostFilter, h, ignoreCase = true)
                }
            }
            items = items.takeLast(maxItems.coerceAtLeast(0))

            // Select patterns to use
            val activePatterns = if (categories != null && categories.isNotEmpty()) {
                patterns.filter { (key, _) -> categories.any { cat -> key.contains(cat, ignoreCase = true) } }
            } else {
                patterns.filterKeys { it !in optInOnly }
            }

            // Scan
            val findings = mutableMapOf<String, MutableList<JsonObject>>()
            var itemsScanned = 0
            val maxBodyScanChars = 200_000

            for (item in items) {
                itemsScanned++
                val url = try { item.finalRequest().url() } catch (_: Exception) { continue }
                val host = try { item.finalRequest().httpService().host() } catch (_: Exception) { "" }

                // Scan request (capped & binary-guarded)
                val rawReqText = try { item.finalRequest().toString() } catch (_: Exception) { "" }
                val requestText = if (BodyText.isProbablyBinary(rawReqText)) "" else rawReqText.take(maxBodyScanChars)
                // Scan response (skip binary MIME/content & cap size)
                val responseText = try {
                    if (!item.hasResponse()) {
                        ""
                    } else {
                        val resp = item.originalResponse()
                        val mime = try { resp.mimeType().name } catch (_: Exception) { null }
                        if (BodyText.isBinaryMime(mime)) {
                            ""
                        } else {
                            val raw = resp.toString()
                            if (BodyText.isProbablyBinary(raw)) "" else raw.take(maxBodyScanChars)
                        }
                    }
                } catch (_: Exception) { "" }

                for ((patternName, regex) in activePatterns) {
                    try {
                        val threshold = entropyGate[patternName]
                        fun addMatch(value: String, location: String) {
                            // Entropy gate: drop low-entropy noise (e.g. "bearer test") for gated patterns.
                            if (threshold != null && io.bitbytelab.raijin.core.Entropy.shannon(value) < threshold) return
                            findings.getOrPut(patternName) { mutableListOf() }.add(buildJsonObject {
                                put("pattern", patternName)
                                put("match", value.take(200))
                                put("location", location)
                                put("url", url)
                                put("host", host)
                            })
                        }
                        if (requestText.isNotEmpty()) {
                            val deadline = System.nanoTime() + 500_000_000L
                            val guardedReq = InterruptibleCharSequence(requestText) { System.nanoTime() > deadline }
                            for (match in regex.findAll(guardedReq)) {
                                guardedReq.disarm()
                                addMatch(match.value, "request")
                            }
                        }
                        if (responseText.isNotEmpty()) {
                            val deadline = System.nanoTime() + 500_000_000L
                            val guardedResp = InterruptibleCharSequence(responseText) { System.nanoTime() > deadline }
                            for (match in regex.findAll(guardedResp)) {
                                guardedResp.disarm()
                                addMatch(match.value, "response")
                            }
                        }
                    } catch (_: RegexTimeoutException) {
                        // Timed out on this item/pattern; continue cleanly
                    } catch (_: Exception) {
                        // Skip this pattern on failure, continue with others
                    }
                }
            }

            // Build result with deduplication
            val dedupedFindings = mutableMapOf<String, MutableList<JsonObject>>()
            for ((category, matchList) in findings) {
                val uniqueMatches = matchList.distinctBy {
                    it["match"]?.jsonPrimitive?.contentOrNull ?: ""
                }
                if (uniqueMatches.isNotEmpty()) {
                    dedupedFindings[category] = uniqueMatches.toMutableList()
                }
            }

            buildJsonObject {
                put("items_scanned", itemsScanned)
                put("total_findings", dedupedFindings.values.sumOf { it.size })
                put("categories_with_findings", dedupedFindings.size)

                // Summary by category
                put("summary", buildJsonObject {
                    dedupedFindings.forEach { (cat, matches) ->
                        put(cat, matches.size)
                    }
                })

                // Detailed findings
                put("findings", buildJsonObject {
                    dedupedFindings.forEach { (cat, matches) ->
                        put(cat, buildJsonArray { matches.forEach { add(it) } })
                    }
                })

                // Available pattern categories
                put("available_categories", buildJsonArray {
                    patterns.keys.forEach { add(it) }
                })
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Passive intel extraction failed: ${e.message}") }
        }
    }
}
