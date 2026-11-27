package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.safety.ScopeGate
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.contentOrNull

/**
 * Sends request steps one after the other, extracting values from each response into variables that
 * later steps use through `{{name}}` placeholders. Backs `http_send_request_chain` and the session
 * login macros.
 *
 * A step is a request object ([HttpRequestBuilder.fromObject]) with an optional `extract` array of
 * `{name, pattern | json_path | xpath, from}` rules ([parseExtractRules]).
 */
internal class HttpRequestChain(
    private val api: MontoyaApi,
    private val scopeGate: ScopeGate,
    private val timeouts: HttpTimeouts,
) {

    /**
     * One step's outcome.
     *
     * @param exchange what was sent and received; null when the step failed before or while
     *   sending.
     * @param fixReport fields describing adjustments made while building the request
     *   (`content_length_rewritten`).
     */
    class StepResult(
        val index: Int,
        val exchange: HttpRequestResponse?,
        val elapsedMs: Long?,
        val extracted: Map<String, String>,
        val fixReport: Map<String, JsonElement>,
        val error: String? = null,
        val timeout: Boolean = false,
        val scope: ScopeGate.Check? = null,
        val extractMissed: List<String> = emptyList(),
        val unresolvedPlaceholders: List<String> = emptyList(),
        /** Where a failed step stopped: `build` (nothing sent) or `send`; null on success. */
        val phase: String? = null,
    ) {
        /** Blocked by the scope gate under enforce: nothing was sent. */
        val outOfScope: Boolean
            get() = scope?.blocked == true

        val success: Boolean
            get() = error == null && !outOfScope && exchange?.response() != null
    }

    /** @param variables every value extracted over the whole run, by name. */
    class Result(val steps: List<StepResult>, val variables: Map<String, String>)

    /**
     * Runs [steps].
     *
     * @param stopOnError stop at the first step that fails (could not be built, was blocked by the
     *   scope policy, timed out or failed to send).
     * @param timeoutMs hard timeout of each step; null or 0 for none.
     * @param prepare applied to each built request right before it is sent.
     * @param siteMapNote site map annotation for a sent step; null leaves the site map alone.
     */
    fun run(
        steps: List<JsonObject>,
        mode: HttpMode,
        stopOnError: Boolean,
        connectionId: String? = null,
        timeoutMs: Long? = null,
        prepare: (HttpRequest) -> HttpRequest = { it },
        siteMapNote: ((Int) -> String)? = { "[MCP] Chain step ${it + 1} via Raijin" },
    ): Result {
        val variables = LinkedHashMap<String, String>()
        val results = ArrayList<StepResult>()
        for ((index, step) in steps.withIndex()) {
            val fixReport = LinkedHashMap<String, JsonElement>()
            var scope: ScopeGate.Check? = null
            var unresolved = emptyList<String>()
            var request: HttpRequest? = null
            val result =
                try {
                    val substituted = substituteVariables(step, variables)
                    unresolved = unresolvedPlaceholders(substituted)
                    // Checked before sending, so a malformed extract rule fails the step without a
                    // request.
                    val rules = parseExtractRules(substituted["extract"])
                    val built = prepare(HttpRequestBuilder.fromObject(substituted, fixReport))
                    request = built
                    val check = scopeGate.checkHttpRequest(built)
                    scope = check
                    if (check.blocked) {
                        StepResult(
                            index,
                            null,
                            null,
                            emptyMap(),
                            fixReport,
                            scope = check,
                            unresolvedPlaceholders = unresolved,
                        )
                    } else {
                        val start = System.nanoTime()
                        val exchange =
                            timeouts.run(timeoutMs) {
                                if (connectionId != null)
                                    api.http().sendRequest(built, mode, connectionId)
                                else api.http().sendRequest(built, mode)
                            }
                        val elapsedMs = (System.nanoTime() - start) / 1_000_000
                        siteMapNote?.let {
                            api.recordToolExchange(exchange, it(index), "http_send_request_chain")
                        }
                        val extracted = extract(rules, exchange)
                        variables.putAll(extracted)
                        StepResult(
                            index,
                            exchange,
                            elapsedMs,
                            extracted,
                            fixReport,
                            scope = check,
                            extractMissed = rules.map { it.name }.filter { it !in extracted },
                            unresolvedPlaceholders = unresolved,
                        )
                    }
                } catch (e: Exception) {
                    StepResult(
                        index,
                        null,
                        null,
                        emptyMap(),
                        fixReport,
                        error = e.message ?: "Unknown error",
                        timeout = e is HttpRequestTimeoutException,
                        scope = scope,
                        unresolvedPlaceholders = unresolved,
                        phase = if (request == null) "build" else "send",
                    )
                }
            results += result
            if (!result.success && stopOnError) break
        }
        return Result(results, variables)
    }

    /**
     * One `extract` rule of a step. Header rules read the `Name: value` lines (every `Set-Cookie`
     * too).
     */
    class ExtractRule(
        val name: String,
        val pattern: String?,
        val jsonPath: String?,
        val xpath: String?,
        val fromHeader: Boolean,
    )

    companion object {

        /**
         * Parses a step's `extract` list: a JSON array of `{name, pattern | json_path | xpath,
         * from}` objects (`from` = "body", the default, or "header"; a header rule needs a
         * pattern). A single object instead of an array, a missing name or selector and a pattern,
         * JSONPath or XPath that does not compile are rejected with a message naming the rule.
         */
        fun parseExtractRules(element: JsonElement?): List<ExtractRule> {
            val items =
                when (element) {
                    null,
                    JsonNull -> return emptyList()
                    is JsonArray -> element
                    else ->
                        throw IllegalArgumentException(
                            "'extract' must be a JSON ARRAY of {name,pattern,from} objects, e.g. " +
                                "extract:[{\"name\":\"csrf\",\"pattern\":\"...\",\"from\":\"body\"}]. " +
                                "Got ${element::class.simpleName}.",
                        )
                }
            return items.mapIndexed { i, item ->
                val obj =
                    item as? JsonObject
                        ?: throw IllegalArgumentException(
                            "Each 'extract' item must be a JSON OBJECT with {name,pattern,from}. Got ${item::class.simpleName}.",
                        )
                val name = obj.text("name")
                val pattern = obj.text("pattern")
                val jsonPath = obj.text("json_path")
                val xpath = obj.text("xpath")
                require(!name.isNullOrEmpty()) { "extract[$i] needs a 'name'." }
                require(pattern != null || !jsonPath.isNullOrEmpty() || !xpath.isNullOrEmpty()) {
                    "extract[$i] needs a 'pattern' (regex), a 'json_path' or an 'xpath'."
                }
                if (pattern != null) {
                    SafeRegex.validate(pattern)?.let {
                        throw IllegalArgumentException(
                            "extract[$i].pattern is not a valid regex: $it",
                        )
                    }
                }
                require(jsonPath.isNullOrEmpty() || xpath.isNullOrEmpty()) {
                    "extract[$i]: give a json_path or an xpath, not both."
                }
                if (!jsonPath.isNullOrEmpty()) {
                    try {
                        JsonPathLite.parse(jsonPath)
                    } catch (e: IllegalArgumentException) {
                        throw IllegalArgumentException("extract[$i].json_path: ${e.message}")
                    }
                }
                if (!xpath.isNullOrEmpty()) {
                    XmlXPath.validate(xpath)?.let {
                        throw IllegalArgumentException("extract[$i].xpath is not valid XPath: $it")
                    }
                }
                val from = obj.text("from") ?: "body"
                require(
                    from.equals("body", ignoreCase = true) ||
                        from.equals("header", ignoreCase = true),
                ) {
                    "extract[$i].from must be 'body' or 'header' (got '$from')."
                }
                val fromHeader = from.equals("header", ignoreCase = true)
                require(
                    !fromHeader ||
                        (jsonPath.isNullOrEmpty() && xpath.isNullOrEmpty() && pattern != null),
                ) {
                    "extract[$i]: a header rule takes a 'pattern' over the 'Name: value' lines, not a json_path or xpath."
                }
                ExtractRule(name, pattern, jsonPath, xpath, fromHeader)
            }
        }

        /**
         * The value each rule takes from [headerBlock] (`Name: value` lines) or [body]; rules that
         * match nothing are left out.
         */
        fun extract(
            rules: List<ExtractRule>,
            headerBlock: String,
            body: String,
        ): Map<String, String> {
            val out = LinkedHashMap<String, String>()
            for (rule in rules) {
                val value =
                    if (rule.fromHeader) {
                        ValueSelector.select(headerBlock, null, null, rule.pattern)
                    } else {
                        ValueSelector.select(body, rule.jsonPath, rule.xpath, rule.pattern)
                    }
                if (value != null) out[rule.name] = value
            }
            return out
        }

        /** Replaces `{{name}}` with the variable's value in every string inside [obj]. */
        fun substituteVariables(obj: JsonObject, variables: Map<String, String>): JsonObject =
            if (variables.isEmpty()) obj
            else JsonObject(obj.mapValues { (_, value) -> substitute(value, variables) })

        private fun substitute(element: JsonElement, variables: Map<String, String>): JsonElement =
            when (element) {
                is JsonPrimitive ->
                    if (element.isString) {
                        var text = element.content
                        variables.forEach { (name, value) ->
                            text = text.replace("{{$name}}", value)
                        }
                        JsonPrimitive(text)
                    } else {
                        element
                    }
                is JsonObject ->
                    JsonObject(element.mapValues { (_, value) -> substitute(value, variables) })
                is JsonArray ->
                    buildJsonArray { element.forEach { add(substitute(it, variables)) } }
            }

        private val PLACEHOLDER = Regex("\\{\\{([^{}]+)}}")

        /**
         * Names of `{{x}}` placeholders still present in any string of [obj] after substitution.
         */
        fun unresolvedPlaceholders(obj: JsonElement): List<String> {
            val out = LinkedHashSet<String>()
            fun walk(e: JsonElement) {
                when (e) {
                    is JsonPrimitive ->
                        if (e.isString)
                            PLACEHOLDER.findAll(e.content).forEach { out += it.groupValues[1] }
                    is JsonObject -> e.forEach { (k, v) -> if (k != "extract") walk(v) }
                    is JsonArray -> e.forEach(::walk)
                }
            }
            walk(obj)
            return out.toList()
        }

        private fun JsonObject.text(key: String): String? =
            (this[key] as? JsonPrimitive)?.contentOrNull

        private fun extract(
            rules: List<ExtractRule>,
            exchange: HttpRequestResponse,
        ): Map<String, String> {
            if (rules.isEmpty()) return emptyMap()
            val response = exchange.response() ?: return emptyMap()
            val headerBlock =
                if (rules.any { it.fromHeader }) {
                    response.headers().joinToString("\r\n") { "${it.name()}: ${it.value()}" }
                } else {
                    ""
                }
            val body = if (rules.any { !it.fromHeader }) response.bodyToString() else ""
            return extract(rules, headerBlock, body)
        }
    }
}
