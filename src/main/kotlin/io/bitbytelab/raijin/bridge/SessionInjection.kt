package io.bitbytelab.raijin.bridge

import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.requests.HttpRequest
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.safety.HeaderSafety
import io.bitbytelab.raijin.state.SessionRule
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.time.Instant
import burp.api.montoya.core.ByteArray as BurpByteArray

/**
 * Puts a session rule's value into a request: a header, a cookie, a form parameter, a URL query
 * parameter or a value in a JSON body. The query string and the JSON body are edited as text, so
 * everything else in the request stays exactly as it was.
 *
 * The value comes from the target's responses, so it is never written where a CR or LF would
 * split the request: a header, a cookie, a form or query parameter (a JSON string escapes them).
 */
internal object SessionInjection {

    /**
     * [request] with the value of every enabled rule among [rules] that has one and applies to
     * [url] injected; a `session.rule.injected` event names each rule that changed the request.
     */
    fun applyRules(
        rules: Collection<SessionRule>,
        request: HttpRequest,
        url: String,
        suiteInScope: () -> Boolean,
        eventBus: EventBus,
    ): HttpRequest {
        var current = request
        for (rule in rules) {
            if (!rule.enabled) continue
            val value = rule.lastExtractedValue ?: continue
            if (!SessionRuleEngine.inScope(rule.scope, rule.scopePattern, url, suiteInScope)) continue
            val before = current
            current = inject(rule, current, value)
            if (current !== before) {
                eventBus.emit("session.rule.injected", buildJsonObject {
                    put("rule", rule.ruleName)
                    put("url", url)
                    put("inject_into", rule.injectInto)
                    put("timestamp", Instant.now().toString())
                })
            }
        }
        return current
    }

    /**
     * [request] with [value], rendered by the rule's template, set where the rule says. An existing
     * header/cookie/parameter/JSON member is updated; a missing one is added only when the rule's
     * `injectIfMissing` is on. Returns [request] itself when nothing changes or the value cannot be
     * written safely.
     */
    fun inject(rule: SessionRule, request: HttpRequest, value: String): HttpRequest {
        val rendered = SessionRuleEngine.render(rule.injectValueTemplate, value)
        val name = rule.injectName
        val add = rule.injectIfMissing
        return when (rule.injectInto.lowercase()) {
            "header" -> {
                if (!HeaderSafety.isValidHeaderName(name) || !HeaderSafety.isValidHeaderValue(rendered)) return request
                val current = request.headerValue(name)
                when {
                    current == rendered -> request
                    current != null -> request.withUpdatedHeader(name, rendered)
                    add -> request.withAddedHeader(name, rendered)
                    else -> request
                }
            }
            "cookie" -> upsertParameter(request, name, rendered, HttpParameterType.COOKIE, add)
            "body" -> upsertParameter(request, name, rendered, HttpParameterType.BODY, add)
            "query" -> {
                if (HeaderSafety.containsCrlf(name) || HeaderSafety.containsCrlf(rendered)) return request
                upsertQuery(request.path(), name, rendered, add)?.let { request.withPath(it) } ?: request
            }
            "json" -> injectJson(request, name, rendered, add)
            else -> request
        }
    }

    /**
     * Whether [request] holds the place this rule injects into (the header, cookie, parameter or
     * JSON member exists), i.e. it carries the rule's session value.
     */
    fun carries(rule: SessionRule, request: HttpRequest): Boolean = when (rule.injectInto.lowercase()) {
        "header" -> request.hasHeader(rule.injectName)
        "cookie" -> request.hasParameter(rule.injectName, HttpParameterType.COOKIE)
        "body" -> request.hasParameter(rule.injectName, HttpParameterType.BODY)
        "query" -> queryHas(request.path(), rule.injectName)
        "json" -> {
            val body = request.body()
            body.length() in 1..JsonPathLite.MAX_DOCUMENT_CHARS &&
                jsonHas(String(body.bytes, Charsets.UTF_8), rule.injectName)
        }
        else -> false
    }

    private fun upsertParameter(request: HttpRequest, name: String, value: String, type: HttpParameterType, add: Boolean): HttpRequest {
        // Cookies serialize into a header and form parameters into the body as written.
        if (HeaderSafety.containsCrlf(name) || HeaderSafety.containsCrlf(value)) return request
        val parameter = if (type == HttpParameterType.COOKIE) HttpParameter.cookieParameter(name, value) else HttpParameter.bodyParameter(name, value)
        return when {
            request.hasParameter(name, type) ->
                if (request.parameterValue(name, type) == value) request else request.withUpdatedParameters(parameter)
            add -> request.withAddedParameters(parameter)
            else -> request
        }
    }

    /**
     * Sets the JSON body member at [path]. An existing scalar is replaced in place on the body's
     * bytes (read one char per byte, the value written as UTF-8), so nothing else in the body
     * changes; otherwise the document is rebuilt as UTF-8. `withBody` keeps Content-Length right.
     */
    private fun injectJson(request: HttpRequest, path: String, value: String, add: Boolean): HttpRequest {
        val body = request.body()
        if (body.length() !in 1..JsonPathLite.MAX_DOCUMENT_CHARS) return request
        val bytes = body.bytes
        val raw = String(bytes, Charsets.ISO_8859_1)
        val inPlace = replaceJsonLeaf(raw, path, String(value.toByteArray(Charsets.UTF_8), Charsets.ISO_8859_1))
        val updated = when {
            inPlace == raw -> return request
            inPlace != null -> inPlace.toByteArray(Charsets.ISO_8859_1)
            else -> (upsertJson(String(bytes, Charsets.UTF_8), path, value, add) ?: return request).toByteArray(Charsets.UTF_8)
        }
        return request.withBody(BurpByteArray.byteArray(*updated))
    }

    // ---------------------------------------------------------------
    // Text-level edits
    // ---------------------------------------------------------------

    /**
     * [target] (a request target: path, optional `?query`) with query parameter [name] set to
     * [value]. The first parameter of that name gets the new value, other parameters and repeats of
     * the name are kept; when the name is absent it is appended if [addIfMissing]. Names are compared
     * as written and [value] is written as is (encode it in the rule's template: `{value|url}`).
     * Null when nothing changes.
     */
    fun upsertQuery(target: String, name: String, value: String, addIfMissing: Boolean): String? {
        val (path, pairs, fragment) = splitTarget(target)
        val index = pairs.indexOfFirst { it.substringBefore('=') == name }
        val updated = when {
            index >= 0 -> {
                val replacement = "$name=$value"
                if (pairs[index] == replacement) return null
                pairs.toMutableList().also { it[index] = replacement }
            }
            addIfMissing -> pairs + "$name=$value"
            else -> return null
        }
        return path + "?" + updated.joinToString("&") + fragment
    }

    /** Whether the query of [target] has a parameter named [name] (compared as written). */
    fun queryHas(target: String, name: String): Boolean =
        splitTarget(target).second.any { it.substringBefore('=') == name }

    /** (path, query parameters as written, `#fragment` or ""). */
    private fun splitTarget(target: String): Triple<String, List<String>, String> {
        val fragmentAt = target.indexOf('#')
        val fragment = if (fragmentAt >= 0) target.substring(fragmentAt) else ""
        val head = if (fragmentAt >= 0) target.substring(0, fragmentAt) else target
        val queryAt = head.indexOf('?')
        val path = if (queryAt >= 0) head.substring(0, queryAt) else head
        val pairs = if (queryAt >= 0 && queryAt + 1 < head.length) head.substring(queryAt + 1).split('&') else emptyList()
        return Triple(path, pairs, fragment)
    }

    /**
     * Why [path] cannot name the place of a value in a JSON body, or null when it can: only member
     * names and array indices lead to one value (no wildcard, no `..`).
     */
    fun validateJsonTarget(path: String): String? {
        val steps = try {
            JsonPathLite.parse(path)
        } catch (e: IllegalArgumentException) {
            return e.message
        }
        if (steps.isEmpty()) return "JSONPath '$path' names the whole document, not a value in it"
        if (steps.any { it.deep || it is JsonPathLite.Step.Wildcard }) {
            return "JSONPath '$path' must name exactly one value to inject into (no '*' and no '..')"
        }
        return null
    }

    /** Whether the JSON [body] has a value at [path] (see [validateJsonTarget]). */
    fun jsonHas(body: String, path: String): Boolean {
        val (steps, root) = parseTarget(body, path) ?: return false
        return JsonPathLite.select(root, steps).isNotEmpty()
    }

    /**
     * The JSON [body] with the scalar at [path] (see [validateJsonTarget]) replaced in place by
     * [value], every other character unchanged; [body] itself when the value is already there. Null
     * when there is no scalar at [path] or its span in the text cannot be told for sure (a key
     * containing '.' or '[', a negative index, a duplicate key).
     */
    fun replaceJsonLeaf(body: String, path: String, value: String): String? {
        val (steps, root) = parseTarget(body, path) ?: return null
        val existing = JsonPathLite.select(root, steps).firstOrNull() as? JsonPrimitive ?: return null
        return replaceLeaf(body, steps, existing, value)
    }

    /**
     * The JSON [body] with the value at [path] (see [validateJsonTarget]) set to [value]. An
     * existing scalar is replaced in place ([replaceJsonLeaf]); a number, boolean or null stays
     * unquoted when [value] is one too, anything else is written as a JSON string. A missing member
     * is added (with the objects leading to it) only if [addIfMissing], rebuilding the document; an
     * array is never extended. Null when [body] is not JSON or nothing changes.
     */
    fun upsertJson(body: String, path: String, value: String, addIfMissing: Boolean): String? {
        val (steps, root) = parseTarget(body, path) ?: return null
        val existing = JsonPathLite.select(root, steps).firstOrNull()
        if (existing is JsonPrimitive) {
            replaceLeaf(body, steps, existing, value)?.let { return it.takeIf { updated -> updated != body } }
        }
        if (existing == null && !addIfMissing) return null
        val replacement = leafFor(existing, value)
        if (replacement == existing) return null
        return set(root, steps, 0, replacement, addIfMissing)?.toString()
    }

    private fun parseTarget(body: String, path: String): Pair<List<JsonPathLite.Step>, JsonElement>? {
        if (body.isBlank() || body.length > JsonPathLite.MAX_DOCUMENT_CHARS || JsonPathLite.exceedsMaxDepth(body)) return null
        if (validateJsonTarget(path) != null) return null
        val root = try { Json.parseToJsonElement(body) } catch (_: Exception) { return null }
        return JsonPathLite.parse(path) to root
    }

    /** Replaces the scalar at [steps] by its span in [body]; null when the span cannot be told for sure. */
    private fun replaceLeaf(body: String, steps: List<JsonPathLite.Step>, existing: JsonPrimitive, value: String): String? {
        val dotted = StringBuilder()
        for (step in steps) {
            when (step) {
                is JsonPathLite.Step.Key -> {
                    // A name with '.' or '[' in it reads like a longer path in the dotted notation.
                    if (step.name.contains('.') || step.name.contains('[')) return null
                    if (dotted.isNotEmpty()) dotted.append('.')
                    dotted.append(step.name)
                }
                is JsonPathLite.Step.Index -> {
                    if (step.index < 0) return null
                    dotted.append('[').append(step.index).append(']')
                }
                is JsonPathLite.Step.Wildcard -> return null
            }
        }
        val leaves = JsonLeafSpans.scan(body) ?: return null
        val target = dotted.toString()
        val leaf = leaves.singleOrNull { it.path == target } ?: return null
        val sameValue = if (existing is JsonNull) leaf.value == "null" else leaf.value == existing.content
        if (!sameValue) return null
        val token = leafFor(existing, value)
        if (token == existing) return body
        return body.substring(0, leaf.start) + token.toString() + body.substring(leaf.end)
    }

    /**
     * The JSON value to write for [value] where [existing] stands: a string, unless a number,
     * boolean or null stands there and [value] is one of those too.
     */
    private fun leafFor(existing: JsonElement?, value: String): JsonElement {
        val bare = existing is JsonPrimitive && !existing.isString &&
            (JsonLeafSpans.isNumber(value) || value == "true" || value == "false" || value == "null")
        return if (bare) Json.parseToJsonElement(value) else JsonPrimitive(value)
    }

    private fun set(node: JsonElement?, steps: List<JsonPathLite.Step>, at: Int, value: JsonElement, create: Boolean): JsonElement? {
        if (at == steps.size) return value
        return when (val step = steps[at]) {
            is JsonPathLite.Step.Key -> {
                val members: Map<String, JsonElement> = when {
                    node is JsonObject -> node
                    (node == null || node is JsonNull) && create -> emptyMap()
                    else -> return null
                }
                val child = members[step.name]
                if (child == null && !create) return null
                val updated = set(child, steps, at + 1, value, create) ?: return null
                JsonObject(LinkedHashMap(members).also { it[step.name] = updated })
            }
            is JsonPathLite.Step.Index -> {
                val array = node as? JsonArray ?: return null
                val index = if (step.index < 0) array.size + step.index else step.index
                if (index !in array.indices) return null
                val updated = set(array[index], steps, at + 1, value, create) ?: return null
                JsonArray(array.toMutableList().also { it[index] = updated })
            }
            is JsonPathLite.Step.Wildcard -> null
        }
    }
}
