package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.bambda.BambdaImportResult
import kotlinx.serialization.json.*

/**
 * Bridge wrapping the Montoya Bambda API.
 *
 * Bambda expressions are Java-like lambda expressions that can be used
 * to customize Burp Suite's behavior (e.g., proxy history filters,
 * HTTP match-and-replace rules).
 */
class BambdaBridge(private val api: MontoyaApi) {

    /**
     * Imports a Bambda into Burp Suite.
     *
     * A real `.bambda` file is NOT a bare Java lambda expression — it's a YAML-ish envelope:
     * `id`, `name`, `function`, `location`, then a `source:` block holding the lambda body
     * (confirmed against PortSwigger's own `bambdas` reference repo). Montoya's `Bambda.
     * importBambda(String)` takes that whole document as one string and has no separate
     * fields for it — Burp parses `id` out of the submitted text itself to dedupe/replace by,
     * which only works in envelope form.
     *
     * [script] may be an envelope already, or a bare lambda body. A bare body is wrapped via
     * [ensureEnvelope] using [name]/[function]/[location] (or defaults) and a generated id. An
     * envelope is kept as written; only the header lines it lacks are added, from the same values.
     *
     * Burp reports the outcome via [BambdaImportResult]; a script that fails
     * to compile is returned with status [BambdaImportResult.Status.LOADED_WITH_ERRORS]
     * rather than by throwing. Callers must consume that result — discarding it
     * makes a compile failure look like a success.
     *
     * @param script Full `.bambda` envelope, or a bare lambda body to auto-wrap.
     * @param name Display name for a header that has none (default "Raijin <id>").
     * @param function Bambda function type for a header that has none (default "VIEW_FILTER").
     *   One token; the set is Burp's and grows with it, so it is not checked against a list here.
     *   [templates] lists the known ones.
     * @param location Where it applies, for a header that has none (default "PROXY_HTTP_HISTORY").
     * @return JSON object confirming the import, with the Bambda's `id`, or reporting an error.
     */
    fun importBambda(script: String, name: String? = null, function: String? = null, location: String? = null): JsonObject {
        val envelope = try {
            ensureEnvelope(script, java.util.UUID.randomUUID().toString(), name, function, location)
        } catch (e: IllegalArgumentException) {
            return buildJsonObject { put("error", e.message ?: "Invalid Bambda header value") }
        }
        val header = header(envelope)
        return try {
            val result = api.bambda().importBambda(envelope)
            buildImportResponse(
                loadedWithErrors = result.status() == BambdaImportResult.Status.LOADED_WITH_ERRORS,
                errors = result.importErrors(),
                scriptLength = envelope.length,
                id = header["id"],
                name = header["name"],
                function = header["function"],
                location = header["location"]
            )
        } catch (e: UnsupportedOperationException) {
            buildJsonObject {
                put("error", "Bambda API is not available in this version of Burp Suite")
                put("available", false)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("error", "Failed to import Bambda: ${e.message}")
                put("script_length", envelope.length)
            }
        }
    }

    companion object {
        private const val DEFAULT_FUNCTION = "VIEW_FILTER"
        private const val DEFAULT_LOCATION = "PROXY_HTTP_HISTORY"

        /** The header keys of a `.bambda` document. */
        private val HEADER_KEYS = listOf("id", "name", "function", "location", "source")
        private val CONTROL_CHARS = Regex("\\p{Cntrl}+")
        private val HEADER_TOKEN = Regex("[A-Z0-9_]+")

        /**
         * The header of a `.bambda` document: its top-level `key: value` lines.
         *
         * The format is line-based, not YAML proper: a key starts its line, and its value is the
         * rest of that line as written, with no quoting (PortSwigger's own BambdaChecker reads it
         * this way, and Burp exports names such as `RepeaterClip: New from Clipboard` unquoted).
         * Lines of the `source:` block are indented, so they are never mistaken for keys. A key
         * given twice takes its last value.
         */
        internal fun header(document: String): Map<String, String> {
            val found = LinkedHashMap<String, String>()
            for (line in document.lineSequence()) {
                val key = HEADER_KEYS.firstOrNull { line.startsWith("$it:") } ?: continue
                found[key] = line.substring(key.length + 1).trim()
            }
            return found
        }

        /**
         * Pure envelope auto-wrap, extracted so it is unit-testable without a live Burp instance.
         *
         * [script] is an envelope when it has at least two header keys at the start of a line,
         * wherever they are: after `#` comments, in any order, with or without an `id`. A document
         * pasted with a uniform indentation is recognised too. An envelope is returned as written
         * when its header is complete; otherwise the missing `id`, `name`, `function` or `location`
         * lines are added above its first header line. Anything else is a bare lambda body and is
         * wrapped into a minimal envelope of the shape Burp itself emits.
         *
         * [name], [function] and [location] land on header lines, so each is reduced to what one
         * line can hold: control characters in a name become spaces, and a function or location
         * must be a single token. No value can add a line, and with it a header key, of its own.
         *
         * @throws IllegalArgumentException when [function] or [location] is not one token.
         */
        internal fun ensureEnvelope(script: String, id: String, name: String?, function: String?, location: String?): String {
            val headerLines = mapOf(
                "id" to id,
                "name" to (oneLine(name) ?: "Raijin $id"),
                "function" to (token(function, "function") ?: DEFAULT_FUNCTION),
                "location" to (token(location, "location") ?: DEFAULT_LOCATION),
            )

            val document = listOf(script, script.trimIndent()).firstOrNull { header(it).size >= 2 }
            if (document != null) {
                val present = header(document)
                val missing = headerLines.filterKeys { it !in present }.map { (key, value) -> "$key: $value" }
                if (missing.isEmpty()) return document
                val lines = document.lines()
                val firstKey = lines.indexOfFirst { line -> HEADER_KEYS.any { line.startsWith("$it:") } }
                return (lines.subList(0, firstKey) + missing + lines.subList(firstKey, lines.size)).joinToString("\n")
            }

            return buildString {
                headerLines.forEach { (key, value) -> appendLine("$key: $value") }
                appendLine("source: |+")
                sourceLines(script).forEach { line -> append("  "); appendLine(line) }
            }
        }

        /** [text] as a header value: one line, or null when nothing is left of it. */
        private fun oneLine(text: String?): String? =
            text?.replace(CONTROL_CHARS, " ")?.trim()?.takeIf { it.isNotEmpty() }

        /** [text] as a function or location name, upper-cased as Burp writes them; null when not given. */
        private fun token(text: String?, param: String): String? {
            val value = text?.trim()?.uppercase()?.takeIf { it.isNotEmpty() } ?: return null
            require(HEADER_TOKEN.matches(value)) { "'$param' must be a single name such as $DEFAULT_FUNCTION, got '$text'" }
            return value
        }

        /**
         * The lambda body as the lines of the `source:` block. The first line with code is
         * left-trimmed: a YAML reader takes the block's indentation from it, so a later line
         * indented less than it would end the block early. Java does not care.
         */
        private fun sourceLines(script: String): List<String> {
            val lines = script.lines()
            val first = lines.indexOfFirst { it.isNotBlank() }
            return lines.mapIndexed { i, line -> if (i == first) line.trimStart() else line }
        }

        /**
         * Pure mapping from a Bambda import outcome to the tool response JSON.
         *
         * Extracted so the success/error branching can be unit-tested without a
         * live Burp instance (the Montoya API is compileOnly here).
         *
         * @param loadedWithErrors true when Burp reported LOADED_WITH_ERRORS
         *   (the script was accepted but failed to compile cleanly).
         * @param errors compile/import diagnostics from Burp, if any.
         * @param scriptLength length of the submitted script.
         * @param id the Bambda's id as submitted; importing the same id again replaces it.
         *   [name], [function] and [location] are the other header values as submitted.
         */
        internal fun buildImportResponse(
            loadedWithErrors: Boolean,
            errors: List<String>,
            scriptLength: Int,
            id: String? = null,
            name: String? = null,
            function: String? = null,
            location: String? = null
        ): JsonObject = buildJsonObject {
            put("status", if (loadedWithErrors) "imported_with_errors" else "imported")
            if (id != null) put("id", id)
            if (name != null) put("name", name)
            if (function != null) put("function", function)
            if (location != null) put("location", location)
            put("script_length", scriptLength)
            if (errors.isNotEmpty()) {
                put("import_errors", buildJsonArray { errors.forEach { add(it) } })
            }
            if (loadedWithErrors) {
                put("error", "Burp loaded the Bambda with errors; it will not run until import_errors are fixed")
            }
        }

        /**
         * The envelope format, the functions and locations known from PortSwigger's public Bambda
         * repository, and a starting lambda body for each kind. Each template's `source` goes to
         * `bambda_import` as `script`, with its `name`, `function` and `location`.
         */
        fun templates(): JsonObject = buildJsonObject {
            put("envelope", buildJsonObject {
                put("example", ensureEnvelope(
                    "return requestResponse.hasResponse() && requestResponse.response().statusCode() == 101;",
                    "00000000-0000-4000-8000-000000000000", "Detect 101 switching protocols", null, null
                ))
                put("rules", buildJsonArray {
                    add("Header keys start their line: id, name, function, location, then source: |+ followed by the Java body indented two spaces.")
                    add("id is a UUID; importing an id that exists replaces that Bambda. bambda_import generates one when the script has none.")
                    add("A header value is the rest of its line, taken as written: no quotes, no line breaks.")
                    add("bambda_import accepts this envelope, or just the Java body plus name / function / location.")
                })
            })
            put("functions", buildJsonArray {
                FUNCTIONS.forEach { (function, locations, contract) ->
                    add(buildJsonObject {
                        put("function", function)
                        put("locations", buildJsonArray { locations.forEach { add(it) } })
                        put("contract", contract)
                    })
                }
            })
            put("functions_note", "From PortSwigger's public Bambda repository; a newer Burp may know more. " +
                "bambda_import does not check function or location against this list, Burp's import result does.")
            put("templates", buildJsonArray {
                TEMPLATES.forEach { template ->
                    add(buildJsonObject {
                        put("name", template.name)
                        put("function", template.function)
                        put("location", template.location)
                        put("description", template.description)
                        put("source", template.source.trimIndent())
                    })
                }
            })
        }

        private val FUNCTIONS = listOf(
            Triple(
                "VIEW_FILTER", listOf("PROXY_HTTP_HISTORY", "PROXY_WEBSOCKET", "LOGGER", "SITEMAP"),
                "Return true to show the item. The item is requestResponse (HTTP history, Logger), message (WebSocket history) or node (site map)."
            ),
            Triple("CAPTURE_FILTER", listOf("LOGGER"), "Return true for Logger to capture the item (requestResponse)."),
            Triple(
                "CUSTOM_COLUMN", listOf("PROXY_HTTP_HISTORY", "PROXY_WEBSOCKET", "LOGGER"),
                "Return the cell value for the row's requestResponse (message for WebSocket history)."
            ),
            Triple(
                "MATCH_AND_REPLACE_REQUEST", listOf("PROXY_HTTP_HISTORY"),
                "Return the HttpRequest to send in place of requestResponse.request()."
            ),
            Triple(
                "MATCH_AND_REPLACE_RESPONSE", listOf("PROXY_HTTP_HISTORY"),
                "Return the HttpResponse to deliver in place of requestResponse.response()."
            ),
            Triple(
                "CUSTOM_ACTION", listOf("REPEATER"),
                "Runs on demand in Repeater; returns nothing. Has requestResponse, httpEditor, api() and logging()."
            ),
            Triple(
                "SCAN_CHECK_PASSIVE_PER_REQUEST", listOf("SCANNER"),
                "Return an AuditResult for requestResponse; must not send requests."
            ),
            Triple("SCAN_CHECK_PASSIVE_PER_HOST", listOf("SCANNER"), "As above, run once per host."),
            Triple(
                "SCAN_CHECK_ACTIVE_PER_REQUEST", listOf("SCANNER"),
                "Return an AuditResult; send requests with http.sendRequest(...)."
            ),
            Triple("SCAN_CHECK_ACTIVE_PER_HOST", listOf("SCANNER"), "As above, run once per host."),
            Triple(
                "SCAN_CHECK_ACTIVE_PER_INSERTION_POINT", listOf("SCANNER"),
                "Return an AuditResult; build requests with insertionPoint.buildHttpRequestWithPayload(...)."
            ),
        )

        private class Template(
            val name: String,
            val function: String,
            val location: String,
            val description: String,
            val source: String,
        )

        private val TEMPLATES = listOf(
            Template(
                "Server errors", "VIEW_FILTER", "PROXY_HTTP_HISTORY",
                "Proxy history filter: only responses with a 5xx status.",
                """
                return requestResponse.hasResponse() && requestResponse.response().statusCode() >= 500;
                """
            ),
            Template(
                "WebSocket messages with a token", "VIEW_FILTER", "PROXY_WEBSOCKET",
                "WebSocket history filter: only messages whose payload mentions a token.",
                """
                return message.payload().toString().toLowerCase().contains("token");
                """
            ),
            Template(
                "Slow responses", "VIEW_FILTER", "LOGGER",
                "Logger filter: responses that took three seconds or more to start.",
                """
                var delta = requestResponse.timingData().timeBetweenRequestSentAndStartOfResponse();
                return delta != null && delta.toMillis() >= 3000;
                """
            ),
            Template(
                "Hide missing responses", "VIEW_FILTER", "SITEMAP",
                "Site map filter: hide entries that never got a response.",
                """
                return node.requestResponse().hasResponse();
                """
            ),
            Template(
                "Server header column", "CUSTOM_COLUMN", "PROXY_HTTP_HISTORY",
                "Proxy history column showing the response's Server header.",
                """
                if (!requestResponse.hasResponse() || !requestResponse.response().hasHeader("Server")) {
                    return "";
                }
                return requestResponse.response().headerValue("Server");
                """
            ),
            Template(
                "Add X-Forwarded-For", "MATCH_AND_REPLACE_REQUEST", "PROXY_HTTP_HISTORY",
                "Match and replace: add a header to every proxied request.",
                """
                return requestResponse.request().withAddedHeader("X-Forwarded-For", "127.0.0.1");
                """
            ),
            Template(
                "Strip Content-Security-Policy", "MATCH_AND_REPLACE_RESPONSE", "PROXY_HTTP_HISTORY",
                "Match and replace: remove the CSP header from every proxied response.",
                """
                return requestResponse.response().withRemovedHeader("Content-Security-Policy");
                """
            ),
            Template(
                "Retry request without cookies", "CUSTOM_ACTION", "REPEATER",
                "Repeater action: resend the request without Cookie and Authorization and show that response.",
                """
                var request = requestResponse.request().withRemovedHeader("Cookie").withRemovedHeader("Authorization");
                var result = api().http().sendRequest(request);
                httpEditor.responsePane().set(result.response().toByteArray());
                """
            ),
            Template(
                "Missing CSP header", "SCAN_CHECK_PASSIVE_PER_REQUEST", "SCANNER",
                "Passive scan check: report responses without a Content-Security-Policy header.",
                """
                if (!requestResponse.hasResponse() || requestResponse.response().hasHeader("Content-Security-Policy")) {
                    return AuditResult.auditResult();
                }
                return AuditResult.auditResult(
                        AuditIssue.auditIssue(
                                "Content Security Policy header missing",
                                "The response does not include a Content-Security-Policy header.",
                                "Add a suitable Content-Security-Policy header.",
                                requestResponse.request().url(),
                                AuditIssueSeverity.LOW,
                                AuditIssueConfidence.FIRM,
                                "",
                                "",
                                AuditIssueSeverity.LOW,
                                requestResponse
                        )
                );
                """
            ),
            Template(
                "Template expression evaluated", "SCAN_CHECK_ACTIVE_PER_INSERTION_POINT", "SCANNER",
                "Active scan check: inject a calculation and report when its result appears in the response and " +
                    "was not there before.",
                """
                var answer = "1787569";
                if (insertionPoint == null || !requestResponse.hasResponse()
                        || requestResponse.response().bodyToString().contains(answer)) {
                    return AuditResult.auditResult();
                }
                var probe = http.sendRequest(insertionPoint.buildHttpRequestWithPayload(ByteArray.byteArray("{{1337*1337}}")));
                if (!probe.hasResponse() || !probe.response().bodyToString().contains(answer)) {
                    return AuditResult.auditResult();
                }
                return AuditResult.auditResult(
                        AuditIssue.auditIssue(
                                "Server-side template injection",
                                "The expression {{1337*1337}} was evaluated: the response contains " + answer + ".",
                                "Do not evaluate user input as a template.",
                                probe.request().url(),
                                AuditIssueSeverity.HIGH,
                                AuditIssueConfidence.FIRM,
                                "",
                                "",
                                AuditIssueSeverity.HIGH,
                                probe
                        )
                );
                """
            ),
        )
    }
}
