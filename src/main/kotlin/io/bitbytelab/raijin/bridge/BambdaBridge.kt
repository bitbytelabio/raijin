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
     * [script] may be a full envelope already (starts with `id:`), or a bare lambda body — the
     * latter is auto-wrapped via [ensureEnvelope] using [name]/[function]/[location] (or
     * defaults) and a generated id, so a simple caller can still pass just the lambda.
     *
     * Burp reports the outcome via [BambdaImportResult]; a script that fails
     * to compile is returned with status [BambdaImportResult.Status.LOADED_WITH_ERRORS]
     * rather than by throwing. Callers must consume that result — discarding it
     * makes a compile failure look like a success.
     *
     * @param script Full `.bambda` envelope, or a bare lambda body to auto-wrap.
     * @param name Display name, when auto-wrapping a bare lambda (default "Raijin <id>").
     * @param function Bambda function type, when auto-wrapping (default "VIEW_FILTER"; Burp's
     *   own accepted values include VIEW_FILTER, CUSTOM_COLUMN, MATCH_AND_REPLACE_REQUEST,
     *   MATCH_AND_REPLACE_RESPONSE, SCAN_CHECK_ACTIVE_PER_REQUEST — not validated client-side).
     * @param location Where it applies, when auto-wrapping (default "PROXY_HTTP_HISTORY"; Burp's
     *   own accepted values include PROXY_HTTP_HISTORY, PROXY_WS_HISTORY, LOGGER, SITE_MAP,
     *   SCANNER — not validated client-side).
     * @return JSON object confirming the import or reporting an error.
     */
    fun importBambda(script: String, name: String? = null, function: String? = null, location: String? = null): JsonObject {
        val envelope = ensureEnvelope(script, java.util.UUID.randomUUID().toString(), name, function, location)
        return try {
            val result = api.bambda().importBambda(envelope)
            buildImportResponse(
                loadedWithErrors = result.status() == BambdaImportResult.Status.LOADED_WITH_ERRORS,
                errors = result.importErrors(),
                scriptLength = envelope.length
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
        /**
         * Pure envelope auto-wrap, extracted so it is unit-testable without a live Burp
         * instance. [script] already starting with `id:` (after leading whitespace) is assumed
         * to be a complete `.bambda` document already and is passed through unchanged; anything
         * else is treated as a bare lambda body and wrapped with the given (or default) id/name/
         * function/location into a minimal valid envelope, matching the shape Burp itself emits.
         */
        internal fun ensureEnvelope(script: String, id: String, name: String?, function: String?, location: String?): String {
            if (script.trimStart().startsWith("id:")) return script
            return buildString {
                appendLine("id: $id")
                appendLine("name: ${name ?: "Raijin $id"}")
                appendLine("function: ${function ?: "VIEW_FILTER"}")
                appendLine("location: ${location ?: "PROXY_HTTP_HISTORY"}")
                appendLine("source: |+")
                script.lines().forEach { line -> append("  "); appendLine(line) }
            }
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
         */
        internal fun buildImportResponse(
            loadedWithErrors: Boolean,
            errors: List<String>,
            scriptLength: Int
        ): JsonObject = buildJsonObject {
            put("status", if (loadedWithErrors) "imported_with_errors" else "imported")
            put("script_length", scriptLength)
            if (errors.isNotEmpty()) {
                put("import_errors", buildJsonArray { errors.forEach { add(it) } })
            }
        }
    }
}
