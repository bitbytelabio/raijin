package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Range
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.HttpService
import burp.api.montoya.intruder.HttpRequestTemplate
import burp.api.montoya.intruder.PayloadProcessor
import burp.api.montoya.intruder.PayloadProcessingResult
import burp.api.montoya.intruder.PayloadData
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.safety.RequestHygiene
import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.*
import java.security.MessageDigest
import java.util.Base64

class IntruderBridge(private val api: MontoyaApi, private val stateManager: StateManager) {

    fun sendToIntruder(request: String, host: String, port: Int, useTls: Boolean, tabName: String?): JsonObject {
        val httpService = HttpService.httpService(host, port, useTls)
        val httpRequest = HttpRequest.httpRequest(httpService, RequestHygiene.normalizeCrlf(request))

        if (tabName != null) {
            api.intruder().sendToIntruder(httpRequest, tabName)
        } else {
            api.intruder().sendToIntruder(httpRequest)
        }

        return buildJsonObject {
            put("status", "sent_to_intruder")
            put("host", host)
            put("port", port)
            put("use_tls", useTls)
            put("tab_name", tabName ?: "auto")
        }
    }

    fun sendWithPositions(
        request: String,
        host: String,
        port: Int,
        useTls: Boolean,
        positions: List<Pair<Int, Int>>,
        tabName: String?
    ): JsonObject {
        val httpService = HttpService.httpService(host, port, useTls)
        // Normalize line endings (issue #7). Bare-LF → CRLF shifts byte offsets, so the
        // caller's payload positions are re-mapped onto the normalized request; an
        // already-CRLF request is unchanged and the offsets pass through untouched.
        val normalized = RequestHygiene.normalizeCrlf(request)
        val httpRequest = HttpRequest.httpRequest(httpService, normalized)

        val insertionPointOffsets = positions.map { (start, end) ->
            Range.range(RequestHygiene.adjustedOffset(request, start), RequestHygiene.adjustedOffset(request, end))
        }

        val template = HttpRequestTemplate.httpRequestTemplate(
            httpRequest,
            insertionPointOffsets
        )

        if (tabName != null) {
            api.intruder().sendToIntruder(httpService, template, tabName)
        } else {
            api.intruder().sendToIntruder(httpService, template)
        }

        return buildJsonObject {
            put("status", "sent_with_positions")
            put("host", host)
            put("port", port)
            put("use_tls", useTls)
            put("tab_name", tabName ?: "auto")
            put("insertion_points", positions.size)
            putJsonArray("positions") {
                for ((start, end) in positions) {
                    addJsonObject {
                        put("start", start)
                        put("end", end)
                    }
                }
            }
        }
    }

    /**
     * Registers a payload processor with Intruder. Everything that can be wrong with it is
     * rejected here: once registered it runs on Intruder's threads, once per payload, where a
     * bad regex or replacement could only fail silently.
     *
     * Registering a [name] again replaces the processor registered under it.
     */
    fun registerPayloadProcessor(
        name: String,
        transformType: String,
        params: Map<String, String>
    ): JsonObject {
        EnumValidation.error(transformType, TRANSFORM_TYPES, "transform_type", required = true)?.let { return it }
        val type = transformType.trim().lowercase()
        if (name.isBlank()) return buildJsonObject { put("error", "name must not be blank") }
        if (type == "regex_replace") {
            regexReplaceError(params)?.let { err -> return buildJsonObject { put("error", err) } }
        }

        val processor = object : PayloadProcessor {
            override fun displayName(): String = name

            override fun processPayload(payloadData: PayloadData): PayloadProcessingResult {
                val currentPayload = payloadData.currentPayload().toString()
                val transformed = transform(type, params, currentPayload) { api.utilities().urlUtils().encode(it) }
                return PayloadProcessingResult.usePayload(
                    burp.api.montoya.core.ByteArray.byteArray(transformed)
                )
            }
        }

        val registration = api.intruder().registerPayloadProcessor(processor)
        // The handle of a processor registered earlier under this name would be lost with the map
        // entry, leaving that processor in Burp with no way to remove it.
        stateManager.intruderRegistrations.put(name, registration)?.let { previous ->
            runCatching { previous.deregister() }
        }
        stateManager.registeredPayloadProcessors.addIfAbsent(name)

        return buildJsonObject {
            put("status", "registered")
            put("name", name)
            put("transform_type", type)
            put("total_registered", stateManager.registeredPayloadProcessors.size)
        }
    }

    companion object {
        internal val TRANSFORM_TYPES = linkedSetOf(
            "encode_base64", "encode_url",
            "hash_md5", "hash_sha1", "hash_sha256",
            "prefix", "suffix", "regex_replace"
        )

        /**
         * One payload through one transform. Pure apart from [urlEncode], which is Burp's.
         * A `regex_replace` that times out leaves the payload as it was.
         */
        internal fun transform(
            type: String,
            params: Map<String, String>,
            payload: String,
            urlEncode: (String) -> String,
        ): String = when (type) {
            "encode_base64" -> Base64.getEncoder().encodeToString(payload.toByteArray())
            "encode_url" -> urlEncode(payload)
            "hash_md5" -> hashPayload(payload, "MD5")
            "hash_sha1" -> hashPayload(payload, "SHA-1")
            "hash_sha256" -> hashPayload(payload, "SHA-256")
            "prefix" -> (params["prefix_value"] ?: "") + payload
            "suffix" -> payload + (params["suffix_value"] ?: "")
            "regex_replace" ->
                SafeRegex.replace(params["regex_pattern"] ?: "", payload, params["regex_replacement"] ?: "")
            else -> payload
        }

        /** Why these `regex_replace` parameters cannot work, or null when they can. */
        internal fun regexReplaceError(params: Map<String, String>): String? {
            val pattern = params["regex_pattern"]
            if (pattern.isNullOrEmpty()) return "regex_replace requires a non-empty regex_pattern"
            SafeRegex.validate(pattern)?.let { return "Invalid regex_pattern: $it" }
            return replacementError(pattern, params["regex_replacement"] ?: "")
                ?.let { "Invalid regex_replacement: $it" }
        }

        /**
         * Why [replacement] is not a valid replacement string for [pattern], or null. Java only
         * parses a replacement when a match is found, so a bad group reference would otherwise
         * surface mid-run, and [SafeRegex.replace] would answer it by leaving every payload unchanged.
         */
        internal fun replacementError(pattern: String, replacement: String): String? {
            val compiled = try {
                SafeRegex.compile(pattern).toPattern()
            } catch (e: Exception) {
                return e.message ?: "regex_pattern does not compile"
            }
            val groupCount = compiled.matcher("").groupCount()
            val groupNames = compiled.namedGroups().keys
            var i = 0
            while (i < replacement.length) {
                when (replacement[i]) {
                    '\\' -> {
                        if (i + 1 >= replacement.length) return "it ends in a backslash that escapes nothing"
                        i += 2
                    }
                    '$' -> {
                        val next = replacement.getOrNull(i + 1)
                        when {
                            next == '{' -> {
                                val close = replacement.indexOf('}', i + 2)
                                if (close < 0) return "the group reference at offset $i has no closing brace"
                                val group = replacement.substring(i + 2, close)
                                if (group !in groupNames) return "regex_pattern has no group named '$group'"
                                i = close + 1
                            }
                            next != null && next in '0'..'9' -> {
                                val group = next - '0'
                                if (group > groupCount) return "regex_pattern has no group $group (it has $groupCount)"
                                i += 2
                            }
                            else -> return "a dollar sign must be followed by a group number or {name}; " +
                                "write a backslash before it for a literal one"
                        }
                    }
                    else -> i++
                }
            }
            return null
        }

        private fun hashPayload(input: String, algorithm: String): String {
            val digest = MessageDigest.getInstance(algorithm)
            val hashBytes = digest.digest(input.toByteArray())
            return hashBytes.joinToString("") { "%02x".format(it) }
        }
    }
}
