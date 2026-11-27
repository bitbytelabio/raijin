package io.bitbytelab.raijin.bridge

import burp.api.montoya.http.message.HttpRequestResponse
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.safety.ScopeGate
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.put

/**
 * The `error` of a multi-request call none of whose [ran] [unit]s (`step`, `request`) got a
 * response: `"<call>: none of the 3 steps that ran got a response (step 1: <reason>)."`.
 * [firstNumber] is the 1-based number of the item the reason is about.
 */
internal fun noResponseError(
    call: String,
    unit: String,
    ran: Int,
    firstNumber: Int,
    reason: String,
): String {
    val what = if (unit == "step") "steps that ran" else "${unit}s"
    return "$call: none of the $ran $what got a response ($unit $firstNumber: ${reason.trimEnd('.')})."
}

/**
 * The top-level `error`, `code` and (for an argument error) `param` of a multi-request call none of
 * whose [items] got a response. [unit] is "step" or "request"; [listParam] is "steps" or
 * "requests"; [numberKey] is the 1-based number field of each item.
 *
 * Nothing sent (every item has phase "build" or out_of_scope true, at least one "build"): the first
 * build item's error as missing_parameter / invalid_arguments. Else no_response, naming the first
 * item that was sent.
 */
internal fun noResponseFields(
    call: String,
    unit: String,
    listParam: String,
    numberKey: String,
    items: List<JsonObject>,
): JsonObject {
    fun JsonObject.built() = (this["phase"] as? JsonPrimitive)?.contentOrNull == "build"
    fun JsonObject.blocked() =
        (this[ScopeGate.OUT_OF_SCOPE] as? JsonPrimitive)?.booleanOrNull == true
    fun JsonObject.number() = (this[numberKey] as? JsonPrimitive)?.intOrNull ?: 1
    val firstBuild = items.firstOrNull { it.built() }
    if (firstBuild != null && items.all { it.built() || it.blocked() }) {
        val n = firstBuild.number()
        val err = (firstBuild["error"] as? JsonPrimitive)?.contentOrNull ?: "unknown error"
        return buildJsonObject {
            if (err == HttpRequestBuilder.MISSING_TARGET) {
                put("error", "$call: $unit $n has neither 'url' nor 'raw_request'.")
                put("code", "missing_parameter")
                put("param", "$listParam[$n].url")
            } else {
                put("error", "$call: $unit $n could not be built: ${err.trimEnd('.')}.")
                put("code", "invalid_arguments")
                put("param", "$listParam[$n]")
            }
        }
    }
    val firstSent = items.firstOrNull { !it.built() && !it.blocked() } ?: items.firstOrNull()
    return buildJsonObject {
        put(
            "error",
            noResponseError(
                call,
                unit,
                items.size,
                firstSent?.number() ?: 1,
                noResponseReason(listOfNotNull(firstSent)),
            ),
        )
        put("code", "no_response")
    }
}

/**
 * Why the first item of [items] (serialized steps or results) has no response, for
 * [noResponseError].
 */
internal fun noResponseReason(items: List<JsonObject>): String {
    val first = items.firstOrNull() ?: return "nothing was sent"
    return (first["no_response"] as? JsonPrimitive)?.contentOrNull
        ?: (first["error"] as? JsonPrimitive)?.contentOrNull
        ?: "blocked by scope"
}

/** How the Montoya-backed HTTP tools report one request/response exchange. */
internal object HttpExchangeJson {

    /**
     * Response header a session login macro puts on the response it obtained by re-establishing the
     * session and sending the request again; its value names the macro. Reported as
     * `reauthenticated` so the agent sees that it happened.
     */
    const val REAUTHENTICATED_HEADER = "X-Raijin-Reauthenticated"

    /**
     * The method as written in the first line of [requestText]: the text before its first space, ""
     * when the line starts with a space. Used when Montoya refuses to parse the method.
     */
    internal fun requestLineMethod(requestText: String): String =
        requestText.substringBefore('\n').trimEnd('\r').substringBefore(' ')

    /**
     * Serializes [result]. Bodies go through [BodyText.render] (binary placeholder, lone surrogates
     * replaced, truncation on a safe boundary).
     *
     * @param elapsedMs wall time of the send, when measured.
     * @param maxBodyLength cap on the response body in characters; null or <= 0 uses
     *   [BodyText.DEFAULT_MAX_LENGTH]. The request body always uses that default.
     */
    fun serialize(
        result: HttpRequestResponse,
        elapsedMs: Long?,
        maxBodyLength: Int? = null,
    ): JsonObject = buildJsonObject {
        put("has_response", result.hasResponse())
        if (!result.hasResponse()) {
            val service = runCatching { result.request().httpService() }.getOrNull()
            val target = service?.let { "${it.host()}:${it.port()}" } ?: "the target"
            put("no_response", "no response from $target (connection refused, reset or timed out)")
        }
        // Montoya throws for a request it cannot turn into a URL (a malformed target sent on
        // purpose).
        put("url", runCatching { result.url() }.getOrNull().orEmpty())

        // Each field is read on its own: Montoya throws from method()/url() of a request sent
        // with a malformed request line, and the other fields are still worth reporting.
        val reqRead = runCatching { result.request() }
        reqRead.onFailure { e ->
            put("request_serialize_error", e.message ?: "failed to serialize request")
        }
        val req = reqRead.getOrNull()
        if (req != null) {
            var unreadField = false
            fun <T> field(read: () -> T): T? =
                runCatching(read).onFailure { unreadField = true }.getOrNull()

            put(
                "request_method",
                field { req.method() }
                    ?: requestLineMethod(runCatching { req.toString() }.getOrNull().orEmpty()),
            )
            field { req.url() }?.let { put("request_url", it) }
            field { req.httpService() }
                ?.let { service ->
                    field { service.host() }?.let { put("request_host", it) }
                    field { service.port() }?.let { put("request_port", it) }
                    field { service.secure() }?.let { put("request_secure", it) }
                }
            field { req.httpVersion() }?.let { put("request_http_version", it) }
            field {
                buildJsonArray {
                    req.headers().forEach { h ->
                        add(
                            buildJsonObject {
                                put("name", h.name())
                                put("value", h.value())
                            },
                        )
                    }
                }
            }
                ?.let { put("request_headers", it) }
            field { BodyText.render(req.bodyToString()) }
                ?.let { requestBody ->
                    put("request_body", requestBody.text)
                    if (requestBody.binary) put("request_body_binary", true)
                    if (requestBody.truncated) put("request_body_truncated", true)
                }
            if (unreadField) {
                runCatching { req.toByteArray() }
                    .onFailure { e ->
                        put("request_serialize_error", e.message ?: "failed to serialize request")
                    }
            }
        }

        if (result.hasResponse()) {
            try {
                val resp = result.response()
                put("status_code", resp.statusCode().toInt())
                put("response_http_version", resp.httpVersion())
                put("response_reason", resp.reasonPhrase() ?: "")
                put("response_mime_type", resp.mimeType().name)
                put("response_body_length", resp.body().length())
                put(
                    "response_headers",
                    buildJsonArray {
                        resp.headers().forEach { h ->
                            add(
                                buildJsonObject {
                                    put("name", h.name())
                                    put("value", h.value())
                                },
                            )
                        }
                    },
                )
                resp
                    .headers()
                    .firstOrNull { it.name().equals(REAUTHENTICATED_HEADER, ignoreCase = true) }
                    ?.let { put("reauthenticated", it.value()) }
                val rendered =
                    BodyText.render(resp.bodyToString(), maxBodyLength, resp.mimeType().name)
                put("response_body", rendered.text)
                if (rendered.binary) put("response_body_binary", true)
                if (rendered.truncated) put("response_body_truncated", true)

                val cookies = resp.cookies()
                if (cookies.isNotEmpty()) {
                    put(
                        "response_cookies",
                        buildJsonArray {
                            cookies.forEach { c ->
                                add(
                                    buildJsonObject {
                                        put("name", c.name())
                                        put("value", c.value())
                                        put("domain", c.domain())
                                        put("path", c.path())
                                    },
                                )
                            }
                        },
                    )
                }
            } catch (e: Exception) {
                put("response_serialize_error", e.message ?: "failed to serialize response")
            }
        }

        if (elapsedMs != null) put("elapsed_ms", elapsedMs)

        try {
            val timingOpt = result.timingData()
            if (timingOpt.isPresent) {
                val td = timingOpt.get()
                put(
                    "timing",
                    buildJsonObject {
                        put(
                            "time_to_first_byte_ms",
                            td.timeBetweenRequestSentAndStartOfResponse().toMillis(),
                        )
                        put(
                            "time_to_complete_ms",
                            td.timeBetweenRequestSentAndEndOfResponse().toMillis(),
                        )
                        // Burp reports the epoch for a request it never sent.
                        val sent = td.timeRequestSent()
                        put(
                            "time_request_sent",
                            sent?.takeIf { it.toInstant().toEpochMilli() > 0 }?.toString(),
                        )
                    },
                )
            }
        } catch (_: Exception) {}
    }
}
