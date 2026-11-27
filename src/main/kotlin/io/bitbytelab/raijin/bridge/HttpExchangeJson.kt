package io.bitbytelab.raijin.bridge

import burp.api.montoya.http.message.HttpRequestResponse
import io.bitbytelab.raijin.core.BodyText
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

/**
 * The `error` of a multi-request call none of whose [ran] [unit]s (`step`, `request`) got a
 * response: `"<call>: none of the 3 steps that ran got a response (step 0: <reason>)."`.
 */
internal fun noResponseError(
    call: String,
    unit: String,
    ran: Int,
    firstIndex: Int,
    reason: String,
): String {
    val what = if (unit == "step") "steps that ran" else "${unit}s"
    return "$call: none of the $ran $what got a response ($unit $firstIndex: ${reason.trimEnd('.')})."
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

        try {
            val req = result.request()
            if (req != null) {
                put("request_method", req.method())
                put("request_url", req.url())
                put("request_host", req.httpService().host())
                put("request_port", req.httpService().port())
                put("request_secure", req.httpService().secure())
                put("request_http_version", req.httpVersion())
                put(
                    "request_headers",
                    buildJsonArray {
                        req.headers().forEach { h ->
                            add(
                                buildJsonObject {
                                    put("name", h.name())
                                    put("value", h.value())
                                },
                            )
                        }
                    },
                )
                val requestBody = BodyText.render(req.bodyToString())
                put("request_body", requestBody.text)
                if (requestBody.binary) put("request_body_binary", true)
                if (requestBody.truncated) put("request_body_truncated", true)
            }
        } catch (e: Exception) {
            put("request_serialize_error", e.message ?: "failed to serialize request")
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
