package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.safety.ScopeGate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

class NoResponseErrorTest {

    private val refusedReason =
        "no response from 127.0.0.1:1 (connection refused, reset or timed out)"

    @Test
    fun `the error names how many ran and why the first got nothing`() {
        val refused = buildJsonObject {
            put("step", 1)
            put("no_response", refusedReason)
        }
        assertEquals(
            "http_send_request_chain: none of the 2 steps that ran got a response " +
                "(step 1: $refusedReason).",
            noResponseError(
                "http_send_request_chain",
                "step",
                2,
                1,
                noResponseReason(listOf(refused)),
            ),
        )
        val failed = buildJsonObject {
            put("request", 2)
            put("error", "group send failed: boom.")
        }
        assertEquals(
            "http_send_requests_parallel: none of the 3 requests got a response (request 2: group send failed: boom).",
            noResponseError(
                "http_send_requests_parallel",
                "request",
                3,
                2,
                noResponseReason(listOf(failed)),
            ),
        )
        assertEquals(
            "blocked by scope",
            noResponseReason(listOf(buildJsonObject { put("step", 1) })),
        )
    }

    private val missingTarget = buildJsonObject {
        put("step", 1)
        put("phase", "build")
        put("error", HttpRequestBuilder.MISSING_TARGET)
    }

    @Test
    fun `a step with no target is a missing parameter, not a missing response`() {
        val fields =
            noResponseFields(
                "http_send_request_chain",
                "step",
                "steps",
                "step",
                listOf(missingTarget),
            )
        assertEquals(JsonPrimitive("missing_parameter"), fields["code"])
        assertEquals(JsonPrimitive("steps[1].url"), fields["param"])
        val error = fields.getValue("error").jsonPrimitive.content
        assertTrue("step 1 has neither 'url' nor 'raw_request'" in error, error)
    }

    @Test
    fun `a sent item without a response makes it no_response and names that item`() {
        val sent = buildJsonObject {
            put("step", 2)
            put("phase", "send")
            put("no_response", refusedReason)
        }
        val fields =
            noResponseFields(
                "http_send_request_chain",
                "step",
                "steps",
                "step",
                listOf(missingTarget, sent),
            )
        assertEquals(JsonPrimitive("no_response"), fields["code"])
        assertTrue("param" !in fields)
        val error = fields.getValue("error").jsonPrimitive.content
        assertTrue("(step 2: $refusedReason)" in error, error)
    }

    @Test
    fun `out of scope items next to a build failure still give the argument error`() {
        val blocked = buildJsonObject {
            put("request", 1)
            put(ScopeGate.OUT_OF_SCOPE, true)
            put("error", "Not sent: out of scope")
        }
        val bad = buildJsonObject {
            put("request", 2)
            put("phase", "build")
            put("error", "Invalid URL: nope.")
        }
        val fields =
            noResponseFields(
                "http_send_requests_parallel",
                "request",
                "requests",
                "request",
                listOf(blocked, bad),
            )
        assertEquals(JsonPrimitive("invalid_arguments"), fields["code"])
        assertEquals(JsonPrimitive("requests[2]"), fields["param"])
        assertEquals(
            JsonPrimitive(
                "http_send_requests_parallel: request 2 could not be built: Invalid URL: nope.",
            ),
            fields["error"],
        )
    }
}
