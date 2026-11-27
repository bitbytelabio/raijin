package io.bitbytelab.raijin.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

class NoResponseErrorTest {

    @Test
    fun `the error names how many ran and why the first got nothing`() {
        val refused = buildJsonObject {
            put("step", 0)
            put(
                "no_response",
                "no response from 127.0.0.1:1 (connection refused, reset or timed out)",
            )
        }
        assertEquals(
            "http_send_request_chain: none of the 2 steps that ran got a response " +
                "(step 0: no response from 127.0.0.1:1 (connection refused, reset or timed out)).",
            noResponseError(
                "http_send_request_chain",
                "step",
                2,
                0,
                noResponseReason(listOf(refused)),
            ),
        )
        val failed = buildJsonObject {
            put("index", 1)
            put("error", "group send failed: boom.")
        }
        assertEquals(
            "http_send_requests_parallel: none of the 3 requests got a response (request 1: group send failed: boom).",
            noResponseError(
                "http_send_requests_parallel",
                "request",
                3,
                1,
                noResponseReason(listOf(failed)),
            ),
        )
        assertEquals(
            "blocked by scope",
            noResponseReason(listOf(buildJsonObject { put("step", 0) })),
        )
    }
}
