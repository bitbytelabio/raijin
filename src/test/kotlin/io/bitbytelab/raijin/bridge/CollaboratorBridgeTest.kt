package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.turbo.mcp.CollaboratorDnsDetails
import io.bitbytelab.raijin.turbo.mcp.CollaboratorHttpDetails
import io.bitbytelab.raijin.turbo.mcp.CollaboratorPayloadInfo
import io.bitbytelab.raijin.turbo.mcp.CollaboratorRecord
import io.bitbytelab.raijin.turbo.mcp.CollaboratorSmtpDetails
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for the pure helpers of [CollaboratorBridge].
 *
 * [CollaboratorBridge.sanitizeCustomData] fits a caller-supplied Collaborator label to Montoya's
 * constraint of at most 16 ASCII-alphanumeric characters. Regression coverage for the live crash:
 *   java.lang.IllegalArgumentException: Length of custom data must not exceed
 *   16 alphanumeric characters
 * which `collaborator_generate_payload` leaked when the label was too long or
 * contained non-alphanumeric characters.
 *
 * The rest covers what a poll result is built from: the saved-client list kept in the Burp
 * project, the split of a raw HTTP message, and the JSON of one recorded interaction.
 */
class CollaboratorBridgeTest {

    private fun sani(s: String) = CollaboratorBridge.sanitizeCustomData(s)

    @Test fun `short alphanumeric label passes through unchanged`() {
        val r = sani("idor7f3a")
        assertEquals("idor7f3a", r.effective)
        assertFalse(r.adjusted)
        assertNull(r.note)
    }

    @Test fun `exactly 16 alphanumeric chars is kept whole`() {
        val v = "abcd1234efgh5678" // 16 chars
        val r = sani(v)
        assertEquals(v, r.effective)
        assertFalse(r.adjusted)
    }

    @Test fun `over-length label is truncated to 16 and flagged`() {
        val r = sani("idorcanarytest2026extra") // >16 alnum
        assertEquals(16, r.effective.length)
        assertEquals("idorcanarytest20", r.effective)
        assertTrue(r.adjusted)
        assertNotNull(r.note)
        assertTrue(r.note!!.contains("truncated"), r.note!!)
    }

    @Test fun `non-alphanumeric characters are stripped`() {
        val r = sani("idor-canary_7f") // dashes/underscores removed
        assertEquals("idorcanary7f", r.effective)
        assertTrue(r.adjusted)
        assertTrue(r.note!!.contains("non-alphanumeric"), r.note!!)
    }

    @Test fun `strip and truncate combine`() {
        // 20 alnum after stripping punctuation → truncated to 16
        val r = sani("idor-canary-test-2026-extra-label")
        assertEquals(16, r.effective.length)
        assertTrue(r.effective.all { it.isLetterOrDigit() })
        assertTrue(r.adjusted)
        assertTrue(r.note!!.contains("removed") && r.note!!.contains("truncated"), r.note!!)
    }

    @Test fun `all-non-alphanumeric input yields empty effective for caller rejection`() {
        val r = sani("---___...")
        assertEquals("", r.effective)
        // the bridge maps an empty effective to a clean actionable error
    }

    @Test fun `unicode letters and spaces are dropped as non-ascii-alphanumeric`() {
        val r = sani("café test 7") // é and spaces dropped → "caftest7"
        assertEquals("caftest7", r.effective)
        assertTrue(r.adjusted)
    }

    @Test fun `the limit constant matches Montoya's documented maximum`() {
        assertEquals(16, CollaboratorBridge.MAX_CUSTOM_DATA)
    }

    // ---------------------------------------------------------------
    // Saved clients (project persistence)
    // ---------------------------------------------------------------

    @Test fun `saved clients round-trip through the project store, awkward characters included`() {
        val clients = listOf(
            CollaboratorBridge.SavedClient("collab-001", "c2VjcmV0LW9uZQ==", "oastify.com", "2026-11-17T10:00:00Z"),
            CollaboratorBridge.SavedClient("collab-007", "k\"e\\y\n+/=", "polling.example:8443", "2026-11-17T11:00:00Z", label = "turbo"),
        )
        val stored = CollaboratorBridge.encodeSavedClients(clients)
        assertEquals(clients, CollaboratorBridge.decodeSavedClients(stored))
    }

    @Test fun `nothing stored reads as no clients`() {
        assertEquals(emptyList(), CollaboratorBridge.decodeSavedClients(null))
        assertEquals(emptyList(), CollaboratorBridge.decodeSavedClients(""))
        assertEquals(emptyList(), CollaboratorBridge.decodeSavedClients("[]"))
    }

    @Test fun `a damaged store never throws and keeps the entries that are whole`() {
        for (garbage in listOf("not json", "{\"client_id\":\"x\"}", "[1, 2", "42", "null")) {
            assertEquals(emptyList(), CollaboratorBridge.decodeSavedClients(garbage), garbage)
        }
        val mixed = """[
            {"client_id":"collab-001","secret_key":"k1","server":"s","created_at":"t"},
            {"client_id":"collab-002"},
            {"secret_key":"orphan"},
            {"client_id":"","secret_key":"blank-id"},
            {"client_id":"collab-003","secret_key":42},
            "junk",
            {"client_id":"collab-001","secret_key":"duplicate-id"},
            {"client_id":"collab-004","secret_key":"k4"}
        ]"""
        assertEquals(
            listOf(
                CollaboratorBridge.SavedClient("collab-001", "k1", "s", "t"),
                CollaboratorBridge.SavedClient("collab-004", "k4", "", ""),
            ),
            CollaboratorBridge.decodeSavedClients(mixed)
        )
    }

    // ---------------------------------------------------------------
    // Raw HTTP message split
    // ---------------------------------------------------------------

    @Test fun `a raw request splits into start line, headers and body`() {
        val message = CollaboratorBridge.splitHttpMessage(
            "POST /leak?token=s3cr3t HTTP/1.1\r\nHost: abc123.oastify.com\r\nX-Dup: 1\r\nX-Dup:2\r\nEmpty:\r\n\r\nuser=admin\r\n\r\npw=x"
        )
        assertEquals("POST /leak?token=s3cr3t HTTP/1.1", message.startLine)
        assertEquals(
            listOf("Host" to "abc123.oastify.com", "X-Dup" to "1", "X-Dup" to "2", "Empty" to ""),
            message.headers
        )
        assertEquals("user=admin\r\n\r\npw=x", message.body, "only the first blank line ends the headers")
    }

    @Test fun `bare LF line endings, a missing body and odd header lines are all kept`() {
        val lfOnly = CollaboratorBridge.splitHttpMessage("GET / HTTP/1.0\nHost: h\n\nbody")
        assertEquals(CollaboratorBridge.HttpMessage("GET / HTTP/1.0", listOf("Host" to "h"), "body"), lfOnly)

        val noBlankLine = CollaboratorBridge.splitHttpMessage("GET / HTTP/1.1\r\nHost: h")
        assertEquals(CollaboratorBridge.HttpMessage("GET / HTTP/1.1", listOf("Host" to "h"), ""), noBlankLine)

        val odd = CollaboratorBridge.splitHttpMessage("GET / HTTP/2\r\n:authority: h\r\nno colon here\r\nA: b: c\r\n\r\n")
        assertEquals(listOf(":authority" to "h", "no colon here" to "", "A" to "b: c"), odd.headers)

        assertEquals(CollaboratorBridge.HttpMessage("", emptyList(), ""), CollaboratorBridge.splitHttpMessage(""))
    }

    // ---------------------------------------------------------------
    // Interaction JSON
    // ---------------------------------------------------------------

    private val payload = CollaboratorPayloadInfo("abc123", "abc123.oastify.com", "collab-001", customData = "mark7")

    private fun record(
        type: String,
        dns: CollaboratorDnsDetails? = null,
        http: CollaboratorHttpDetails? = null,
        smtp: CollaboratorSmtpDetails? = null,
        detailsError: String? = null,
    ) = CollaboratorRecord(
        clientId = "collab-001",
        payloadId = "abc123",
        type = type,
        timestamp = "2026-11-17T10:00:01Z",
        clientIp = "203.0.113.5",
        clientPort = 44321,
        customData = "mark7",
        dns = dns,
        http = http,
        smtp = smtp,
        detailsError = detailsError,
        seq = 7,
    )

    private val response = "HTTP/1.1 200 OK\r\nServer: Burp Collaborator https://burpcollaborator.net/\r\n" +
        "Content-Type: text/html\r\n\r\n<html><body>zq8</body></html>"

    private fun httpRecord(request: String, response: String? = this.response, requestLength: Int = request.length) = record(
        CollaboratorRecord.HTTP,
        http = CollaboratorHttpDetails(
            protocol = "HTTPS",
            method = "POST",
            url = "https://abc123.oastify.com/leak?token=s3cr3t",
            status = if (response == null) null else 200,
            request = request,
            response = response,
            responseMimeType = "HTML",
            requestLength = requestLength,
        )
    )

    private fun JsonObject.text(key: String): String? = this[key]?.jsonPrimitive?.content

    private fun JsonObject.headers(key: String): List<Pair<String, String>> =
        getValue(key).jsonArray.map { it.jsonObject.text("name")!! to it.jsonObject.text("value")!! }

    @Test fun `an interaction names its payload, its position and where it came from`() {
        val json = CollaboratorBridge.serializeInteraction(record(CollaboratorRecord.DNS, CollaboratorDnsDetails("A", "abc123.oastify.com", null, "00")), payload)
        assertEquals(7L, json.getValue("seq").jsonPrimitive.long)
        assertEquals("dns", json.text("type"))
        assertEquals("abc123", json.text("id"), "the Montoya interaction id, which the UI keys on")
        assertEquals("abc123", json.text("payload_id"))
        assertEquals("abc123.oastify.com", json.text("payload"))
        assertEquals("collab-001", json.text("client_id"))
        assertEquals("203.0.113.5", json.text("client_ip"))
        assertEquals(44321, json.getValue("client_port").jsonPrimitive.int)
        assertEquals("2026-11-17T10:00:01Z", json.text("timestamp"))
        assertEquals("mark7", json.text("custom_data"))
        assertNull(json["metadata"])

        val unknownPayload = CollaboratorBridge.serializeInteraction(record(CollaboratorRecord.DNS), payload = null)
        assertEquals("abc123", unknownPayload.text("payload_id"), "the id is on the interaction itself")
        assertNull(unknownPayload["payload"])

        val labelled = CollaboratorBridge.serializeInteraction(record(CollaboratorRecord.DNS), payload.copy(metadata = "SSRF in webhook"))
        assertEquals("SSRF in webhook", labelled.text("metadata"))
    }

    @Test fun `an HTTP interaction carries the full request and response`() {
        val request = "POST /leak?token=s3cr3t HTTP/1.1\r\nHost: abc123.oastify.com\r\nCookie: session=exfiltrated\r\n" +
            "X-Dup: 1\r\nX-Dup: 2\r\n\r\nuser=admin&pw=hunter2"
        val http = CollaboratorBridge.serializeInteraction(httpRecord(request), payload).getValue("http_details").jsonObject

        assertEquals("HTTPS", http.text("protocol"))
        assertEquals("POST", http.text("request_method"))
        assertEquals("https://abc123.oastify.com/leak?token=s3cr3t", http.text("request_url"))
        assertEquals(200, http.getValue("response_status").jsonPrimitive.int)
        assertEquals("POST /leak?token=s3cr3t HTTP/1.1", http.text("request_line"))
        assertEquals(
            listOf("Host" to "abc123.oastify.com", "Cookie" to "session=exfiltrated", "X-Dup" to "1", "X-Dup" to "2"),
            http.headers("request_headers")
        )
        assertEquals("user=admin&pw=hunter2", http.text("request_body"))
        assertEquals(request.length, http.getValue("request_length").jsonPrimitive.int)
        assertEquals(
            listOf("Server" to "Burp Collaborator https://burpcollaborator.net/", "Content-Type" to "text/html"),
            http.headers("response_headers")
        )
        assertEquals("<html><body>zq8</body></html>", http.text("response_body"))
        assertEquals(response.length, http.getValue("response_length").jsonPrimitive.int)
        for (flag in listOf("request_body_truncated", "request_body_binary", "response_body_truncated", "response_body_binary")) {
            assertNull(http[flag], flag)
        }
    }

    @Test fun `an HTTP interaction without a response reports status 0 and no response fields`() {
        val http = CollaboratorBridge.serializeInteraction(httpRecord("GET / HTTP/1.1\r\nHost: h\r\n\r\n", response = null), payload)
            .getValue("http_details").jsonObject
        assertEquals(0, http.getValue("response_status").jsonPrimitive.int)
        assertEquals("", http.text("request_body"))
        assertNull(http["response_headers"])
        assertNull(http["response_body"])
        assertNull(http["response_length"])
    }

    @Test fun `a binary body becomes a placeholder while the headers stay readable`() {
        val request = "POST /up HTTP/1.1\r\nHost: h\r\nX-Leak: still-here\r\n\r\n\u0000\u0001\u0002PNG\u0000\u0000"
        val http = CollaboratorBridge.serializeInteraction(httpRecord(request), payload).getValue("http_details").jsonObject

        assertEquals(listOf("Host" to "h", "X-Leak" to "still-here"), http.headers("request_headers"))
        assertTrue(http.text("request_body")!!.startsWith("[binary request body omitted"), http.text("request_body"))
        assertTrue(http.getValue("request_body_binary").jsonPrimitive.boolean)
    }

    @Test fun `bodies are cut at max_body_length and flagged`() {
        val request = "POST / HTTP/1.1\r\nHost: h\r\n\r\n" + "A".repeat(5_000)
        val http = CollaboratorBridge.serializeInteraction(httpRecord(request), payload, maxBodyLength = 100)
            .getValue("http_details").jsonObject

        assertEquals("A".repeat(100) + "... [truncated, full length: 5000]", http.text("request_body"))
        assertTrue(http.getValue("request_body_truncated").jsonPrimitive.boolean)
        assertEquals(listOf("Host" to "h"), http.headers("request_headers"), "the cap is on bodies, not headers")
        assertEquals("<html><body>zq8</body></html>", http.text("response_body"), "a body under the cap is untouched")
        assertNull(http["response_body_truncated"])
    }

    @Test fun `a request cut when it was captured is flagged even though what is left fits`() {
        val http = CollaboratorBridge.serializeInteraction(
            httpRecord("POST / HTTP/1.1\r\nHost: h\r\n\r\nkept part", requestLength = 3_000_000), payload
        ).getValue("http_details").jsonObject

        assertEquals("kept part", http.text("request_body"))
        assertTrue(http.getValue("request_body_truncated").jsonPrimitive.boolean)
        assertEquals(3_000_000, http.getValue("request_length").jsonPrimitive.int)
    }

    @Test fun `a lone surrogate in a header cannot reach the encoder`() {
        val request = "GET /a\uD83D HTTP/1.1\r\nX-Bad\uDE00: va\uD83Dlue\r\nX-Emoji: \uD83D\uDE00\r\n\r\n"
        val http = CollaboratorBridge.serializeInteraction(httpRecord(request), payload).getValue("http_details").jsonObject

        assertEquals("GET /a\uFFFD HTTP/1.1", http.text("request_line"))
        assertEquals(listOf("X-Bad\uFFFD" to "va\uFFFDlue", "X-Emoji" to "\uD83D\uDE00"), http.headers("request_headers"))
    }

    @Test fun `a header block beyond its cap is cut and flagged`() {
        val headers = (1..30).joinToString("") { "X-Fill-$it: ${"v".repeat(9_990)}\r\n" } // about 10k characters each
        val http = CollaboratorBridge.serializeInteraction(httpRecord("GET / HTTP/1.1\r\n$headers\r\n"), payload)
            .getValue("http_details").jsonObject

        val shown = http.headers("request_headers")
        assertTrue(shown.size in 9..11, "about ten 10k headers fit in the 100k cap, got ${shown.size}")
        assertTrue(shown.sumOf { it.first.length + it.second.length } <= 100_000)
        assertTrue(http.getValue("request_headers_truncated").jsonPrimitive.boolean)
    }

    @Test fun `the summary form used for events leaves the headers and bodies out`() {
        val request = "POST /x HTTP/1.1\r\nHost: h\r\n\r\nbody"
        val http = CollaboratorBridge.serializeInteraction(httpRecord(request), payload, maxBodyLength = 2_000, full = false)
            .getValue("http_details").jsonObject

        assertEquals("POST", http.text("request_method"))
        assertEquals("https://abc123.oastify.com/leak?token=s3cr3t", http.text("request_url"))
        assertEquals(200, http.getValue("response_status").jsonPrimitive.int)
        assertEquals("POST /x HTTP/1.1", http.text("request_line"))
        for (left in listOf("request_headers", "request_body", "response_headers", "response_body")) {
            assertNull(http[left], left)
        }
    }

    @Test fun `a DNS interaction gives the decoded name or the reason there is none`() {
        val decoded = CollaboratorBridge.serializeInteraction(
            record(CollaboratorRecord.DNS, dns = CollaboratorDnsDetails("AAAA", "abc123.oastify.com", null, "1234")), payload
        ).getValue("dns_details").jsonObject
        assertEquals("AAAA", decoded.text("query_type"))
        assertEquals("abc123.oastify.com", decoded.text("query_name"))
        assertEquals("1234", decoded.text("query_hex"))
        assertNull(decoded["query_name_error"])

        val malformed = CollaboratorBridge.serializeInteraction(
            record(CollaboratorRecord.DNS, dns = CollaboratorDnsDetails("UNKNOWN", null, "reserved label type (length byte 0x80) at offset 12", "80ff")),
            payload
        ).getValue("dns_details").jsonObject
        assertNull(malformed["query_name"], "a query that does not decode must not come out as a name")
        assertEquals("reserved label type (length byte 0x80) at offset 12", malformed.text("query_name_error"))
        assertEquals("80ff", malformed.text("query_hex"), "the raw query is still there to inspect")
    }

    @Test fun `an SMTP interaction carries the conversation`() {
        val conversation = "EHLO attacker\r\nMAIL FROM:<a@b>\r\nRCPT TO:<x@abc123.oastify.com>\r\nDATA\r\nSubject: leak\r\n\r\nsecret\r\n.\r\n"
        val smtp = CollaboratorBridge.serializeInteraction(
            record(CollaboratorRecord.SMTP, smtp = CollaboratorSmtpDetails("SMTPS", conversation)), payload
        ).getValue("smtp_details").jsonObject
        assertEquals("SMTPS", smtp.text("protocol"))
        assertEquals(conversation, smtp.text("conversation"))
        assertEquals(conversation.length, smtp.getValue("conversation_length").jsonPrimitive.int)
        assertNull(smtp["conversation_truncated"])

        val cut = CollaboratorBridge.serializeInteraction(
            record(CollaboratorRecord.SMTP, smtp = CollaboratorSmtpDetails("SMTP", conversation)), payload, maxBodyLength = 10
        ).getValue("smtp_details").jsonObject
        assertEquals("EHLO attac... [truncated, full length: ${conversation.length}]", cut.text("conversation"))
        assertTrue(cut.getValue("conversation_truncated").jsonPrimitive.boolean)
    }

    @Test fun `details Burp did not provide are reported where they would have been`() {
        val dns = CollaboratorBridge.serializeInteraction(record(CollaboratorRecord.DNS, detailsError = "DNS details not available"), payload)
        assertEquals("DNS details not available", dns.getValue("dns_details").jsonObject.text("error"))
        assertNull(dns["error"], "one unreadable interaction is not a failed poll")

        val http = CollaboratorBridge.serializeInteraction(record(CollaboratorRecord.HTTP), payload)
        assertEquals("HTTP details not available", http.getValue("http_details").jsonObject.text("error"))

        val smtp = CollaboratorBridge.serializeInteraction(record(CollaboratorRecord.SMTP, detailsError = "Could not read SMTP details: boom"), payload)
        assertEquals("Could not read SMTP details: boom", smtp.getValue("smtp_details").jsonObject.text("error"))

        val unknown = CollaboratorBridge.serializeInteraction(record("UNKNOWN", detailsError = "Interaction type could not be read"), payload)
        assertEquals("unknown", unknown.text("type"))
        assertEquals("Interaction type could not be read", unknown.text("details_error"))
    }
}
