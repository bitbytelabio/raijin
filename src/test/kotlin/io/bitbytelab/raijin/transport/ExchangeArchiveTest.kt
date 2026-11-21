package io.bitbytelab.raijin.transport

import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueDefinition
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.io.File
import java.lang.reflect.Proxy
import java.nio.file.Files
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class ExchangeArchiveTest {
    private lateinit var dir: File

    @BeforeTest fun setUp() {
        dir = Files.createTempDirectory("raijin-archive").toFile()
        System.setProperty(ExchangeArchive.PROP_DIR, File(dir, "nested").path)
    }

    @AfterTest fun tearDown() {
        System.clearProperty(ExchangeArchive.PROP_DIR)
        dir.deleteRecursively()
    }

    private inline fun <reified T> fake(crossinline answer: (String) -> Any?): T =
        Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { _, m, _ -> answer(m.name) } as T

    private fun bytes(s: String): BurpByteArray = fake { if (it == "getBytes") s.toByteArray(Charsets.ISO_8859_1) else null }

    private fun exchange(req: String, resp: String?): HttpRequestResponse {
        val request = fake<HttpRequest> {
            when (it) { "method" -> "GET"; "url" -> "https://t.test/a?x=1"; "toByteArray" -> bytes(req); else -> null }
        }
        val response = resp?.let { r ->
            fake<HttpResponse> { when (it) { "statusCode" -> 200.toShort(); "toByteArray" -> bytes(r); else -> null } }
        }
        return fake { when (it) { "request" -> request; "response" -> response; "hasResponse" -> response != null; else -> null } }
    }

    private fun lines(name: String) = File(File(dir, "nested"), name).readLines().map { Json.parseToJsonElement(it).jsonObject }

    @Test fun `an exchange line has exactly the documented keys`() {
        ExchangeArchive.appendExchange("http_send_request", exchange("GET /a HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nhi"))
        val line = lines(ExchangeArchive.EXCHANGES_FILE).single()
        assertEquals(
            setOf(
                "seq", "time_epoch_ms", "tool", "method", "url", "status", "request_b64", "response_b64",
                "request_truncated", "response_truncated", "response_reconstructed",
            ),
            line.keys
        )
        assertEquals(1L, line["seq"]!!.jsonPrimitive.long)
        assertEquals("http_send_request", line["tool"]!!.jsonPrimitive.content)
        assertEquals(200, line["status"]!!.jsonPrimitive.int)
        assertEquals("HTTP/1.1 200 OK\r\n\r\nhi", String(Base64.getDecoder().decode(line["response_b64"]!!.jsonPrimitive.content)))
    }

    @Test fun `seq continues across lines and a missing response is null`() {
        ExchangeArchive.appendRaw("http_send_pipeline", "GET", "http://t.test:80/", "GET / HTTP/1.1\r\n\r\n".toByteArray(), null, null, true)
        ExchangeArchive.appendExchange("http_race", exchange("GET / HTTP/1.1\r\n\r\n", null))
        val (first, second) = lines(ExchangeArchive.EXCHANGES_FILE)
        assertEquals(listOf(1L, 2L), listOf(first["seq"]!!.jsonPrimitive.long, second["seq"]!!.jsonPrimitive.long))
        assertEquals(JsonNull, second["response_b64"])
        assertEquals(JsonNull, second["status"])
        assertEquals("true", first["response_reconstructed"]!!.jsonPrimitive.content)
    }

    @Test fun `an issue line has exactly the documented keys`() {
        val issue = fake<AuditIssue> {
            when (it) {
                "name" -> "SQL injection"; "severity" -> AuditIssueSeverity.HIGH; "confidence" -> AuditIssueConfidence.FIRM
                "baseUrl" -> "https://t.test/"; "detail" -> "d"; "remediation" -> ""
                "definition" -> fake<AuditIssueDefinition> { m ->
                    when (m) { "background" -> "Why it matters"; "remediation" -> "How to fix"; else -> null }
                }
                "requestResponses" -> List(5) { exchange("GET / HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n") }
                else -> null
            }
        }
        ExchangeArchive.appendIssue(issue)
        val line = lines(ExchangeArchive.ISSUES_FILE).single()
        assertEquals(
            setOf(
                "seq", "time_epoch_ms", "name", "severity", "confidence", "base_url", "detail", "remediation",
                "background", "remediation_background", "evidence",
            ),
            line.keys
        )
        assertEquals(JsonNull, line["remediation"])
        assertEquals("Why it matters", line["background"]!!.jsonPrimitive.content)
        assertEquals("How to fix", line["remediation_background"]!!.jsonPrimitive.content)
        assertEquals(3, line["evidence"]!!.jsonArray.size)
        assertEquals(setOf("request_b64", "response_b64"), line["evidence"]!!.jsonArray[0].jsonObject.keys)
    }

    @Test fun `nothing is written without the property`() {
        System.clearProperty(ExchangeArchive.PROP_DIR)
        ExchangeArchive.appendExchange("http_send_request", exchange("GET / HTTP/1.1\r\n\r\n", null))
        assertFalse(File(dir, "nested").exists())
    }
}
