package io.bitbytelab.raijin.tools

import io.bitbytelab.raijin.bridge.UtilitiesBridge
import io.bitbytelab.raijin.testClientConnection
import io.bitbytelab.raijin.tools.utilities.UtilitiesTools
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.lang.reflect.Proxy
import java.net.URLDecoder
import java.util.Base64
import burp.api.montoya.MontoyaApi
import burp.api.montoya.utilities.Base64Utils
import burp.api.montoya.utilities.URLUtils
import burp.api.montoya.utilities.Utilities
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ToolResultHelpersTest {

    @Test
    fun `toolError marks isError and produces valid escaped JSON`() {
        val msg = "bad \"input\"\nline2 \\ path"
        val res = toolError(msg)
        assertEquals(true, res.isError)
        val parsed = Json.parseToJsonElement((res.content.first() as TextContent).text).jsonObject
        assertEquals(msg, parsed["error"]?.jsonPrimitive?.content)
    }

    @Test
    fun `toolJsonResult sets isError only when JsonObject contains non-null error`() {
        val okObj = toolJsonResult(buildJsonObject { put("status", "ok") })
        assertFalse(okObj.isError == true)

        val errObj = toolJsonResult(buildJsonObject { put("error", "boom") })
        assertEquals(true, errObj.isError)

        val arrRes = toolJsonResult(buildJsonArray { })
        assertFalse(arrRes.isError == true)
    }

    private fun stubUtilitiesApi(): MontoyaApi {
        val b64Utils = Proxy.newProxyInstance(Base64Utils::class.java.classLoader, arrayOf(Base64Utils::class.java)) { _, m, args ->
            if (m.name == "decode") {
                val decoded = String(Base64.getDecoder().decode(args!![0] as String), Charsets.UTF_8)
                Proxy.newProxyInstance(MontoyaApi::class.java.classLoader, arrayOf(burp.api.montoya.core.ByteArray::class.java)) { _, bm, _ ->
                    if (bm.name == "toString") decoded else null
                }
            } else null
        } as Base64Utils
        val urlUtils = Proxy.newProxyInstance(URLUtils::class.java.classLoader, arrayOf(URLUtils::class.java)) { _, m, args ->
            if (m.name == "decode") URLDecoder.decode(args!![0] as String, Charsets.UTF_8) else null
        } as URLUtils
        val utilities = Proxy.newProxyInstance(Utilities::class.java.classLoader, arrayOf(Utilities::class.java)) { _, m, _ ->
            when (m.name) {
                "base64Utils" -> b64Utils
                "urlUtils" -> urlUtils
                else -> null
            }
        } as Utilities
        return Proxy.newProxyInstance(MontoyaApi::class.java.classLoader, arrayOf(MontoyaApi::class.java)) { _, m, _ ->
            if (m.name == "utilities") utilities else null
        } as MontoyaApi
    }

    @Test
    fun `util_base64_decode and util_url_decode emit valid JSON for strings with quotes and newlines`() {
        val server = Server(
            Implementation("test", "0"),
            ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
        )
        UtilitiesTools.register(server, UtilitiesBridge(stubUtilitiesApi()))

        val tricky = "{\"sub\":\"alice\",\"note\":\"line1\\nline2\"}"
        val b64 = Base64.getEncoder().encodeToString(tricky.toByteArray(Charsets.UTF_8))

        val b64Res = runBlocking {
            server.tools.getValue("util_base64_decode").handler(
                testClientConnection,
                CallToolRequest(CallToolRequestParams("util_base64_decode", buildJsonObject { put("data", b64) }))
            )
        }
        assertFalse(b64Res.isError == true)
        val b64Json = Json.parseToJsonElement((b64Res.content.first() as TextContent).text).jsonObject
        assertEquals(tricky, b64Json["decoded"]?.jsonPrimitive?.content)

        val urlRes = runBlocking {
            server.tools.getValue("util_url_decode").handler(
                testClientConnection,
                CallToolRequest(CallToolRequestParams("util_url_decode", buildJsonObject { put("data", "%22hello%5C%0Aworld%22") }))
            )
        }
        assertFalse(urlRes.isError == true)
        val urlJson = Json.parseToJsonElement((urlRes.content.first() as TextContent).text).jsonObject
        assertEquals("\"hello\\\nworld\"", urlJson["decoded"]?.jsonPrimitive?.content)
    }

    private fun utilitiesServer(): Server {
        val server = Server(
            Implementation("test", "0"),
            ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
        )
        UtilitiesTools.register(server, UtilitiesBridge(stubUtilitiesApi()))
        return server
    }

    private fun callUtil(server: Server, tool: String, args: JsonObject) = runBlocking {
        server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, args)))
    }

    private fun parsed(r: io.modelcontextprotocol.kotlin.sdk.types.CallToolResult) =
        Json.parseToJsonElement((r.content.first() as TextContent).text).jsonObject

    @Test
    fun `util_decode_smart emits valid JSON and fully_decoded for output with quotes, backslashes and newlines`() {
        val server = utilitiesServer()
        val plain = "say \"hi\"\n\\path\\"
        val b64 = Base64.getEncoder().encodeToString(plain.toByteArray(Charsets.UTF_8))

        val res = callUtil(server, "util_decode_smart", buildJsonObject { put("data", b64) })
        assertFalse(res.isError == true)
        val json = parsed(res)
        assertEquals(plain, json["decoded"]?.jsonPrimitive?.content)
        assertEquals(1, json["layers"]?.jsonPrimitive?.int)
        assertEquals(true, json["fully_decoded"]?.jsonPrimitive?.boolean)

        val capped = callUtil(server, "util_decode_smart", buildJsonObject {
            put("data", Base64.getEncoder().encodeToString(b64.toByteArray()))
            put("max_depth", 1)
        })
        assertEquals(false, parsed(capped)["fully_decoded"]?.jsonPrimitive?.boolean)
    }

    @Test
    fun `util_jwt_decode keeps claims with quotes, backslashes and newlines intact`() {
        val server = utilitiesServer()
        val enc = Base64.getUrlEncoder().withoutPadding()
        val note = "a \"quoted\" \\ back\nslash"
        val payload = buildJsonObject { put("sub", "alice"); put("note", note) }.toString()
        val token = enc.encodeToString("""{"alg":"HS256"}""".toByteArray()) + "." +
            enc.encodeToString(payload.toByteArray()) + ".sig"

        val res = callUtil(server, "util_jwt_decode", buildJsonObject { put("token", token) })
        assertFalse(res.isError == true)
        assertEquals(note, parsed(res)["payload"]?.jsonObject?.get("note")?.jsonPrimitive?.content)
    }

    @Test
    fun `utilities errors are flagged isError with valid JSON`() {
        val server = utilitiesServer()
        val cases = listOf(
            "util_random_string" to buildJsonObject { put("length", 0) },
            "util_random_bytes" to buildJsonObject { put("length", "many") },
            "util_random_bytes" to buildJsonObject { },
            "util_decode_smart" to buildJsonObject { put("data", "x"); put("max_depth", 1000) },
            "util_jwt_decode" to buildJsonObject { put("token", "not\"a\\jwt") },
            "util_base64_decode" to buildJsonObject { },
        )
        for ((tool, args) in cases) {
            val res = callUtil(server, tool, args)
            assertEquals(true, res.isError, "$tool $args")
            assertTrue(parsed(res)["error"]?.jsonPrimitive?.content?.isNotBlank() == true, "$tool $args")
        }
    }
}
