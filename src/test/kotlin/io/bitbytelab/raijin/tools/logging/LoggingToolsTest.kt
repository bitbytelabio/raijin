package io.bitbytelab.raijin.tools.logging

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import io.bitbytelab.raijin.bridge.LoggingBridge
import io.bitbytelab.raijin.testClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * `log(action=message)` routes every level but `error` to Burp's output stream, as it always has. The
 * merged `log` tool advertises the event levels (`info`, `debug`, `critical`) for the same parameter,
 * so agents send them here too: they must still be logged, not refused.
 */
class LoggingToolsTest {
    private val output = mutableListOf<String>()
    private val errors = mutableListOf<String>()

    private val server = Server(
        Implementation("t", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    ).also { server ->
        val logging = Proxy.newProxyInstance(Logging::class.java.classLoader, arrayOf(Logging::class.java)) { _, m, args ->
            when (m.name) {
                "logToOutput" -> output += args[0].toString()
                "logToError" -> errors += args[0].toString()
                else -> error("unexpected Logging.${m.name}")
            }
            null
        } as Logging
        val api = Proxy.newProxyInstance(MontoyaApi::class.java.classLoader, arrayOf(MontoyaApi::class.java)) { _, m, _ ->
            if (m.name == "logging") logging else error("unexpected MontoyaApi.${m.name}")
        } as MontoyaApi
        LoggingTools.register(server, LoggingBridge(api))
    }

    private fun logMessage(message: String, level: String): CallToolResult = runBlocking {
        val args = buildJsonObject { put("message", message); put("level", level) }
        server.tools.getValue("log_message").handler(testClientConnection, CallToolRequest(CallToolRequestParams("log_message", args)))
    }

    @Test
    fun `log_message sends every level but error to the output stream`() {
        for (level in listOf("output", "info", "debug", "critical", "INFO", "error")) {
            assertNotEquals(true, logMessage("m-$level", level).isError, "level $level")
        }

        assertEquals(listOf("m-output", "m-info", "m-debug", "m-critical", "m-INFO"), output)
        assertEquals(listOf("m-error"), errors)
    }
}
