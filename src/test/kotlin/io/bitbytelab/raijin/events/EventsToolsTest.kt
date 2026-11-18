package io.bitbytelab.raijin.events

import io.bitbytelab.raijin.testClientConnection
import io.bitbytelab.raijin.tools.events.EventsTools
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** events_subscribe leaks nothing, events_get reads a subscription, events_clear keeps internal listeners. */
class EventsToolsTest {

    private val bus = EventBus()
    private val server = Server(
        Implementation("test", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    ).also { EventsTools.register(it, bus) }

    private fun call(tool: String, args: JsonObject = buildJsonObject {}): CallToolResult = runBlocking {
        server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, args)))
    }

    private fun CallToolResult.json(): JsonObject = Json.parseToJsonElement((content.first() as TextContent).text).jsonObject

    @Test fun `subscribing many times registers no push callback`() {
        repeat(20) { call("events_subscribe", buildJsonObject { putJsonArray("types") { add("scanner.issue") } }) }
        assertEquals(0, bus.pushSubscriberCount())
        assertEquals(20, bus.pollSubscriptionCount())
    }

    @Test fun `events_get with a subscription returns its matching events since the last poll`() {
        val id = call("events_subscribe", buildJsonObject { putJsonArray("types") { add("scanner.issue") } })
            .json().getValue("subscription_id").jsonPrimitive.content
        bus.emit("proxy.request", buildJsonObject {})
        bus.emit("scanner.issue", buildJsonObject { put("name", "xss") })

        val first = call("events_get", buildJsonObject { put("subscription_id", id) }).json()
        val events = first.getValue("events").jsonArray
        assertEquals(1, events.size)
        assertEquals("scanner.issue", events.single().jsonObject.getValue("type").jsonPrimitive.content)

        val second = call("events_get", buildJsonObject { put("subscription_id", id) }).json()
        assertTrue(second.getValue("events").jsonArray.isEmpty())
    }

    @Test fun `an unknown subscription is an error result`() {
        val r = call("events_get", buildJsonObject { put("subscription_id", "sub-404") })
        assertEquals(true, r.isError)
        assertTrue(r.json().getValue("error").jsonPrimitive.content.contains("events_subscribe"))
    }

    @Test fun `events_clear drops client subscriptions but keeps internal listeners`() {
        var internalSeen = 0
        bus.subscribeInternal(emptyList()) { internalSeen++ }
        call("events_subscribe")
        bus.emit("t", buildJsonObject {})

        val cleared = call("events_clear").json()
        assertEquals(1, cleared.getValue("events_removed").jsonPrimitive.content.toInt())
        assertEquals(0, bus.pollSubscriptionCount())
        bus.emit("t", buildJsonObject {})
        assertEquals(2, internalSeen, "the dashboard / UI listener keeps receiving events after events_clear")
    }

    @Test fun `events_unsubscribe reports an unknown id`() {
        val id = call("events_subscribe").json().getValue("subscription_id").jsonPrimitive.content
        assertEquals("unsubscribed", call("events_unsubscribe", buildJsonObject { put("subscription_id", id) }).json().getValue("status").jsonPrimitive.content)
        assertEquals("not_found", call("events_unsubscribe", buildJsonObject { put("subscription_id", id) }).json().getValue("status").jsonPrimitive.content)
    }

    @Test fun `a negative max_events is clamped to 0 and reported`() {
        val r = call("events_get", buildJsonObject { put("max_events", -1) })
        assertEquals(false, r.isError ?: false)
        assertEquals(0, r.json().getValue("max_events_clamped_to").jsonPrimitive.content.toInt())
    }
}
