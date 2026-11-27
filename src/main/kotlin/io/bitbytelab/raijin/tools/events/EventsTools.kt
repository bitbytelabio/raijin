package io.bitbytelab.raijin.tools.events

import io.bitbytelab.raijin.core.ClampedInt
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asClampedInt
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.core.withClampReport
import io.bitbytelab.raijin.events.BurpEvent
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.*

object EventsTools {

    private const val DEFAULT_MAX_EVENTS = 20

    fun register(server: Server, eventBus: EventBus) {

        // 1. events_get
        server.addTool(
            name = "events_get",
            description =
                "Retrieve events from the event bus using cursor-based polling. Returns events " +
                    "whose ID is strictly greater than since_id. Use the last event's ID as the cursor " +
                    "for subsequent polls. With subscription_id (from events_subscribe) it returns the " +
                    "subscription's matching events since its previous poll instead, and advances that " +
                    "cursor; since_id is then ignored. Parameters: since_id (number, return events after " +
                    "this ID; defaults to 0 for all events), max_events (number, maximum events to return; " +
                    "defaults to $DEFAULT_MAX_EVENTS), subscription_id (string, optional).",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("since_id") {
                                put("type", "integer")
                                put("description", "Return events after this ID (default 0)")
                            }
                            putJsonObject("max_events") {
                                put("type", "integer")
                                put("minimum", 0)
                                put(
                                    "description",
                                    "Maximum events to return (default $DEFAULT_MAX_EVENTS)",
                                )
                            }
                            putJsonObject("subscription_id") {
                                put("type", "string")
                                put(
                                    "description",
                                    "Poll this subscription (from events_subscribe) from its own cursor",
                                )
                            }
                            putJsonObject("include_results") {
                                put("type", "boolean")
                                put(
                                    "description",
                                    "Include each tool call's result summary (default false: only is_error and its size in bytes)",
                                )
                            }
                        },
                    required = emptyList(),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val maxEventsArg = maxEventsArg(args)
                val maxEvents = maxEventsArg?.value ?: DEFAULT_MAX_EVENTS
                val includeResults = args["include_results"].asBooleanSafe() ?: false

                val subscriptionId = (args["subscription_id"] as? JsonPrimitive)?.contentOrNull
                if (subscriptionId != null) {
                    val page =
                        eventBus.poll(subscriptionId, maxEvents)
                            ?: return@addTool toolError(
                                "Unknown subscription_id '$subscriptionId': it was unsubscribed, cleared by events_clear, " +
                                    "or dropped as the least recently used beyond ${EventBus.MAX_POLL_SUBSCRIPTIONS} subscriptions. " +
                                    "Call events_subscribe again.",
                            )
                    return@addTool toolJsonResult(
                        buildJsonObject {
                                put("subscription_id", subscriptionId)
                                putJsonArray("types") {
                                    page.subscription.types.forEach { add(it) }
                                }
                                put("returned", page.events.size)
                                put("cursor", page.cursor)
                                put("last_id", eventBus.lastId())
                                put("missed_events", page.missed)
                                put("events", serializeEvents(page.events, includeResults))
                            }
                            .withClampReport("max_events", maxEventsArg),
                    )
                }

                val sinceId = args["since_id"].asLongSafe() ?: 0L
                val events = eventBus.getEvents(sinceId, maxEvents)
                toolJsonResult(
                    buildJsonObject {
                            put("since_id", sinceId)
                            put("returned", events.size)
                            put("last_id", eventBus.lastId())
                            put("buffer_size", eventBus.size())
                            put("events", serializeEvents(events, includeResults))
                        }
                        .withClampReport("max_events", maxEventsArg),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 2. events_get_by_type
        server.addTool(
            name = "events_get_by_type",
            description =
                "Retrieve events from the event bus filtered by event type(s). Supports " +
                    "cursor-based polling. Parameters: types (array of strings, event types to filter " +
                    "e.g. ['proxy.request', 'scanner.issue']), since_id (number, return events after " +
                    "this ID; defaults to 0), max_events (number, maximum events to return; defaults to $DEFAULT_MAX_EVENTS).",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("types") {
                                put("type", "array")
                                put(
                                    "description",
                                    "Event types to filter e.g. ['proxy.request', 'scanner.issue']",
                                )
                                putJsonObject("items") { put("type", "string") }
                            }
                            putJsonObject("since_id") {
                                put("type", "integer")
                                put("description", "Return events after this ID (default 0)")
                            }
                            putJsonObject("max_events") {
                                put("type", "integer")
                                put("minimum", 0)
                                put(
                                    "description",
                                    "Maximum events to return (default $DEFAULT_MAX_EVENTS)",
                                )
                            }
                        },
                    required = listOf("types"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()

                val types =
                    args["types"].asStringList()
                        ?: return@addTool toolError(
                            "Missing required parameter: types (array of strings)",
                        )

                val sinceId = args["since_id"].asLongSafe() ?: 0L
                val maxEventsArg = maxEventsArg(args)
                val maxEvents = maxEventsArg?.value ?: DEFAULT_MAX_EVENTS

                val events = eventBus.getEventsByType(types, sinceId, maxEvents)
                toolJsonResult(
                    buildJsonObject {
                            put("since_id", sinceId)
                            putJsonArray("types") { types.forEach { add(it) } }
                            put("returned", events.size)
                            put("last_id", eventBus.lastId())
                            put("events", serializeEvents(events))
                        }
                        .withClampReport("max_events", maxEventsArg),
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 3. events_subscribe
        server.addTool(
            name = "events_subscribe",
            description =
                "Open a poll subscription: a type filter plus a cursor starting after the latest " +
                    "event. Read it with events_get(subscription_id=...), which returns the matching events " +
                    "since the previous poll and advances the cursor. The subscription holds no events (they " +
                    "stay in the event ring buffer until evicted), so poll regularly. At most " +
                    "${EventBus.MAX_POLL_SUBSCRIPTIONS} stay open; the least recently used is dropped beyond that. " +
                    "Parameters: types (array of strings, event types to subscribe to; empty array subscribes " +
                    "to all events).",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("types") {
                                put("type", "array")
                                put(
                                    "description",
                                    "Event types to subscribe to; empty array subscribes to all events",
                                )
                                putJsonObject("items") { put("type", "string") }
                            }
                        },
                    required = emptyList(),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val types = args["types"].asStringList().orEmpty()

                val subscription = eventBus.openPollSubscription(types)
                toolJsonResult(
                    buildJsonObject {
                        put("subscription_id", subscription.id)
                        put("status", "subscribed")
                        put("cursor_since_id", subscription.cursor)
                        putJsonArray("types") { subscription.types.forEach { add(it) } }
                        put(
                            "note",
                            "Poll with events.get with subscription_id '${subscription.id}'; each poll returns " +
                                "the matching events since the previous one.",
                        )
                    },
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 4. events_unsubscribe
        server.addTool(
            name = "events_unsubscribe",
            description =
                "Unsubscribe from event bus notifications. Removes a previously created " +
                    "subscription by its ID. Parameters: subscription_id (string, the subscription " +
                    "ID returned by events_subscribe).",
            inputSchema =
                ToolSchema(
                    properties =
                        buildJsonObject {
                            putJsonObject("subscription_id") {
                                put("type", "string")
                                put("description", "Subscription ID returned by events_subscribe")
                            }
                        },
                    required = listOf("subscription_id"),
                ),
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val subscriptionId =
                    (args["subscription_id"] as? JsonPrimitive)?.contentOrNull
                        ?: return@addTool toolError("Missing required parameter: subscription_id")

                val removed = eventBus.unsubscribe(subscriptionId)
                toolJsonResult(
                    buildJsonObject {
                        put("subscription_id", subscriptionId)
                        put("status", if (removed) "unsubscribed" else "not_found")
                    },
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 5. events_clear
        server.addTool(
            name = "events_clear",
            description =
                "Clear all buffered events and drop every subscription opened with " +
                    "events_subscribe. Burp-side listeners (the dashboard live feed, the Raijin tab) keep " +
                    "running. Irreversible. No parameters required.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList()),
        ) { _ ->
            try {
                val sizeBefore = eventBus.size()
                eventBus.clear()
                toolJsonResult(
                    buildJsonObject {
                        put("status", "cleared")
                        put("events_removed", sizeBefore)
                    },
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    /**
     * `max_events` clamped into 0..[MAX_EVENTS] (null when absent): a negative or huge value is
     * served at the bound and reported as `max_events_clamped_to`; only a non-integer is an error.
     */
    internal fun maxEventsArg(args: Map<String, JsonElement>): ClampedInt? =
        args["max_events"].asClampedInt("max_events", 0, MAX_EVENTS).getOrThrow()

    private const val MAX_EVENTS = 10_000

    /**
     * Serializes a list of BurpEvent objects to a JsonArray. Without [includeResults], a tool
     * call's `result_summary` becomes `result: {is_error, bytes}` (its UTF-8 size), which keeps a
     * page of events small.
     */
    private fun serializeEvents(
        events: List<BurpEvent>,
        includeResults: Boolean = true,
    ): JsonArray {
        return buildJsonArray {
            for (event in events) {
                addJsonObject {
                    put("id", event.id)
                    put("type", event.type)
                    put("timestamp", event.timestamp)
                    put("data", if (includeResults) event.data else compactResult(event.data))
                }
            }
        }
    }

    private fun compactResult(data: JsonElement): JsonElement {
        val obj = data as? JsonObject ?: return data
        val summary = (obj["result_summary"] as? JsonPrimitive)?.contentOrNull ?: return data
        return JsonObject(
            obj.filterKeys { it != "result_summary" } +
                ("result" to
                    buildJsonObject {
                        obj["is_error"]?.let { put("is_error", it) }
                        put("bytes", summary.toByteArray(Charsets.UTF_8).size)
                    }),
        )
    }
}
