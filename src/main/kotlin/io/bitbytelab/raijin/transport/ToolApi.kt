package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.core.BuildInfo
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.contentLength
import io.ktor.server.request.contentType
import io.ktor.server.request.receiveChannel
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.utils.io.readBuffer
import io.modelcontextprotocol.kotlin.sdk.server.ClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.shared.RequestOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.CreateMessageRequest
import io.modelcontextprotocol.kotlin.sdk.types.CreateMessageResult
import io.modelcontextprotocol.kotlin.sdk.types.ElicitRequest
import io.modelcontextprotocol.kotlin.sdk.types.ElicitRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.ElicitResult
import io.modelcontextprotocol.kotlin.sdk.types.ElicitationCompleteNotification
import io.modelcontextprotocol.kotlin.sdk.types.EmptyResult
import io.modelcontextprotocol.kotlin.sdk.types.ListRootsRequest
import io.modelcontextprotocol.kotlin.sdk.types.ListRootsResult
import io.modelcontextprotocol.kotlin.sdk.types.LoggingMessageNotification
import io.modelcontextprotocol.kotlin.sdk.types.McpJson
import io.modelcontextprotocol.kotlin.sdk.types.PingRequest
import io.modelcontextprotocol.kotlin.sdk.types.RequestId
import io.modelcontextprotocol.kotlin.sdk.types.ResourceUpdatedNotification
import io.modelcontextprotocol.kotlin.sdk.types.ServerNotification
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.Tool
import kotlinx.coroutines.CancellationException
import kotlinx.io.readByteArray
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Plain JSON tool API on the MCP listeners, for the `raijin` CLI: list the tools and call one
 * without an MCP session. [installLocalhostSecurity] guards it like `/mcp`.
 *
 * - `GET  /api/v1/info`          → `{"name","version","api"}`
 * - `GET  /api/v1/tools`         → `{"tools":[Tool...]}` (MCP `Tool` JSON)
 * - `POST /api/v1/tools/{name}`  → body = the tool's arguments object (`application/json`; empty = `{}`);
 *   answers an MCP `CallToolResult`
 */
internal object ToolApi {
    const val BASE = "/api/v1"
    const val VERSION = 1
}

internal fun Application.installToolApi(server: Server) {
    routing {
        route(ToolApi.BASE) {
            get("info") {
                call.respondJson(
                    HttpStatusCode.OK,
                    buildJsonObject {
                        put("name", "burpsuite")
                        put("version", BuildInfo.VERSION)
                        put("api", ToolApi.VERSION)
                    }
                )
            }
            get("tools") {
                val tools = server.tools.values.map { McpJson.encodeToJsonElement(Tool.serializer(), it.tool) }
                call.respondJson(HttpStatusCode.OK, JsonObject(mapOf("tools" to JsonArray(tools))))
            }
            post("tools/{name}") {
                val name = call.parameters["name"].orEmpty()
                val registered = server.tools[name]
                    ?: return@post call.respondError(HttpStatusCode.NotFound, "unknown tool $name")
                val body = call.readBounded()
                    ?: return@post call.respondError(
                        HttpStatusCode.PayloadTooLarge,
                        "request body over ${McpServerManager.MAX_REQUEST_BODY_BYTES} bytes"
                    )
                // A non-JSON content type is what a cross-site <form> can send without a CORS preflight.
                if (body.isNotEmpty() && !call.request.contentType().match(ContentType.Application.Json)) {
                    return@post call.respondError(
                        HttpStatusCode.UnsupportedMediaType,
                        "Content-Type must be application/json"
                    )
                }
                val arguments = parseArguments(body)
                    ?: return@post call.respondError(
                        HttpStatusCode.BadRequest,
                        "body must be a JSON object of the tool's arguments"
                    )
                val result = try {
                    registered.handler(ApiConnection, CallToolRequest(CallToolRequestParams(name = name, arguments = arguments)))
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    CallToolResult(content = listOf(TextContent("Error executing tool $name: ${e.message}")), isError = true)
                }
                call.respondJson(HttpStatusCode.OK, McpJson.encodeToJsonElement(CallToolResult.serializer(), result))
            }
        }
    }
}

/** The body, or null when it is over [McpServerManager.MAX_REQUEST_BODY_BYTES]. */
private suspend fun ApplicationCall.readBounded(): ByteArray? {
    val max = McpServerManager.MAX_REQUEST_BODY_BYTES
    if ((request.contentLength() ?: 0L) > max) return null
    val bytes = receiveChannel().readBuffer(max + 1).readByteArray()
    return if (bytes.size > max) null else bytes
}

/** An empty body means no arguments; anything else must be one JSON object. */
private fun parseArguments(body: ByteArray): JsonObject? {
    val text = body.decodeToString()
    if (text.isBlank()) return JsonObject(emptyMap())
    return runCatching { McpJson.parseToJsonElement(text) }.getOrNull() as? JsonObject
}

private suspend fun ApplicationCall.respondJson(status: HttpStatusCode, body: JsonElement) =
    respondText(McpJson.encodeToString(JsonElement.serializer(), body), ContentType.Application.Json, status)

private suspend fun ApplicationCall.respondError(status: HttpStatusCode, message: String) =
    respondJson(status, JsonObject(mapOf("error" to JsonPrimitive(message))))

/**
 * The [ClientConnection] tool handlers get over the API. No Raijin tool talks back to the client
 * (sampling, elicitation, roots), so only notifications are accepted, and dropped.
 */
private object ApiConnection : ClientConnection {
    override val sessionId: String = "raijin-api"

    override suspend fun notification(notification: ServerNotification, relatedRequestId: RequestId?) = Unit

    private fun unavailable(): Nothing = throw IllegalStateException("not available over the Raijin tool API")

    override suspend fun ping(request: PingRequest, options: RequestOptions?): EmptyResult = unavailable()
    override suspend fun createMessage(request: CreateMessageRequest, options: RequestOptions?): CreateMessageResult =
        unavailable()
    override suspend fun listRoots(request: ListRootsRequest, options: RequestOptions?): ListRootsResult = unavailable()
    override suspend fun createElicitation(
        message: String,
        requestedSchema: ElicitRequestParams.RequestedSchema,
        options: RequestOptions?,
    ): ElicitResult = unavailable()
    override suspend fun createElicitation(
        message: String,
        elicitationId: String,
        url: String,
        options: RequestOptions?,
    ): ElicitResult = unavailable()
    override suspend fun createElicitation(request: ElicitRequest, options: RequestOptions?): ElicitResult = unavailable()
    override suspend fun sendLoggingMessage(notification: LoggingMessageNotification) = unavailable()
    override suspend fun sendResourceUpdated(notification: ResourceUpdatedNotification) = unavailable()
    override suspend fun sendResourceListChanged() = unavailable()
    override suspend fun sendToolListChanged() = unavailable()
    override suspend fun sendPromptListChanged() = unavailable()
    override suspend fun sendElicitationComplete(notification: ElicitationCompleteNotification) = unavailable()
}
