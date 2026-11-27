package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.core.BuildInfo
import io.bitbytelab.raijin.tools.ToolArgs
import io.bitbytelab.raijin.tools.ToolConsolidation
import io.bitbytelab.raijin.tools.ToolNames
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
import io.modelcontextprotocol.kotlin.sdk.types.ReadResourceRequest
import io.modelcontextprotocol.kotlin.sdk.types.ReadResourceRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.ReadResourceResult
import io.modelcontextprotocol.kotlin.sdk.types.RequestId
import io.modelcontextprotocol.kotlin.sdk.types.Resource
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
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

/**
 * Plain JSON tool API on the MCP listeners, for the `raijin` CLI: list the tools and call one
 * without an MCP session. [installLocalhostSecurity] guards it like `/mcp`.
 *
 * - `GET /api/v1/info` → `{"name","version","api","instructions"}`
 * - `GET /api/v1/tools` → `{"tools":[Tool...]}` (MCP `Tool` JSON)
 * - `GET /api/v1/resources` → `{"resources":[Resource...]}` (MCP `Resource` JSON)
 * - `GET /api/v1/resources/read?uri=<uri>` → MCP `ReadResourceResult`
 * - `POST /api/v1/tools/{name}` → body = the tool's arguments object (`application/json`; empty =
 *   `{}`); answers an MCP `CallToolResult`. [name] is resolved leniently ([ToolNames.resolve]); an
 *   unknown name is an `unknown_tool` error result, and error envelopes come in the CLI's `run`
 *   form ([runForm]).
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
                        put("instructions", McpServerManager.SERVER_INSTRUCTIONS)
                    },
                )
            }
            get("tools") {
                val tools =
                    server.tools.values.map {
                        McpJson.encodeToJsonElement(Tool.serializer(), it.tool)
                    }
                call.respondJson(HttpStatusCode.OK, JsonObject(mapOf("tools" to JsonArray(tools))))
            }
            get("resources") {
                val resources =
                    server.resources.values.map {
                        McpJson.encodeToJsonElement(Resource.serializer(), it.resource)
                    }
                call.respondJson(
                    HttpStatusCode.OK,
                    JsonObject(mapOf("resources" to JsonArray(resources))),
                )
            }
            get("resources/read") {
                val uri =
                    call.request.queryParameters["uri"]
                        ?: return@get call.respondError(
                            HttpStatusCode.BadRequest,
                            "uri query parameter is required.",
                            "missing_parameter",
                        )
                val registered =
                    server.resources[uri]
                        ?: return@get call.respondError(
                            HttpStatusCode.NotFound,
                            "unknown resource $uri.",
                            "not_found",
                        )
                val result =
                    try {
                        registered.readHandler(
                            ApiConnection,
                            ReadResourceRequest(ReadResourceRequestParams(uri = uri)),
                        )
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        return@get call.respondError(
                            HttpStatusCode.InternalServerError,
                            "reading $uri failed: ${e.message}",
                            "internal",
                        )
                    }
                call.respondJson(
                    HttpStatusCode.OK,
                    McpJson.encodeToJsonElement(ReadResourceResult.serializer(), result),
                )
            }
            post("tools/{name}") {
                val name = call.parameters["name"].orEmpty()
                val body =
                    call.readBounded()
                        ?: return@post call.respondError(
                            HttpStatusCode.PayloadTooLarge,
                            "request body over ${McpServerManager.MAX_REQUEST_BODY_BYTES} bytes.",
                            "invalid_arguments",
                        )
                // A non-JSON content type is what a cross-site <form> can send without a CORS
                // preflight.
                if (
                    body.isNotEmpty() &&
                        !call.request.contentType().match(ContentType.Application.Json)
                ) {
                    return@post call.respondError(
                        HttpStatusCode.UnsupportedMediaType,
                        "Content-Type must be application/json.",
                        "invalid_arguments",
                    )
                }
                val arguments =
                    parseArguments(body)
                        ?: return@post call.respondError(
                            HttpStatusCode.BadRequest,
                            "body must be a JSON object of the tool's arguments.",
                            "invalid_type",
                        )
                val tools = server.tools.mapValues { it.value.tool }
                val found =
                    when (val r = ToolNames.resolve(name, tools)) {
                        is ToolNames.Found -> r
                        is ToolNames.NotFound -> {
                            val result = unknownTool(name, r, arguments, tools)
                            return@post call.respondJson(
                                HttpStatusCode.OK,
                                McpJson.encodeToJsonElement(CallToolResult.serializer(), result),
                            )
                        }
                    }
                // `{"do":"scope.check","action":"list"}`: the explicit `action` wins; say so.
                val override =
                    actionOf(arguments)
                        ?.takeIf { found.action != null && it != found.action }
                        ?.let { "ran ${found.tool}.$it ('action' overrides 'do')" }
                val args =
                    JsonObject(
                        found.extra +
                            (found.action?.let { mapOf("action" to JsonPrimitive(it)) }
                                ?: emptyMap()) +
                            arguments,
                    )
                val result =
                    try {
                        server.tools
                            .getValue(found.tool)
                            .handler(
                                ApiConnection,
                                CallToolRequest(
                                    CallToolRequestParams(name = found.tool, arguments = args),
                                ),
                            )
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        ToolArgs.error(
                            "internal",
                            "${ToolArgs.callName(found.tool, actionOf(args))} failed: ${e.message ?: e.javaClass.simpleName}",
                        )
                    }
                val shaped =
                    ToolArgs.withNotes(
                        runForm(result, found.tool, actionOf(args)),
                        listOfNotNull(found.note, override),
                    )
                call.respondJson(
                    HttpStatusCode.OK,
                    McpJson.encodeToJsonElement(CallToolResult.serializer(), shaped),
                )
            }
        }
    }
}

private fun actionOf(args: JsonObject): String? =
    (args["action"] as? JsonPrimitive)?.takeIf { it.isString }?.content

/**
 * `unknown_tool` for [name]: the near call names, and `retry` only when [ToolNames.resolve] found
 * one certain call and [arguments] pass that call's checks as sent ([ToolConsolidation.callFits]).
 */
internal fun unknownTool(
    name: String,
    r: ToolNames.NotFound,
    arguments: JsonObject,
    tools: Map<String, Tool>,
): CallToolResult {
    val message =
        r.didYouMean.firstOrNull()?.let { "Unknown tool '$name'. Did you mean '$it'?" }
            ?: "Unknown tool '$name'; guide {} lists every tool."
    val args = JsonObject(arguments - "do")
    val retry =
        r.retry?.takeIf { call ->
            val tool = call.substringBefore('.')
            ToolConsolidation.callFits(
                tool,
                call.substringAfter('.', "").ifEmpty { null },
                args,
                tools[tool],
            )
        }
    return ToolArgs.error("unknown_tool", message) {
        putJsonArray("did_you_mean") { r.didYouMean.forEach { add(it) } }
        retry?.let { put("retry", JsonObject(mapOf("do" to JsonPrimitive(it)) + args)) }
        put("see", ToolArgs.guideCall(null))
    }
}

/**
 * [result] in the `run` form the `raijin` CLI takes: an error envelope (one JSON object with a
 * string `code`) gets its `example` and `retry` as `{"do":"tool[.action]", ...}` calls and a `see`
 * pointing at the tool's guide topic. Any other result is returned as is; MCP `/mcp` callers never
 * see this form.
 */
internal fun runForm(result: CallToolResult, tool: String, action: String?): CallToolResult {
    if (result.isError != true) return result
    val content = result.content.singleOrNull() as? TextContent ?: return result
    val json =
        runCatching { McpJson.parseToJsonElement(content.text) }.getOrNull() as? JsonObject
            ?: return result
    if ((json["code"] as? JsonPrimitive)?.isString != true) return result
    fun doForm(call: JsonObject): JsonObject {
        val a = actionOf(call)
        val target = if (a != null) "$tool.$a" else tool
        return JsonObject(
            mapOf("do" to JsonPrimitive(target)) + (if (a != null) call - "action" else call),
        )
    }
    val fields = LinkedHashMap<String, JsonElement>(json)
    listOf("example", "retry").forEach { key ->
        (json[key] as? JsonObject)?.let { fields[key] = doForm(it) }
    }
    if ("see" !in fields) {
        // An action the group does not have (a typo, `sha256`) has no topic of its own: point at
        // the tool.
        val known = action?.let { ToolConsolidation.resolveAction(tool, it) }
        val topic = if (known != null) "$tool.$known" else tool
        fields["see"] = ToolArgs.guideCall(topic)
    }
    return result.copy(content = listOf(content.copy(text = JsonObject(fields).toString())))
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
    respondText(
        McpJson.encodeToString(JsonElement.serializer(), body),
        ContentType.Application.Json,
        status,
    )

/** An HTTP error in the envelope's shape: `{"error", "code", "retryable"}`. */
private suspend fun ApplicationCall.respondError(
    status: HttpStatusCode,
    message: String,
    code: String,
) =
    respondJson(
        status,
        JsonObject(
            mapOf(
                "error" to JsonPrimitive(message),
                "code" to JsonPrimitive(code),
                "retryable" to JsonPrimitive(code in ToolArgs.RETRYABLE),
            ),
        ),
    )

/**
 * The [ClientConnection] tool handlers get over the API. No Raijin tool talks back to the client
 * (sampling, elicitation, roots), so only notifications are accepted, and dropped.
 */
private object ApiConnection : ClientConnection {
    override val sessionId: String = "raijin-api"

    override suspend fun notification(
        notification: ServerNotification,
        relatedRequestId: RequestId?,
    ) = Unit

    private fun unavailable(): Nothing =
        throw IllegalStateException("not available over the Raijin tool API")

    override suspend fun ping(request: PingRequest, options: RequestOptions?): EmptyResult =
        unavailable()

    override suspend fun createMessage(
        request: CreateMessageRequest,
        options: RequestOptions?,
    ): CreateMessageResult = unavailable()

    override suspend fun listRoots(
        request: ListRootsRequest,
        options: RequestOptions?,
    ): ListRootsResult = unavailable()

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

    override suspend fun createElicitation(
        request: ElicitRequest,
        options: RequestOptions?,
    ): ElicitResult = unavailable()

    override suspend fun sendLoggingMessage(notification: LoggingMessageNotification) =
        unavailable()

    override suspend fun sendResourceUpdated(notification: ResourceUpdatedNotification) =
        unavailable()

    override suspend fun sendResourceListChanged() = unavailable()

    override suspend fun sendToolListChanged() = unavailable()

    override suspend fun sendPromptListChanged() = unavailable()

    override suspend fun sendElicitationComplete(notification: ElicitationCompleteNotification) =
        unavailable()
}
