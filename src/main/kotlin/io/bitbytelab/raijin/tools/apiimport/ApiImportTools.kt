package io.bitbytelab.raijin.tools.apiimport

import io.bitbytelab.raijin.bridge.ApiImportBridge
import io.bitbytelab.raijin.core.asBodyString
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object ApiImportTools {
    fun register(server: Server, bridge: ApiImportBridge) {
        server.addTool(
            name = "api_import_openapi",
            description = "Import an OpenAPI 3.0/3.1 or Swagger 2.0 document (JSON or YAML). Builds one ready-to-send " +
                "request per operation, with example path, query, header and cookie parameters and a body (JSON, " +
                "form, multipart or XML), adds them to the sitemap and optionally sends them through Burp so the " +
                "sitemap holds the responses too. Returns the endpoints, each with the security requirement it is " +
                "under, and security_schemes, which says how every credential is carried. Parameters: spec_json " +
                "(required, the document text), spec_url (where the document was downloaded from; resolves relative " +
                "server URLs), base_url (optional target override), auth_header/auth_value (optional auth for all " +
                "requests), add_to_scope (bool), add_to_sitemap (bool), send_requests (bool, actually send and get " +
                "responses).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("spec_json") { put("type", "string"); put("description", "The OpenAPI/Swagger document text, JSON or YAML") }
                    putJsonObject("spec_url") { put("type", "string"); put("description", "URL the document was downloaded from, so relative server URLs (and a Swagger 2.0 document without host) can be resolved. It is not fetched") }
                    putJsonObject("base_url") { put("type", "string"); put("description", "Optional base URL override, e.g. https://api.example.com/v1; replaces the document's server URLs") }
                    putJsonObject("auth_header") { put("type", "string"); put("description", "Optional auth header name for all requests (needs auth_value)") }
                    putJsonObject("auth_value") { put("type", "string"); put("description", "Optional auth header value for all requests (needs auth_header)") }
                    putJsonObject("add_to_scope") { put("type", "boolean"); put("description", "Add the base URL to scope (default true)") }
                    putJsonObject("add_to_sitemap") { put("type", "boolean"); put("description", "Add the generated requests to the sitemap (default true)") }
                    putJsonObject("send_requests") { put("type", "boolean"); put("description", "Actually send requests and get responses (default false)") }
                },
                required = listOf("spec_json")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                // A document passed as a JSON object rather than as text is taken as is.
                val spec = args["spec_json"].asBodyString()?.takeIf { it.isNotBlank() }
                    ?: return@addTool toolError("Parameter 'spec_json' is required")
                val authHeader = args["auth_header"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() }
                val authValue = args["auth_value"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() }
                if ((authHeader == null) != (authValue == null)) {
                    return@addTool toolError("Parameters 'auth_header' and 'auth_value' must be given together")
                }

                toolJsonResult(
                    bridge.importOpenApi(
                        specJson = spec,
                        baseUrl = args["base_url"]?.jsonPrimitive?.contentOrNull,
                        authHeader = authHeader,
                        authValue = authValue,
                        addToScope = args["add_to_scope"].asBooleanSafe() ?: true,
                        addToSitemap = args["add_to_sitemap"].asBooleanSafe() ?: true,
                        sendRequests = args["send_requests"].asBooleanSafe() ?: false,
                        specUrl = args["spec_url"]?.jsonPrimitive?.contentOrNull
                    )
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
