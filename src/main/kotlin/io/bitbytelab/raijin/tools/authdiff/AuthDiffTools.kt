package io.bitbytelab.raijin.tools.authdiff

import io.bitbytelab.raijin.bridge.AnalysisBridge
import io.bitbytelab.raijin.bridge.BridgeFactory
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asBoundedInt
import io.bitbytelab.raijin.core.asJsonObjectList
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

object AuthDiffTools {
    fun register(server: Server, bridges: BridgeFactory.Bridges) = register(server, bridges.analysis)

    fun register(server: Server, analysis: AnalysisBridge) {
        server.addTool(
            name = "auth_diff",
            description = """Authorization level diffing: sends the same request with different auth levels (admin, user, unauthenticated) and compares responses to detect IDOR, privilege escalation, and broken access control.

Provide auth_levels as an array of at least 2 objects: [{"name": "admin", "header_name": "Authorization", "header_value": "Bearer admin-token"}, {"name": "user", "header_name": "Authorization", "header_value": "Bearer user-token"}, {"name": "none"}]. A level that needs several headers (session cookie + CSRF token) lists them in "headers": {"Cookie": "...", "X-CSRF-Token": "..."}; "remove_headers": ["X-Tenant-Key"] drops headers for that level.

A level's headers replace the request's own (never a second Cookie/Authorization line). A level named "none"/"unauth"/"anonymous" is sent without credentials: Authorization, Cookie, API-key/token headers and every header another level uses for its identity are stripped. Content-Length is corrected for every level. Each response reports headers_set / headers_removed / credential_headers_kept so you can check what was sent.

Analyzes status codes, body content, body length, and headers for differences. Flags critical findings like identical responses across auth levels — except when the target looks like a static asset (content-type or file extension: CSS/JS/image/font), where identical-across-levels is expected and the finding is downgraded to informational instead. Levels that are all refused alike (same 401/403/404/5xx, a redirect to a login page, or a 200 that only carries a login page or a denial message) are informational, never high or critical. A level that times out is listed under errors and not compared.""",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request string") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") {
                        put("type", "integer"); put("minimum", 1); put("maximum", 65535)
                        put("description", "Target port number (default 443)")
                    }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Whether to use HTTPS (TLS) (default: port==443)") }
                    putJsonObject("auth_levels") {
                        put("type", "array"); putJsonObject("items") { put("type", "object") }
                        put("description", "At least 2 auth level objects: {name, header_name?, header_value?, headers?, remove_headers?}; name none/unauth/anonymous sends no credentials")
                    }
                    putJsonObject("compare_fields") {
                        put("type", "array")
                        putJsonObject("items") {
                            put("type", "string")
                            putJsonArray("enum") { AnalysisBridge.AUTH_DIFF_FIELDS.forEach { add(it) } }
                        }
                        put("description", "Optional list of response fields to compare (default: all)")
                    }
                    putJsonObject("denied_regex") {
                        put("type", "string")
                        put("description", "Optional regex (case-insensitive): a response whose body matches is treated as denied whatever its status. For applications that refuse with a 200 the built-in login-page / denial-message detection does not recognise")
                    }
                },
                required = listOf("request", "host", "auth_levels")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val reqStr = (args["request"] as? JsonPrimitive)?.contentOrNull
                    ?: return@addTool toolError("Parameter 'request' is required")
                val host = (args["host"] as? JsonPrimitive)?.contentOrNull
                    ?: return@addTool toolError("Parameter 'host' is required")
                val port = args["port"].asBoundedInt("port", 1, 65535)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid port") } ?: 443
                val useTls = args["use_tls"].asBooleanSafe() ?: args["tls"].asBooleanSafe() ?: (port == 443)
                val authLevels = args["auth_levels"].asJsonObjectList()
                    ?: return@addTool toolError("Parameter 'auth_levels' is required (array of auth level objects)")
                val compareFields = args["compare_fields"].asStringList()
                val deniedRegex = (args["denied_regex"] as? JsonPrimitive)?.contentOrNull?.takeIf { it.isNotEmpty() }

                toolJsonResult(analysis.authDiff(reqStr, host, port, useTls, authLevels, compareFields, deniedRegex))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
