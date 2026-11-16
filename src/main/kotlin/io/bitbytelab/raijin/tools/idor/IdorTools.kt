package io.bitbytelab.raijin.tools.idor

import io.bitbytelab.raijin.bridge.IdorHuntBridge
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asBoundedInt
import io.bitbytelab.raijin.core.asClampedInt
import io.bitbytelab.raijin.core.asJsonObjectList
import io.bitbytelab.raijin.core.withClampReport
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/** Registers the `idor_hunt` MCP tool — horizontal object-id IDOR with canary confirmation. */
object IdorTools {

    private val ID_LOCATIONS = listOf("path", "query", "header", "cookie", "body-json", "body-form")

    fun register(server: Server, bridge: IdorHuntBridge) {
        server.addTool(
            name = "idor_hunt",
            description = "Horizontal-IDOR / BOLA hunter with CANARY confirmation — the object-id-swap that auth_diff/access_control_sweep do not do. " +
                "Give a raw request that identity A makes to A's own object, plus 'identities' where each low-priv account declares its own 'object_id' " +
                "(a resource it owns) and 'canary' (a string that appears only in its own data). For every (reader, owner) pair the tool swaps the object " +
                "id to the owner's resource, replays under the reader's auth, and asserts the owner's canary appears in the reader's response — a CONFIRMED " +
                "cross-user read — while filtering the own-data-reflection false positive. It also runs the identity-diff (vertical/unauth) with the id held " +
                "constant, and can enumerate the id-transformation set (encodings, neighbours, type-juggling); a transformed id is only reported when the " +
                "response is not the reader's own view or a not-found answer, and confirmed when another identity's canary appears in it. " +
                "The id is swapped at its parameter boundary only (one path segment, one query/form/cookie/header value, one JSON value), so /v1/users/1 " +
                "never becomes /v2/users/2, and Content-Length is corrected. Auto-detects the object id in path/query/body/header/cookie (preferring an " +
                "identity's own object_id when the request holds it), or pin it with id_value/id_location/id_name. Scope-gated (mcp_scope_mode) and bounded.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request A makes to A's own object") }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") {
                        put("type", "integer"); put("minimum", 1); put("maximum", 65535)
                        put("description", "Target port (default 443)")
                    }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Use HTTPS (default: port==443)") }
                    putJsonObject("identities") {
                        put("type", "array"); putJsonObject("items") { put("type", "object") }
                        put("description", "At least 2: [{name, header_name?, header_value?, headers?, remove_headers?, object_id?, canary?}]; an identity's headers replace the request's own, name none/unauth/anonymous strips every credential header. object_id = a resource that identity owns; canary = a token only in that identity's own data (enables confirmed-grade verdicts). The first identity is the primary one (it replays the id transformations).")
                    }
                    putJsonObject("id_value") { put("type", "string"); put("description", "Optional: the object-id value in 'request' to swap (else auto-detected). It must stand alone as a path segment, a parameter/cookie/header value or a JSON value, or begin a path segment before a character that is not a letter or digit (42 in /users/42-alice)") }
                    putJsonObject("id_location") {
                        put("type", "string")
                        putJsonArray("enum") { ID_LOCATIONS.forEach { add(it) } }
                        put("description", "Optional: where the id is")
                    }
                    putJsonObject("id_name") { put("type", "string"); put("description", "Optional: which parameter holds the id when the value alone is ambiguous — a query/form/cookie/header name, a JSON path or key (user.id), or the 0-based index of a path segment") }
                    putJsonObject("transforms") { put("type", "boolean"); put("description", "Also replay the id-transformation set (encodings/neighbours/type-juggle) under the primary identity (default false)") }
                    putJsonObject("enumerate") {
                        put("type", "integer"); put("minimum", 0); put("maximum", IdorHuntBridge.MAX_TRANSFORMS)
                        put("description", "Optional neighbour/transform replay count (0=off); a larger value is clamped to ${IdorHuntBridge.MAX_TRANSFORMS} and reported as enumerate_clamped_to")
                    }
                },
                required = listOf("request", "host", "identities")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val req = args.string("request")
                    ?: return@addTool toolError("Parameter 'request' (raw HTTP request string) is required")
                val host = args.string("host")
                    ?: return@addTool toolError("Parameter 'host' is required")
                val port = args["port"].asBoundedInt("port", 1, 65535)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid port") } ?: 443
                val useTls = args["use_tls"].asBooleanSafe() ?: args["tls"].asBooleanSafe() ?: (port == 443)
                val identities = args["identities"].asJsonObjectList()
                    ?: return@addTool toolError("Parameter 'identities' (array of >=2 identity objects) is required")
                val idValue = args.string("id_value")?.takeIf { it.isNotEmpty() }
                val idLocation = args.string("id_location")?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
                EnumValidation.error(idLocation, ID_LOCATIONS.toSet(), "id_location")?.let { return@addTool toolJsonResult(it) }
                val idName = args.string("id_name")?.takeIf { it.isNotEmpty() }
                val transforms = args["transforms"].asBooleanSafe() ?: false
                val enumerate = args["enumerate"].asClampedInt("enumerate", 0, IdorHuntBridge.MAX_TRANSFORMS)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid enumerate") }

                toolJsonResult(
                    bridge.hunt(req, host, port, useTls, identities, idLocation, idValue, transforms, enumerate?.value ?: 0, idName)
                        .withClampReport("enumerate", enumerate)
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    private fun Map<String, JsonElement>.string(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull
}
