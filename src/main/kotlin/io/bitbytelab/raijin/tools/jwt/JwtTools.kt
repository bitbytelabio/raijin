package io.bitbytelab.raijin.tools.jwt

import io.bitbytelab.raijin.bridge.JwtBridge
import io.bitbytelab.raijin.core.asStringList
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers `jwt_attack` (probe action `jwt`) and the `jwt_keys` key ring.
 * Decode-only inspection stays on `util_jwt_decode`.
 */
object JwtTools {
    fun register(server: Server, bridge: JwtBridge) {
        server.addTool(
            name = "jwt_attack",
            description = "Run or inspect a JSON Web Token. Modes: " +
                "analyze (flag alg:none, HMAC, asymmetric alg, kid/jku, missing exp); " +
                "forge_none (unsigned tokens, case variants); " +
                "alg_confusion (RS->HS — pass public_key as PEM or JWK JSON, or key_id); " +
                "crack (HMAC secret from wordlist or the built-in list); " +
                "sign (HMAC secret); " +
                "sign_key (key_id from jwt_keys); " +
                "verify (one key_id, or every key); " +
                "encrypt / decrypt (key_id, alg, enc); " +
                "embed_jwk (sign and embed the public key); " +
                "empty_hmac; psychic (ES256|ES384|ES512); " +
                "header_url (header=jku|x5u, url). " +
                "Create keys with jwt_keys.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("token") { put("type", "string"); put("description", "The JWT or plaintext to operate on. encrypt takes the plaintext in token.") }
                    putJsonObject("mode") {
                        put("type", "string")
                        put(
                            "description",
                            "analyze|forge_none|alg_confusion|crack|sign|sign_key|verify|encrypt|decrypt|embed_jwk|empty_hmac|psychic|header_url (default: analyze)"
                        )
                    }
                    putJsonObject("secret") { put("type", "string"); put("description", "HMAC secret for mode=sign") }
                    putJsonObject("public_key") { put("type", "string"); put("description", "Server public key for mode=alg_confusion: PEM text, or JWK/JWK-set JSON (converted to PEM automatically). Alternatively pass key_id for a ring key.") }
                    putJsonObject("wordlist") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Candidate secrets for mode=crack") }
                    putJsonObject("alg") { put("type", "string"); put("description", "JWS or JWE alg. Defaults from the key or HS256 / RSA-OAEP-256") }
                    putJsonObject("enc") { put("type", "string"); put("description", "JWE content encryption method for encrypt (default A256GCM)") }
                    putJsonObject("key_id") { put("type", "string"); put("description", "Key ring id from jwt_keys") }
                    putJsonObject("header") { put("type", "string"); put("description", "jku or x5u for mode=header_url (default jku)") }
                    putJsonObject("url") { put("type", "string"); put("description", "URL written into the header for mode=header_url") }
                    putJsonObject("payload_overrides") { put("type", "object"); put("description", "Claims to override when forging or signing, e.g. {\"sub\":\"admin\"}") }
                },
                required = listOf("token")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val token = args["token"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Parameter 'token' is required"}""")),
                        isError = true
                    )
                val mode = args["mode"]?.jsonPrimitive?.contentOrNull ?: "analyze"
                val secret = args["secret"]?.jsonPrimitive?.contentOrNull
                val publicKey = args["public_key"]?.jsonPrimitive?.contentOrNull
                val wordlist = args["wordlist"].asStringList()
                val alg = args["alg"]?.jsonPrimitive?.contentOrNull
                val enc = args["enc"]?.jsonPrimitive?.contentOrNull
                val keyId = args["key_id"]?.jsonPrimitive?.contentOrNull
                val header = args["header"]?.jsonPrimitive?.contentOrNull
                val url = args["url"]?.jsonPrimitive?.contentOrNull
                val overrides = args["payload_overrides"] as? JsonObject

                val result = bridge.attack(
                    token, mode, secret, publicKey, wordlist, overrides, alg, keyId, enc, header, url
                )
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject { put("error", e.message ?: "Unknown error") }.toString())),
                    isError = true
                )
            }
        }

        server.addTool(
            name = "jwt_keys",
            description = "JWK key ring for probe jwt. Actions: " +
                "generate (kty=RSA|EC|OKP|oct|password, size or crv); " +
                "import (pem, jwk, or password); " +
                "list (no private material); " +
                "export (format=jwk|pem, include_private defaults to false); " +
                "delete.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("action") { put("type", "string"); put("description", "generate|import|list|export|delete") }
                    putJsonObject("kty") { put("type", "string"); put("description", "RSA, EC, OKP, oct, or password") }
                    putJsonObject("size") { put("type", "integer"); put("description", "RSA bits (default 2048) or oct bits (default 256)") }
                    putJsonObject("crv") { put("type", "string"); put("description", "EC: P-256, P-384, P-521, secp256k1. OKP: Ed25519, Ed448, X25519, X448") }
                    putJsonObject("alg") { put("type", "string"); put("description", "Optional algorithm to store on the key") }
                    putJsonObject("key_id") { put("type", "string"); put("description", "Id to assign, export, or delete") }
                    putJsonObject("pem") { put("type", "string"); put("description", "PEM text for action=import") }
                    putJsonObject("jwk") { put("type", "string"); put("description", "JWK or JWK set JSON for action=import") }
                    putJsonObject("password") { put("type", "string"); put("description", "Password for a PBES key import") }
                    putJsonObject("format") { put("type", "string"); put("description", "jwk (default) or pem") }
                    putJsonObject("include_private") { put("type", "boolean"); put("description", "When true, export includes private key bytes") }
                },
                required = listOf("action")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val action = args["action"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent("""{"error":"Parameter 'action' is required"}""")),
                        isError = true
                    )
                val includePrivate = args["include_private"]?.jsonPrimitive?.booleanOrNull
                    ?: (args["include_private"]?.jsonPrimitive?.contentOrNull == "true")
                val jwk = when (val raw = args["jwk"]) {
                    is JsonObject -> raw.toString()
                    is JsonPrimitive -> raw.contentOrNull
                    else -> null
                }
                val result = bridge.keys(
                    action = action,
                    kty = args["kty"]?.jsonPrimitive?.contentOrNull,
                    size = args["size"]?.jsonPrimitive?.intOrNull,
                    crv = args["crv"]?.jsonPrimitive?.contentOrNull,
                    alg = args["alg"]?.jsonPrimitive?.contentOrNull,
                    keyId = args["key_id"]?.jsonPrimitive?.contentOrNull,
                    pem = args["pem"]?.jsonPrimitive?.contentOrNull,
                    jwk = jwk,
                    password = args["password"]?.jsonPrimitive?.contentOrNull,
                    format = args["format"]?.jsonPrimitive?.contentOrNull,
                    includePrivate = includePrivate,
                )
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(
                    content = listOf(TextContent(buildJsonObject { put("error", e.message ?: "Unknown error") }.toString())),
                    isError = true
                )
            }
        }
    }
}
