package io.bitbytelab.raijin.tools.jwt

import io.bitbytelab.raijin.bridge.JwtBridge
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.core.asBoundedInt
import io.bitbytelab.raijin.core.asJsonObjectSafe
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.jwt.JwtJose
import io.bitbytelab.raijin.jwt.JwtKeyRing
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers `jwt_attack` (probe action `jwt`) and the `jwt_keys` key ring.
 * Decode-only inspection stays on `util_jwt_decode`.
 */
object JwtTools {

    /** Every `alg` either tool takes: JWS algorithms for the signing modes, JWE key management ones for encrypt. */
    private val ALGS = JwtJose.JWS_ALGS + JwtJose.JWE_ALGS

    fun register(server: Server, bridge: JwtBridge) {
        server.addTool(
            name = "jwt_attack",
            description = "Run or inspect a JSON Web Token. Modes: " +
                "analyze (flag alg:none, HMAC, asymmetric alg, kid/jku, missing or malformed exp, repeated claims); " +
                "forge_none (unsigned tokens, case variants); " +
                "alg_confusion (RS->HS — pass public_key as PEM or JWK JSON, or key_id); " +
                "crack (HMAC secret from wordlist or the built-in list); " +
                "sign (HMAC secret); " +
                "sign_key (key_id from jwt_keys; sets alg and kid, keeps the rest of the header); " +
                "verify (one key_id, or every key; says why a key does not verify); " +
                "encrypt / decrypt (key_id, alg, enc); " +
                "embed_jwk (sign and embed the public key); " +
                "empty_hmac; psychic (ES256|ES384|ES512); " +
                "header_url (header=jku|x5u, url; with key_id the token is signed with that key and the result " +
                "holds host.body, the JWK set or PEM certificate chain to serve at url). " +
                "Signing modes keep the payload byte for byte, whatever it holds, unless payload_overrides names claims. " +
                "Create keys with jwt_keys.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("token") { put("type", "string"); put("description", "The JWT or plaintext to operate on. encrypt takes the plaintext in token.") }
                    putJsonObject("mode") {
                        put("type", "string")
                        putJsonArray("enum") { JwtBridge.MODES.forEach { add(it) } }
                        put("description", "JWT operation (default analyze)")
                    }
                    putJsonObject("secret") { put("type", "string"); put("description", "HMAC secret for mode=sign") }
                    putJsonObject("public_key") { put("type", "string"); put("description", "Server public key for mode=alg_confusion: PEM text, or JWK/JWK-set JSON (converted to PEM automatically). Alternatively pass key_id for a ring key.") }
                    putJsonObject("wordlist") { put("type", "array"); putJsonObject("items") { put("type", "string") }; put("description", "Candidate secrets for mode=crack") }
                    putJsonObject("alg") {
                        put("type", "string")
                        putJsonArray("enum") { ALGS.forEach { add(it) } }
                        put("description", "JWS alg for the signing modes, JWE key management alg for encrypt. Defaults from the key, else HS256 / RSA-OAEP-256")
                    }
                    putJsonObject("enc") {
                        put("type", "string")
                        putJsonArray("enum") { JwtJose.JWE_ENCS.forEach { add(it) } }
                        put("description", "JWE content encryption method for encrypt (default A256GCM)")
                    }
                    putJsonObject("key_id") { put("type", "string"); put("description", "Key ring id from jwt_keys") }
                    putJsonObject("header") {
                        put("type", "string")
                        putJsonArray("enum") { JwtBridge.URL_HEADERS.forEach { add(it) } }
                        put("description", "Header that mode=header_url writes (default jku)")
                    }
                    putJsonObject("url") { put("type", "string"); put("description", "URL written into the header for mode=header_url") }
                    putJsonObject("payload_overrides") { put("type", "object"); put("description", "Claims to override when forging or signing, e.g. {\"sub\":\"admin\"}. Written into the payload in place; every copy of a repeated claim gets the value. Needs a JSON object payload") }
                },
                required = listOf("token")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val token = args.string("token")
                    ?: return@addTool toolError("Parameter 'token' is required")
                val mode = args.text("mode")?.lowercase() ?: "analyze"
                EnumValidation.error(mode, JwtBridge.MODES.toSet(), "mode")?.let { return@addTool toolJsonResult(it) }
                val alg = args.text("alg")
                EnumValidation.error(alg, ALGS.toSet(), "alg")?.let { return@addTool toolJsonResult(it) }
                val enc = args.text("enc")
                EnumValidation.error(enc, JwtJose.JWE_ENCS.toSet(), "enc")?.let { return@addTool toolJsonResult(it) }
                val header = args.text("header")
                EnumValidation.error(header, JwtBridge.URL_HEADERS.toSet(), "header")?.let { return@addTool toolJsonResult(it) }
                val overrides = args["payload_overrides"]
                    ?.takeUnless { it is JsonNull || (it is JsonPrimitive && it.content.isBlank()) }
                    ?.let {
                        it.asJsonObjectSafe()
                            ?: return@addTool toolError("Parameter 'payload_overrides' must be a JSON object such as {\"sub\":\"admin\"}")
                    }

                toolJsonResult(
                    bridge.attack(
                        token = token,
                        mode = mode,
                        secret = args.string("secret"),
                        // Kept byte for byte: the PEM text is the HMAC secret, trailing newline included.
                        publicKey = args.string("public_key")?.takeIf { it.isNotBlank() },
                        wordlist = args["wordlist"].asStringList(),
                        overrides = overrides,
                        alg = alg,
                        // An id is matched as written (an imported kid may carry spaces); only blank means "none".
                        keyId = args.string("key_id")?.takeIf { it.isNotBlank() },
                        enc = enc,
                        header = header,
                        url = args.string("url"),
                    )
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "jwt_keys",
            description = "JWK key ring for probe jwt. Actions: " +
                "generate (kty=RSA|EC|OKP|oct|password, size or crv); " +
                "import (pem, jwk, or password); " +
                "list (no private material); " +
                "export (format=jwk|pem, include_private defaults to false); " +
                "delete. " +
                "Every key lists the probe jwt modes it can serve (an X25519 or X448 key encrypts and decrypts, it does not sign).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("action") {
                        put("type", "string")
                        putJsonArray("enum") { JwtBridge.KEY_ACTIONS.forEach { add(it) } }
                        put("description", "Key ring operation")
                    }
                    putJsonObject("kty") {
                        put("type", "string")
                        putJsonArray("enum") { JwtKeyRing.KTYS.forEach { add(it) } }
                        put("description", "Key type for action=generate")
                    }
                    putJsonObject("size") {
                        put("type", "integer"); put("minimum", JwtKeyRing.MIN_SIZE_BITS); put("maximum", JwtKeyRing.MAX_SIZE_BITS)
                        put("description", "RSA bits (default 2048, at least 512) or oct bits (default 256), a multiple of 8")
                    }
                    putJsonObject("crv") {
                        put("type", "string")
                        putJsonArray("enum") { JwtKeyRing.CURVES.forEach { add(it) } }
                        put("description", "EC: P-256, P-384, P-521, secp256k1. OKP: Ed25519, Ed448 (sign), X25519, X448 (encrypt)")
                    }
                    putJsonObject("alg") {
                        put("type", "string")
                        putJsonArray("enum") { ALGS.forEach { add(it) } }
                        put("description", "Optional algorithm to store on the key")
                    }
                    putJsonObject("key_id") { put("type", "string"); put("description", "Id to assign, export, or delete") }
                    putJsonObject("pem") { put("type", "string"); put("description", "PEM text for action=import") }
                    putJsonObject("jwk") { put("type", "string"); put("description", "JWK or JWK set JSON for action=import") }
                    putJsonObject("password") { put("type", "string"); put("description", "Password for a PBES key import") }
                    putJsonObject("format") {
                        put("type", "string")
                        putJsonArray("enum") { JwtBridge.EXPORT_FORMATS.forEach { add(it) } }
                        put("description", "Export format (default jwk)")
                    }
                    putJsonObject("include_private") { put("type", "boolean"); put("description", "When true, export includes private key bytes") }
                },
                required = listOf("action")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val action = args.text("action")?.lowercase()
                EnumValidation.error(action, JwtBridge.KEY_ACTIONS.toSet(), "action", required = true)
                    ?.let { return@addTool toolJsonResult(it) }
                val kty = args.text("kty")
                EnumValidation.error(kty, JwtKeyRing.KTYS.toSet(), "kty")?.let { return@addTool toolJsonResult(it) }
                val alg = args.text("alg")
                EnumValidation.error(alg, ALGS.toSet(), "alg")?.let { return@addTool toolJsonResult(it) }
                val format = args.text("format")
                EnumValidation.error(format, JwtBridge.EXPORT_FORMATS.toSet(), "format")?.let { return@addTool toolJsonResult(it) }
                val size = args["size"].asBoundedInt("size", JwtKeyRing.MIN_SIZE_BITS, JwtKeyRing.MAX_SIZE_BITS)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid size") }
                val jwk = when (val raw = args["jwk"]) {
                    is JsonObject -> raw.toString()
                    is JsonPrimitive -> raw.contentOrNull
                    else -> null
                }

                toolJsonResult(
                    bridge.keys(
                        action = action.orEmpty(),
                        kty = kty,
                        size = size,
                        // The ring owns the curve names: it also takes spellings such as secp256r1.
                        crv = args.text("crv"),
                        alg = alg,
                        keyId = args.string("key_id")?.takeIf { it.isNotBlank() },
                        pem = args.string("pem"),
                        jwk = jwk,
                        password = args.string("password"),
                        format = format,
                        includePrivate = args["include_private"].asBooleanSafe() ?: false,
                    )
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    private fun Map<String, JsonElement>.string(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull

    /** A string argument trimmed, or null when it is absent or blank: a client that sends `""` for "not set" means not set. */
    private fun Map<String, JsonElement>.text(name: String): String? = string(name)?.trim()?.takeIf { it.isNotEmpty() }
}
