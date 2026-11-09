package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.jwt.Jwt
import io.bitbytelab.raijin.jwt.JwtJose
import io.bitbytelab.raijin.jwt.JwtKey
import io.bitbytelab.raijin.jwt.JwtKeyRing
import io.bitbytelab.raijin.jwt.jwkTextToPem
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * MCP-facing wrapper over [Jwt] and the JWK ring. No Montoya types.
 * [load] and [save] persist the ring (extension data). Both are null in unit tests.
 */
class JwtBridge(
    private val load: (() -> String?)? = null,
    private val save: ((String) -> Unit)? = null,
) {
    private val ring = JwtKeyRing()

    init {
        try {
            load?.invoke()?.takeIf { it.isNotBlank() }?.let { ring.restore(it) }
        } catch (_: Exception) {
            // A corrupt ring must not stop the extension from loading.
        }
    }

    /**
     * Runs a JWT [mode] against [token]:
     *  - `analyze`        — decode + flag alg family, kid/jku, exp.
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
     *  - `header_url`     — set `jku` or `x5u` to [url].
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
            when (mode.lowercase()) {
                "analyze" -> {
                    val p = Jwt.decode(token) ?: return err("Not a decodable JWT")
                    buildJsonObject {
                        put("header", p.header)
                        put("payload", p.payload)
                        put("alg", p.alg)
                        put("issues", buildJsonArray {
                            Jwt.analyze(token).forEach {
                                add(buildJsonObject {
                                    put("id", it.id); put("severity", it.severity); put("detail", it.detail)
                                })
                            }
                        })
                    }
                }
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
                    val forged = Jwt.resign(token, key, alg ?: "HS256", overrides) ?: return err("Could not forge token")
                    buildJsonObject {
                        put("token", forged)
                        put("note", "RS->HS confusion: signed with the public key as the HMAC secret. Works when the server uses one verify() across alg families.")
                    }
                }
                "crack" -> {
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
                    val signed = Jwt.resign(token, s, alg ?: "HS256", overrides) ?: return err("Could not sign (bad token or alg)")
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
                "psychic" -> buildJsonObject { put("token", JwtJose.psychic(token, alg, overrides)) }
                "header_url" -> {
                    val target = url ?: return err("header_url requires url")
                    buildJsonObject { put("token", JwtJose.headerUrl(token, header, target, overrides)) }
                }
                else -> err(
                    "Unknown mode '$mode'. Use: analyze | forge_none | alg_confusion | crack | sign | " +
                        "sign_key | verify | encrypt | decrypt | embed_jwk | empty_hmac | psychic | header_url."
                )
            }
        } catch (e: Exception) {
            err("JWT operation failed: ${e.message}")
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
            when (action.lowercase()) {
                "generate" -> {
                    val kind = kty ?: return err("generate requires kty")
                    val key = ring.generate(kind, size, crv, alg, keyId)
                    persist()
                    buildJsonObject {
                        put("key_id", key.id)
                        put("kty", key.kty)
                        key.alg?.let { put("alg", it) }
                        key.crv?.let { put("crv", it) }
                        key.publicJwk()?.let { put("public_jwk", it) }
                    }
                }
                "import" -> {
                    val imported = ring.import(pem, jwk, password)
                    persist()
                    buildJsonObject {
                        put("imported", buildJsonArray { imported.forEach { add(it.summary()) } })
                    }
                }
                "list" -> buildJsonObject {
                    put("keys", buildJsonArray { ring.list().forEach { add(it.summary()) } })
                }
                "export" -> {
                    val id = keyId ?: return err("export requires key_id")
                    val key = ring.get(id)
                    val fmt = (format ?: "jwk").lowercase()
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
                    if (deleted) persist()
                    buildJsonObject {
                        put("key_id", id)
                        put("deleted", deleted)
                    }
                }
                else -> err("Unknown action '$action'. Use: generate | import | list | export | delete.")
            }
        } catch (e: Exception) {
            err(e.message ?: "Key operation failed")
        }
    }

    private fun verify(token: String, keyId: String?): JsonObject {
        val selected = if (keyId != null) {
            listOf(ring.get(keyId))
        } else {
            ring.list()
        }
        val joseKeys = selected.filterIsInstance<JwtKey.Jose>()
        if (joseKeys.isEmpty()) return err(if (keyId != null) "Unknown or non-JWK key_id '$keyId'" else "No keys to verify with")
        val rows = joseKeys.map { key ->
            val valid = try {
                JwtJose.verify(token, key.jwk)
            } catch (_: Exception) {
                false
            }
            key to valid
        }
        return buildJsonObject {
            put("valid", rows.any { it.second })
            put("matches", buildJsonArray {
                rows.forEach { (key, valid) ->
                    add(buildJsonObject {
                        put("key_id", key.id)
                        put("valid", valid)
                    })
                }
            })
        }
    }

    private fun joseKey(id: String): JwtKey.Jose = when (val key = ring.get(id)) {
        is JwtKey.Jose -> key
        is JwtKey.Password -> throw IllegalArgumentException("Key '$id' is a password and cannot sign")
    }

    private fun persist() {
        val store = save ?: return
        store(ring.snapshot())
    }

    private fun err(msg: String): JsonObject = buildJsonObject { put("error", msg) }

    companion object {
        const val PERSIST_KEY = "raijin.jwt.keys"

        /** Small built-in wordlist for quick HS-secret cracking when none is supplied. */
        val DEFAULT_SECRETS = listOf(
            "secret", "password", "123456", "admin", "changeme", "your-256-bit-secret", "jwt", "token",
            "key", "secretkey", "supersecret", "test", "qwerty", "letmein", "private", "jwtsecret",
            "my-secret", "s3cr3t", "default", "root"
        )
    }
}
