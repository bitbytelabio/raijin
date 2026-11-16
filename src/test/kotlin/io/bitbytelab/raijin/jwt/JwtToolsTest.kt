package io.bitbytelab.raijin.jwt

import io.bitbytelab.raijin.bridge.JwtBridge
import io.bitbytelab.raijin.testClientConnection
import io.bitbytelab.raijin.tools.jwt.JwtTools
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The tool layer of `jwt_attack` and `jwt_keys`: closed parameters carry an enum, and every failure
 * comes back as valid JSON with `isError` set.
 */
class JwtToolsTest {
    private val token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    private val server = Server(
        Implementation("t", "0"),
        ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
    ).also { JwtTools.register(it, JwtBridge()) }

    private fun call(tool: String, args: JsonObject): CallToolResult = runBlocking {
        server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, args)))
    }

    private fun json(result: CallToolResult): JsonObject =
        Json.parseToJsonElement((result.content.first() as TextContent).text).jsonObject

    private fun enumOf(tool: String, parameter: String): List<String> =
        server.tools.getValue(tool).tool.inputSchema.properties!!.getValue(parameter).jsonObject
            .getValue("enum").jsonArray.map { it.jsonPrimitive.content }

    private fun JsonObject.text(name: String): String = getValue(name).jsonPrimitive.content

    @Test
    fun `closed parameters list their values in the schema`() {
        assertEquals(
            listOf(
                "analyze", "forge_none", "alg_confusion", "crack", "sign", "sign_key", "verify",
                "encrypt", "decrypt", "embed_jwk", "empty_hmac", "psychic", "header_url",
            ),
            enumOf("jwt_attack", "mode")
        )
        val algs = enumOf("jwt_attack", "alg")
        assertEquals(JwtJose.JWS_ALGS + JwtJose.JWE_ALGS, algs)
        for (alg in listOf("HS256", "RS256", "PS512", "ES256K", "EdDSA", "RSA-OAEP-256", "ECDH-ES+A256KW", "dir", "PBES2-HS256+A128KW")) {
            assertTrue(alg in algs, alg)
        }
        assertEquals(JwtJose.JWE_ENCS, enumOf("jwt_attack", "enc"))
        assertEquals(listOf("jku", "x5u"), enumOf("jwt_attack", "header"))

        assertEquals(listOf("generate", "import", "list", "export", "delete"), enumOf("jwt_keys", "action"))
        assertEquals(listOf("RSA", "EC", "OKP", "oct", "password"), enumOf("jwt_keys", "kty"))
        assertEquals(listOf("P-256", "P-384", "P-521", "secp256k1", "Ed25519", "Ed448", "X25519", "X448"), enumOf("jwt_keys", "crv"))
        assertEquals(algs, enumOf("jwt_keys", "alg"))
        assertEquals(listOf("jwk", "pem"), enumOf("jwt_keys", "format"))

        // jwt_attack is dispatched as probe(action=jwt): it must not declare a parameter called action itself.
        assertFalse("action" in server.tools.getValue("jwt_attack").tool.inputSchema.properties!!.keys)
    }

    @Test
    fun `every mode in the schema is one the bridge runs`() {
        val bridge = JwtBridge()
        for (mode in enumOf("jwt_attack", "mode")) {
            val result = bridge.attack(token, mode, null, null, null, null, null)
            assertFalse(result["error"]?.jsonPrimitive?.content.orEmpty().startsWith("Unknown mode"), mode)
        }
        for (action in enumOf("jwt_keys", "action")) {
            val result = bridge.keys(action = action)
            assertFalse(result["error"]?.jsonPrimitive?.content.orEmpty().startsWith("Unknown action"), action)
        }
    }

    @Test
    fun `every failure is valid JSON flagged isError`() {
        fun args(build: JsonObjectBuilder.() -> Unit): JsonObject = buildJsonObject(build)
        val failures = listOf(
            Triple("jwt_attack", args { }, "'token' is required"),
            Triple("jwt_attack", args { put("token", token); put("mode", "bogus") }, "'mode'"),
            Triple("jwt_attack", args { put("token", token); put("mode", "sign"); put("secret", "s"); put("alg", "HS999") }, "'alg'"),
            Triple("jwt_attack", args { put("token", token); put("mode", "encrypt"); put("enc", "A1") }, "'enc'"),
            Triple("jwt_attack", args { put("token", token); put("mode", "header_url"); put("header", "kid"); put("url", "https://a.example/") }, "'header'"),
            Triple("jwt_attack", args { put("token", "not a jwt") }, "Not a decodable JWT"),
            Triple("jwt_attack", args { put("token", token); put("mode", "sign") }, "requires 'secret'"),
            Triple("jwt_attack", args { put("token", token); put("mode", "sign"); put("secret", "s"); put("alg", "RS256") }, "HS256, HS384 or HS512"),
            Triple("jwt_attack", args { put("token", token); put("mode", "sign_key"); put("key_id", "missing") }, "Unknown key_id"),
            Triple("jwt_attack", args { put("token", token); put("mode", "header_url") }, "requires url"),
            Triple("jwt_attack", args { put("token", token); put("mode", "sign"); put("secret", "s"); put("payload_overrides", "[1]") }, "payload_overrides"),
            Triple("jwt_attack", args { put("token", token); put("mode", "sign"); put("secret", "s"); put("payload_overrides", 5) }, "payload_overrides"),
            Triple("jwt_attack", args { put("token", "say \"hi\"\n\\"); put("mode", "decrypt"); put("key_id", "missing") }, "Unknown key_id"),
            Triple("jwt_keys", args { }, "'action' is required"),
            Triple("jwt_keys", args { put("action", "bogus") }, "'action'"),
            Triple("jwt_keys", args { put("action", "generate") }, "requires kty"),
            Triple("jwt_keys", args { put("action", "generate"); put("kty", "DSA") }, "'kty'"),
            Triple("jwt_keys", args { put("action", "generate"); put("kty", "RSA"); put("size", 64) }, "'size'"),
            Triple("jwt_keys", args { put("action", "generate"); put("kty", "RSA"); put("size", "big") }, "'size'"),
            Triple("jwt_keys", args { put("action", "generate"); put("kty", "RSA"); put("size", 1001) }, "multiple of 8"),
            Triple("jwt_keys", args { put("action", "generate"); put("kty", "EC"); put("crv", "P-999") }, "Unknown curve"),
            Triple("jwt_keys", args { put("action", "generate"); put("kty", "oct"); put("alg", "ROT13") }, "'alg'"),
            Triple("jwt_keys", args { put("action", "export"); put("key_id", "nope") }, "Unknown key_id"),
            Triple("jwt_keys", args { put("action", "export"); put("key_id", "nope"); put("format", "der") }, "'format'"),
            Triple("jwt_keys", args { put("action", "import") }, "import requires"),
            Triple("jwt_keys", args { put("action", "import"); put("jwk", "{\"kty\":\"nope\"}") }, ""),
            Triple("jwt_keys", args { put("action", "delete") }, "requires key_id"),
        )
        for ((tool, arguments, expected) in failures) {
            val result = call(tool, arguments)
            assertEquals(true, result.isError, "$tool $arguments")
            val error = json(result).text("error")
            assertTrue(error.isNotBlank() && expected in error, "$tool $arguments -> $error")
        }
    }

    @Test
    fun `results that are not failures are not flagged`() {
        val analyzed = call("jwt_attack", buildJsonObject { put("token", token) })
        assertNotEquals(true, analyzed.isError)
        assertEquals("HS256", json(analyzed).text("alg"))

        // No match is an answer, not an error.
        val uncracked = call("jwt_attack", buildJsonObject { put("token", token); put("mode", "CRACK"); put("wordlist", "nope") })
        assertNotEquals(true, uncracked.isError)
        assertEquals("false", json(uncracked).text("cracked"))

        val generated = call("jwt_keys", buildJsonObject { put("action", "generate"); put("kty", "ec"); put("crv", "secp256r1"); put("key_id", "k") })
        assertNotEquals(true, generated.isError, json(generated).toString())
        assertEquals("P-256", json(generated).text("crv"))
        assertNotEquals(true, call("jwt_keys", buildJsonObject { put("action", "list") }).isError)

        val verified = call("jwt_attack", buildJsonObject { put("token", token); put("mode", "verify") })
        assertNotEquals(true, verified.isError)
        assertEquals("false", json(verified).text("valid"))
    }

    @Test
    fun `payload_overrides is taken as an object or as its JSON text`() {
        fun sign(overrides: JsonObject.() -> JsonObject): JsonObject {
            val base = buildJsonObject { put("token", token); put("mode", "sign"); put("secret", "s") }
            return json(call("jwt_attack", base.overrides()))
        }
        val asObject = sign { JsonObject(this + buildJsonObject { putJsonObject("payload_overrides") { put("sub", "admin") } }) }
        val asText = sign { JsonObject(this + buildJsonObject { put("payload_overrides", "{\"sub\":\"admin\"}") }) }
        val blank = sign { JsonObject(this + buildJsonObject { put("payload_overrides", "") }) }

        assertEquals("admin", Jwt.decode(asObject.text("token"))!!.payload.text("sub"))
        assertEquals(asObject.text("token"), asText.text("token"))
        assertEquals("1234567890", Jwt.decode(blank.text("token"))!!.payload.text("sub"))
    }

    @Test
    fun `one header_url call gives the signed token and the document to host`() {
        call("jwt_keys", buildJsonObject { put("action", "generate"); put("kty", "EC"); put("crv", "P-256"); put("key_id", "mine") })
        val result = call(
            "jwt_attack",
            buildJsonObject {
                put("token", token); put("mode", "header_url"); put("key_id", "mine")
                put("header", "JKU"); put("url", "https://exploit.example/jwks.json")
                putJsonObject("payload_overrides") { put("sub", "administrator") }
            }
        )
        assertNotEquals(true, result.isError, json(result).toString())
        val body = json(result)
        assertNull(body["error"])
        val signed = Jwt.split(body.text("token"))!!
        assertEquals("https://exploit.example/jwks.json", signed.header.text("jku"))
        assertEquals("mine", signed.header.text("kid"))
        assertEquals("administrator", signed.claims!!.text("sub"))
        val host = body.getValue("host").jsonObject
        val hosted = Json.parseToJsonElement(host.text("body")).jsonObject.getValue("keys").jsonArray.single().jsonObject
        assertEquals("mine", hosted.text("kid"))
        assertFalse("d" in hosted.keys)
    }
}
