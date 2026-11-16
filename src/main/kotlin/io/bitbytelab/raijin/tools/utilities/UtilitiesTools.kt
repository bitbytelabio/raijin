package io.bitbytelab.raijin.tools.utilities

import io.bitbytelab.raijin.bridge.UtilitiesBridge
import io.bitbytelab.raijin.core.asBoundedInt
import io.bitbytelab.raijin.core.asBooleanSafe
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

object UtilitiesTools {

    private val HASH_ALGORITHMS = listOf("MD5", "SHA_1", "SHA_256", "SHA_384", "SHA_512")
    private val COMPRESS_ALGORITHMS = listOf("GZIP", "DEFLATE")
    private val DECOMPRESS_ALGORITHMS = listOf("GZIP", "DEFLATE", "BROTLI")
    private const val MAX_RANDOM_LENGTH = 10_000
    private const val MAX_DECODE_DEPTH = 100

    fun register(server: Server, bridge: UtilitiesBridge) {

        // 1. util_url_encode
        server.addTool(
            name = "util_url_encode",
            description = "URL-encode a string. Parameters: data (required, the string " +
                "to encode), encode_all (optional boolean, default false. If true, " +
                "encodes all characters including unreserved ones).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    string("data", "The string to encode")
                    boolean("encode_all", "If true, encodes all characters including unreserved ones (default false)")
                },
                required = listOf("data")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val data = args["data"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: data")
                val encodeAll = args["encode_all"].asBooleanSafe() ?: false

                jsonKey("encoded", bridge.urlEncode(data, encodeAll))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 2. util_url_decode
        server.addTool(
            name = "util_url_decode",
            description = "URL-decode a string. Parameters: data (required, the " +
                "URL-encoded string to decode).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    string("data", "The URL-encoded string to decode")
                },
                required = listOf("data")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val data = args["data"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: data")

                jsonKey("decoded", bridge.urlDecode(data))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 3. util_base64_encode
        server.addTool(
            name = "util_base64_encode",
            description = "Base64-encode a string. Parameters: data (required, the " +
                "string to encode), url_safe (optional boolean, default false. If " +
                "true, uses URL-safe base64 encoding without padding).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    string("data", "The string to encode")
                    boolean("url_safe", "If true, uses URL-safe base64 encoding without padding (default false)")
                },
                required = listOf("data")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val data = args["data"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: data")
                val urlSafe = args["url_safe"].asBooleanSafe() ?: false

                jsonKey("encoded", bridge.base64Encode(data, urlSafe))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 4. util_base64_decode
        server.addTool(
            name = "util_base64_decode",
            description = "Base64-decode a string. Parameters: data (required, the " +
                "base64-encoded string to decode). Supports both standard and " +
                "URL-safe base64.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    string("data", "The base64-encoded string to decode")
                },
                required = listOf("data")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val data = args["data"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: data")

                jsonKey("decoded", bridge.base64Decode(data))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 5. util_html_encode
        server.addTool(
            name = "util_html_encode",
            description = "HTML-encode a string, escaping special characters like " +
                "<, >, &, \", and '. Parameters: data (required, the string to encode).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    string("data", "The string to encode")
                },
                required = listOf("data")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val data = args["data"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: data")

                jsonKey("encoded", bridge.htmlEncode(data))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 6. util_hash
        server.addTool(
            name = "util_hash",
            description = "Compute a cryptographic hash of a string. Parameters: " +
                "data (required, the string to hash), algorithm (required, one of: " +
                "MD5, SHA_1, SHA_256, SHA_384, SHA_512).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    string("data", "The string to hash")
                    enumString("algorithm", "Hash algorithm", HASH_ALGORITHMS)
                },
                required = listOf("data", "algorithm")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val data = args["data"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: data")
                val algorithm = args["algorithm"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: algorithm")

                toolJsonResult(bridge.hash(data, algorithm))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 7. util_compress
        server.addTool(
            name = "util_compress",
            description = "Compress data using the specified algorithm. Parameters: " +
                "data (required, base64-encoded input data), algorithm (required, " +
                "one of: GZIP, DEFLATE). Returns base64-encoded compressed data. " +
                "(BROTLI is not supported for compression by Burp; it is available " +
                "for util_decompress only.)",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    string("data", "Base64-encoded input data")
                    enumString("algorithm", "Compression algorithm", COMPRESS_ALGORITHMS)
                },
                required = listOf("data", "algorithm")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val data = args["data"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: data")
                val algorithm = args["algorithm"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: algorithm")

                toolJsonResult(bridge.compress(data, algorithm))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 8. util_decompress
        server.addTool(
            name = "util_decompress",
            description = "Decompress data using the specified algorithm. Parameters: " +
                "data (required, base64-encoded compressed data), algorithm (required, " +
                "one of: GZIP, DEFLATE, BROTLI). Returns base64-encoded decompressed " +
                "data and a text representation if valid UTF-8.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    string("data", "Base64-encoded compressed data")
                    enumString("algorithm", "Compression algorithm", DECOMPRESS_ALGORITHMS)
                },
                required = listOf("data", "algorithm")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val data = args["data"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: data")
                val algorithm = args["algorithm"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: algorithm")

                toolJsonResult(bridge.decompress(data, algorithm))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 9. util_random_string
        server.addTool(
            name = "util_random_string",
            description = "Generate a cryptographically random string. Parameters: " +
                "length (required, integer length of the string, 1-$MAX_RANDOM_LENGTH), charset (optional, " +
                "default 'alphanumeric'. Predefined sets: 'alphanumeric', 'alpha', " +
                "'numeric', 'hex', 'ascii'. Or provide a custom string of characters).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    integer("length", "Length of the string to generate", 1, MAX_RANDOM_LENGTH)
                    string("charset", "Predefined set (alphanumeric, alpha, numeric, hex, ascii) or custom characters; default alphanumeric")
                },
                required = listOf("length")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val length = args["length"].asBoundedInt("length", 1, MAX_RANDOM_LENGTH)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid length") }
                    ?: return@addTool toolError("Missing required parameter: length")
                val charset = args["charset"]?.jsonPrimitive?.contentOrNull ?: "alphanumeric"

                toolJsonResult(bridge.randomString(length, charset))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 10. util_random_bytes
        server.addTool(
            name = "util_random_bytes",
            description = "Generate cryptographically random bytes. Parameters: " +
                "length (required, integer number of bytes to generate, 1-$MAX_RANDOM_LENGTH). Returns " +
                "hex and base64 encoded representations.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    integer("length", "Number of bytes to generate", 1, MAX_RANDOM_LENGTH)
                },
                required = listOf("length")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val length = args["length"].asBoundedInt("length", 1, MAX_RANDOM_LENGTH)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid length") }
                    ?: return@addTool toolError("Missing required parameter: length")

                toolJsonResult(bridge.randomBytes(length))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 11. util_jwt_decode
        server.addTool(
            name = "util_jwt_decode",
            description = "Decode a JSON Web Token (JWT) and extract its header, " +
                "payload, and signature. Checks the exp claim for expiration. " +
                "Parameters: token (required, the JWT string), verify_signature " +
                "(optional boolean, default false. If true, verifies HMAC signature), " +
                "secret (optional, the secret key for HMAC signature verification).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    string("token", "The JWT string to decode")
                    boolean("verify_signature", "If true, verifies the HMAC signature (default false)")
                    string("secret", "The secret key for HMAC signature verification")
                },
                required = listOf("token")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val token = args["token"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: token")
                val verifySignature = args["verify_signature"].asBooleanSafe() ?: false
                val secret = args["secret"]?.jsonPrimitive?.contentOrNull

                toolJsonResult(bridge.jwtDecode(token, verifySignature, secret))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // 12. util_decode_smart
        server.addTool(
            name = "util_decode_smart",
            description = "Automatically detect and decode multiple layers of encoding " +
                "(base64, URL encoding, hex) iteratively until stable or max depth is " +
                "reached. fully_decoded is true when no further layer could be decoded. " +
                "Parameters: data (required, the encoded data string), " +
                "max_depth (optional integer 1-$MAX_DECODE_DEPTH, default 10, maximum decoding iterations).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    string("data", "The encoded data string")
                    integer("max_depth", "Maximum decoding iterations (default 10)", 1, MAX_DECODE_DEPTH)
                },
                required = listOf("data")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val data = args["data"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool toolError("Missing required parameter: data")
                val maxDepth = args["max_depth"].asBoundedInt("max_depth", 1, MAX_DECODE_DEPTH)
                    .getOrElse { return@addTool toolError(it.message ?: "Invalid max_depth") } ?: 10

                toolJsonResult(bridge.decodeSmart(data, maxDepth))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        // NOTE: util_shell_execute was removed in 2.0.6. It was a raw ProcessBuilder
        // (NOT "Burp's safe shell API" as previously mis-documented) and, combined with
        // the unauthenticated anyHost() transports, was a remote-code-execution primitive
        // reachable from any website the operator visited. A Burp HTTP-tooling extension
        // has no business shelling out; do not reintroduce it.
    }

    private fun jsonKey(key: String, value: String): CallToolResult = toolJsonResult(buildJsonObject { put(key, value) })

    private fun JsonObjectBuilder.string(name: String, description: String) =
        putJsonObject(name) { put("type", "string"); put("description", description) }

    private fun JsonObjectBuilder.boolean(name: String, description: String) =
        putJsonObject(name) { put("type", "boolean"); put("description", description) }

    private fun JsonObjectBuilder.integer(name: String, description: String, min: Int, max: Int) =
        putJsonObject(name) {
            put("type", "integer"); put("minimum", min); put("maximum", max); put("description", description)
        }

    private fun JsonObjectBuilder.enumString(name: String, description: String, values: List<String>) =
        putJsonObject(name) {
            put("type", "string")
            putJsonArray("enum") { values.forEach { add(it) } }
            put("description", "$description: ${values.joinToString(", ")}")
        }
}
