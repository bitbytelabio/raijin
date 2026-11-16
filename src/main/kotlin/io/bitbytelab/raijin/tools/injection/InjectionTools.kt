package io.bitbytelab.raijin.tools.injection

import io.bitbytelab.raijin.bridge.InjectionBridge
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.core.asLongSafe
import io.bitbytelab.raijin.core.asStringList
import io.bitbytelab.raijin.injection.InjectionClass
import io.bitbytelab.raijin.injection.PayloadEncoding
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.*

/** Registers the `injection_probe` MCP tool. */
object InjectionTools {

    private val PORTS = 1..65535

    /** `injection_probe` arguments after validation. */
    internal data class Arguments(
        val request: String,
        val host: String,
        val port: Int,
        val useTls: Boolean,
        val classes: List<String>?,
        val delaySeconds: Int,
        val encoding: String?,
        val baseValue: String,
        val oob: Boolean,
        val oobWaitSeconds: Int,
        val timeBudgetSeconds: Int,
    )

    fun register(server: Server, bridge: InjectionBridge) {
        server.addTool(
            name = "injection_probe",
            description = "Guided injection detection with confirmation oracles (not blind fuzzing). Mark the injection " +
                "point with the FUZZ keyword anywhere in the raw request: the request line, a header line such as " +
                "'Cookie: TrackingId=FUZZ', or the body. Each payload is written in the encoding that position needs " +
                "(URL path/query, form body, JSON string or value, XML, cookie, header) and Content-Length is " +
                "recomputed; 'encoding' overrides this. Classes: sqli (error, time, boolean), nosqli (error, " +
                "server-side JavaScript boolean, operator injection, time), cmdi (command output, time, out-of-band), " +
                "ssti (expression evaluation), lfi (file read), xxe (external entity, XInclude, out-of-band), ssrf " +
                "(internal content in the response, out-of-band), xss (reflection context and which characters " +
                "survive), open_redirect, crlf (response header injection). Out-of-band checks use a Burp " +
                "Collaborator client and are skipped with a reason when Burp has none (Community Edition); an " +
                "interaction that arrives after the call returned is reported by the next call. A finding needs a " +
                "response that differs from the baseline (the same request with 'base_value' at FUZZ) in a way the " +
                "payload explains: a timeout is never evidence, a delay must repeat while a zero-delay control stays " +
                "fast, a TRUE/FALSE difference must hold over three rounds. Every finding carries its payload, a " +
                "confidence (certain, firm, tentative) and the evidence (baseline next to probe) to re-check it. All " +
                "classes together send about 130 requests when nothing is found; pass 'classes' to narrow. " +
                "Scope-gated (mcp_scope_mode).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("request") {
                        put("type", "string")
                        put("description", "Raw HTTP request with the FUZZ keyword at the injection point (request line, any header line or the body)")
                    }
                    putJsonObject("host") { put("type", "string"); put("description", "Target hostname") }
                    putJsonObject("port") {
                        put("type", "integer"); put("minimum", PORTS.first); put("maximum", PORTS.last)
                        put("description", "Target port (1-65535, default 443)")
                    }
                    putJsonObject("use_tls") { put("type", "boolean"); put("description", "Use HTTPS (default: port==443)") }
                    putJsonObject("classes") {
                        put("type", "array")
                        putJsonObject("items") {
                            put("type", "string")
                            putJsonArray("enum") { InjectionClass.accepted.forEach { add(it) } }
                        }
                        put("description", "Classes to test (default: all). 'traversal' is accepted for lfi.")
                    }
                    putJsonObject("encoding") {
                        put("type", "string")
                        putJsonArray("enum") { PayloadEncoding.ids.forEach { add(it) } }
                        put(
                            "description",
                            "How payloads are written at FUZZ. auto (default): by position, keeping %XX sequences a payload " +
                                "already has. raw: byte for byte, nothing encoded. url: percent-encoded as a query/form value. " +
                                "json: escaped as JSON string content. xml: XML-escaped."
                        )
                    }
                    putJsonObject("base_value") {
                        put("type", "string")
                        put(
                            "description",
                            "Benign value sent at FUZZ for the baseline and kept as the prefix of appended payloads (default " +
                                "\"1\"). Use the parameter's real value so TRUE conditions reproduce the normal response; " +
                                "use \"\" when FUZZ already follows the value (id=42FUZZ)."
                        )
                    }
                    putJsonObject("delay_seconds") {
                        put("type", "integer")
                        put("minimum", InjectionBridge.DELAY_SECONDS.first); put("maximum", InjectionBridge.DELAY_SECONDS.last)
                        put("description", "Sleep asked of time-based payloads (1-30, default 5). Raise it for a target with jitter.")
                    }
                    putJsonObject("oob") {
                        put("type", "boolean")
                        put("description", "Run the out-of-band checks through Burp Collaborator (default true)")
                    }
                    putJsonObject("oob_wait_seconds") {
                        put("type", "integer")
                        put("minimum", InjectionBridge.OOB_WAIT_SECONDS.first); put("maximum", InjectionBridge.OOB_WAIT_SECONDS.last)
                        put("description", "How long to wait for out-of-band interactions after the last probe (0-60, default 5)")
                    }
                    putJsonObject("time_budget_seconds") {
                        put("type", "integer")
                        put("minimum", InjectionBridge.TIME_BUDGET_SECONDS.first); put("maximum", InjectionBridge.TIME_BUDGET_SECONDS.last)
                        put("description", "No new probe starts after this long; unfinished classes are reported (10-3600, default 300)")
                    }
                },
                required = listOf("request", "host")
            )
        ) { request ->
            try {
                val args = parseArguments(request.params.arguments ?: emptyMap())
                toolJsonResult(
                    bridge.probe(
                        args.request, args.host, args.port, args.useTls, args.classes, args.delaySeconds,
                        args.encoding, args.baseValue, args.oob, args.oobWaitSeconds, args.timeBudgetSeconds,
                    )
                )
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }

    /**
     * Validates the raw tool arguments.
     * @throws IllegalArgumentException with the message to return when a value has the wrong type,
     *   is out of range, or is not one of a parameter's allowed values.
     */
    internal fun parseArguments(args: Map<String, JsonElement>): Arguments {
        val request = args.string("request")?.takeIf { it.isNotEmpty() }
            ?: throw IllegalArgumentException("Parameter 'request' is required (mark the injection point with FUZZ)")
        val host = args.string("host")?.trim()?.takeIf { it.isNotEmpty() }
            ?: throw IllegalArgumentException("Parameter 'host' is required")
        val port = args.int("port", PORTS) ?: 443
        val classes = args["classes"]?.takeUnless { it is JsonNull }?.asStringList()
        InjectionClass.select(classes).error?.let { throw IllegalArgumentException(it) }
        val encoding = args.string("encoding")?.trim()?.ifEmpty { null }
        EnumValidation.error(encoding, PayloadEncoding.ids.toSet(), "encoding")?.let {
            throw IllegalArgumentException(it["error"]?.jsonPrimitive?.contentOrNull ?: "Parameter 'encoding' has an invalid value")
        }
        return Arguments(
            request = request,
            host = host,
            port = port,
            useTls = args.bool("use_tls") ?: (port == 443),
            classes = classes,
            delaySeconds = args.int("delay_seconds", InjectionBridge.DELAY_SECONDS) ?: 5,
            encoding = encoding,
            baseValue = args.string("base_value") ?: "1",
            oob = args.bool("oob") ?: true,
            oobWaitSeconds = args.int("oob_wait_seconds", InjectionBridge.OOB_WAIT_SECONDS) ?: 5,
            timeBudgetSeconds = args.int("time_budget_seconds", InjectionBridge.TIME_BUDGET_SECONDS) ?: 300,
        )
    }

    private fun Map<String, JsonElement>.string(name: String): String? {
        val element = this[name]
        if (element == null || element is JsonNull) return null
        return (element as? JsonPrimitive)?.contentOrNull ?: throw IllegalArgumentException("Parameter '$name' must be a string")
    }

    private fun Map<String, JsonElement>.int(name: String, range: IntRange): Int? {
        val element = this[name]
        if (element == null || element is JsonNull) return null
        val value = element.asLongSafe() ?: throw IllegalArgumentException("Parameter '$name' must be an integer")
        require(value in range) { "Parameter '$name' must be between ${range.first} and ${range.last} (got $value)" }
        return value.toInt()
    }

    private fun Map<String, JsonElement>.bool(name: String): Boolean? {
        val element = this[name]
        if (element == null || element is JsonNull) return null
        return (element as? JsonPrimitive)?.booleanOrNull ?: throw IllegalArgumentException("Parameter '$name' must be true or false")
    }
}
