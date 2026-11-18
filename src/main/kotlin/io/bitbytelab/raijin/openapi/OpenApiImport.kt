package io.bitbytelab.raijin.openapi

import io.bitbytelab.raijin.safety.RequestHygiene
import kotlinx.serialization.json.*

/** One ready-to-send request for an operation of the document. */
class PlannedRequest(
    val method: String,
    val server: ServerUrl,
    /** Origin-form request target: the encoded path below [server], base path included, plus the query. */
    val target: String,
    /** Header and cookie parameters; the `Content-Type` belongs to [body]. */
    val headers: List<Pair<String, String>>,
    val body: PlannedBody?,
    val operationId: String,
    val summary: String,
    val tags: List<String>,
    val queryParameters: Int,
    /** The Security Requirement Objects in force (alternatives; empty means no credentials), null when none is stated. */
    val security: JsonArray?
) {
    val url: String get() = server.origin + target
}

/** What importing a document comes to: its requests, and the credentials its operations expect. */
class ImportPlan(
    val version: String,
    val server: ServerUrl,
    val requests: List<PlannedRequest>,
    /** Security schemes by name, each with a `credential` line saying how a request carries it. */
    val securitySchemes: JsonObject,
    val warnings: List<String>
)

/** Turns an OpenAPI 3.x / Swagger 2.0 document into one request per operation, with example parameters and body. */
object OpenApiImport {
    /** Text one parameter value or request body example may make, its name counted once for every item it spreads into. */
    internal const val MAX_EXAMPLE_CHARS = 1L shl 20

    /** Text the requests of one import may hold together, the examples measured on the way included: 64 MiB. */
    internal const val MAX_PLAN_CHARS = 64L shl 20

    private val METHODS = listOf("get", "post", "put", "delete", "patch", "options", "head", "trace")
    private val PATH_PARAMETER = Regex("\\{([^{}/]+)\\}")

    /** What a `{placeholder}` no parameter declares is filled with: a value a numeric and a string segment both accept. */
    private const val UNDECLARED_PATH_VALUE = "1"

    /** Characters of a path that are sent as written; `%` among them, so what is already escaped stays so. */
    private const val PATH_LITERALS = "/%:@!$&'()*+,;="

    /** Reserved characters an `allowReserved` query value keeps: those a query may hold that do not end the value. */
    private const val RESERVED_IN_QUERY = ":/?@!$'()*,;="

    /** Cookie-value characters (RFC 6265) besides the unreserved ones; `%` is escaped so the value decodes back. */
    private const val COOKIE_SAFE = "!#$&'()*+/:<=>?@[]^`{|}"

    /** Headers the connection sets for itself: a placeholder value would misroute the request or misstate its length. */
    private val TRANSPORT_HEADERS = setOf("host", "content-length", "transfer-encoding", "connection")

    private class Context(
        val doc: OpenApiDocument,
        val swagger2: Boolean,
        val server: ServerUrl,
        /** The caller chose the server: per-path and per-operation `servers` do not apply. */
        val pinned: Boolean,
        val documentUrl: String?,
        val budget: TextBudget
    )

    /**
     * Plans one request per operation of [doc].
     *
     * @param baseUrl replaces every server URL of the document when given.
     * @param documentUrl where the document was served from; relative server URLs resolve against it.
     * @throws IllegalArgumentException when this is not an OpenAPI / Swagger document, no server URL can be worked out,
     *   or the requests would hold more than [MAX_PLAN_CHARS] of text.
     */
    fun plan(doc: OpenApiDocument, baseUrl: String? = null, documentUrl: String? = null): ImportPlan {
        val root = doc.root
        val openApi = root["openapi"].asText()
        val swagger = root["swagger"].asText()
        require(openApi != null || swagger != null) {
            "Unrecognized spec format: missing 'openapi' or 'swagger' key. " +
                "Provide an OpenAPI 3.x or Swagger 2.0 document (JSON or YAML)."
        }
        val swagger2 = openApi == null
        val override = baseUrl?.trim()?.takeIf { it.isNotEmpty() }
        val server = when {
            override != null -> OpenApiServers.parse(override) ?: throw IllegalArgumentException("Invalid base URL: $override")
            swagger2 -> OpenApiServers.swagger2(root, documentUrl)
            else -> OpenApiServers.openApi3(root, documentUrl)
        } ?: throw IllegalArgumentException(
            "No usable server URL in the document: it has to be an absolute http(s) URL with a dotted host name or " +
                "localhost, or a relative one that spec_url can resolve. Pass base_url to choose the target."
        )
        val context = Context(doc, swagger2, server, pinned = override != null, documentUrl = documentUrl, budget = TextBudget(MAX_PLAN_CHARS))
        val warnings = ArrayList<String>()
        val requests = ArrayList<PlannedRequest>()
        for ((path, declared) in root["paths"] as? JsonObject ?: JsonObject(emptyMap())) {
            if (path.startsWith("x-")) continue // a specification extension, not a path
            val item = doc.deref(declared) ?: continue
            for (method in METHODS) {
                val operation = item[method] as? JsonObject ?: continue
                try {
                    requests.add(request(context, path, item, method, operation))
                } catch (e: PlanTooLargeException) {
                    throw e
                } catch (e: Exception) {
                    warnings.add(context.budget.take("${method.uppercase()} $path was skipped: ${e.message ?: e.javaClass.simpleName}"))
                }
            }
        }
        return ImportPlan(
            version = if (swagger2) "Swagger $swagger" else "OpenAPI $openApi",
            server = server,
            requests = requests,
            securitySchemes = securitySchemes(doc).also(context.budget::chargeText),
            warnings = warnings
        )
    }

    private fun request(context: Context, path: String, item: JsonObject, method: String, operation: JsonObject): PlannedRequest {
        val doc = context.doc
        val budget = context.budget
        val server = if (context.pinned) context.server else
            OpenApiServers.fromServers(operation["servers"], context.documentUrl)
                ?: OpenApiServers.fromServers(item["servers"], context.documentUrl)
                ?: context.server
        budget.take(server.url)

        val query = ArrayList<String>()
        val headers = ArrayList<Pair<String, String>>()
        val cookies = ArrayList<String>()
        val pathValues = HashMap<String, String>()
        val formData = ArrayList<FormField>()
        var bodyParameter: JsonObject? = null
        var queryParameters = 0
        for (parameter in parameters(doc, item, operation)) {
            val name = parameter["name"].asText() ?: continue
            val location = parameter["in"].asText()
            if (location == "body") { // Swagger 2: its schema is turned into the request body below
                bodyParameter = parameter
                continue
            }
            val value = parameterValue(parameter, doc, budget)
            // Measured before any text is made from it: spread by its style, an example can outgrow the document.
            budget.admit("the example of parameter '$name'", name, value)
            val style = ParameterStyle.of(parameter, location, context.swagger2)
            when (location) {
                "query" -> {
                    queryParameters++
                    val reserved = (parameter["allowReserved"] as? JsonPrimitive)?.booleanOrNull == true
                    formPairs(name, value, style) { percentEncode(it, if (reserved) RESERVED_IN_QUERY else "") }
                        .mapTo(query) { (key, text) -> budget.take("$key=$text") }
                }
                "path" -> pathValues[name] = budget.take(pathText(name, value, style) { percentEncode(it) })
                // A line break in an example must not split the header it is sent in.
                "header" -> if (name.lowercase() !in TRANSPORT_HEADERS) {
                    headers.add(
                        budget.take(RequestHygiene.stripCrlf(name)) to
                            budget.take(RequestHygiene.stripCrlf(pathText(name, value, style) { it }))
                    )
                }
                "cookie" -> formPairs(name, value, style) { percentEncode(it, COOKIE_SAFE) }
                    .mapTo(cookies) { (key, text) -> budget.take("$key=$text") }
                "formData" -> formData.add(FormField(name, value, style, file = parameter["type"].asText() == "file"))
            }
        }
        if (cookies.isNotEmpty()) headers.add("Cookie" to cookies.joinToString("; "))

        // Any method may carry the body its operation declares (DELETE included).
        val declaredBody = bodyParameter
        val body = when {
            !context.swagger2 -> doc.deref(operation["requestBody"])?.let { OpenApiBodies.fromRequestBody(it, doc, budget) }
            declaredBody != null -> OpenApiBodies.fromBodyParameter(declaredBody, consumes(context, operation), doc, budget)
            formData.isNotEmpty() -> OpenApiBodies.fromFormData(formData, consumes(context, operation), budget)
            else -> null
        }
        if (body != null) {
            budget.charge(body.contentType.length.toLong() + body.text.length)
            headers.removeAll { it.first.equals("Content-Type", ignoreCase = true) }
        }

        // The template may carry a fragment (dropped) or a literal query (kept) besides its `{placeholders}`;
        // a placeholder may come back any number of times.
        val template = path.substringBefore('#')
        val filled = PATH_PARAMETER.replace(template.substringBefore('?')) {
            budget.take(pathValues[it.groupValues[1]] ?: UNDECLARED_PATH_VALUE)
        }
        template.substringAfter('?', "").takeIf { it.isNotEmpty() }?.let { query.add(0, it) }
        val target = budget.take(
            percentEncode(OpenApiServers.joinPaths(server.basePath, filled), PATH_LITERALS) +
                if (query.isEmpty()) "" else "?" + query.joinToString("&")
        )

        // The endpoint list repeats these for every request, and `$ref`-shared path items repeat requests.
        val operationId = operation["operationId"].asText() ?: "$method $path"
        val summary = operation["summary"].asText().orEmpty()
        val tags = (operation["tags"] as? JsonArray)?.mapNotNull { it.asText() }.orEmpty()
        val security = (operation["security"] ?: doc.root["security"]) as? JsonArray
        budget.charge(operationId.length.toLong() + summary.length + tags.sumOf { it.length.toLong() })
        security?.let(budget::chargeText)

        return PlannedRequest(
            method = method.uppercase(),
            server = server,
            target = target,
            headers = headers,
            body = body,
            operationId = operationId,
            summary = summary,
            tags = tags,
            queryParameters = queryParameters,
            security = security
        )
    }

    /**
     * The parameters of an operation with `$ref`s followed: the path item's, then the operation's own,
     * which replace a path-level parameter of the same name and location.
     */
    private fun parameters(doc: OpenApiDocument, item: JsonObject, operation: JsonObject): Collection<JsonObject> {
        val unique = LinkedHashMap<String, JsonObject>()
        for (owner in listOf(item, operation)) {
            val declared = owner["parameters"] as? JsonArray ?: continue
            for (reference in declared) {
                val parameter = doc.deref(reference) ?: continue
                val name = parameter["name"].asText() ?: continue
                val location = parameter["in"].asText() ?: continue
                // Header names are case-insensitive; a line break cannot occur in a location, so it separates safely.
                unique[location + "\n" + if (location == "header") name.lowercase() else name] = parameter
            }
        }
        return unique.values
    }

    /** The value a parameter is sent with: its own `example(s)`, else one generated from its schema. */
    private fun parameterValue(parameter: JsonObject, doc: OpenApiDocument, budget: TextBudget): JsonElement {
        (parameter["example"].orAbsent() ?: doc.exampleValue(parameter["examples"]) ?: parameter["x-example"].orAbsent())
            ?.let { return it }
        parameter["schema"].orAbsent()?.let { return OpenApiSchema.example(it, doc) }
        // OpenAPI 3 `content`: a single media type, whose value travels serialised in one piece.
        ((parameter["content"] as? JsonObject)?.values?.firstOrNull() as? JsonObject)?.let { media ->
            val value = media["example"].orAbsent()
                ?: doc.exampleValue(media["examples"])
                ?: OpenApiSchema.example(media["schema"], doc)
            if (value is JsonPrimitive) return value
            budget.admit("the example of parameter '${parameter["name"].asText()}'", "", value)
            return JsonPrimitive(value.toString())
        }
        // Swagger 2: the parameter itself carries `type`, `format`, `enum`, `default` and `items`.
        return OpenApiSchema.example(parameter, doc)
    }

    private fun consumes(context: Context, operation: JsonObject): List<String> =
        ((operation["consumes"] ?: context.doc.root["consumes"]) as? JsonArray)?.mapNotNull { it.asText() }.orEmpty()

    /** OpenAPI 3 `components.securitySchemes` or Swagger 2 `securityDefinitions`, vendor extensions left out. */
    private fun securitySchemes(doc: OpenApiDocument): JsonObject {
        val declared = (doc.root["components"] as? JsonObject)?.get("securitySchemes") as? JsonObject
            ?: doc.root["securityDefinitions"] as? JsonObject
            ?: return JsonObject(emptyMap())
        return buildJsonObject {
            for ((name, reference) in declared) {
                val scheme = doc.deref(reference) ?: continue
                putJsonObject(name) {
                    for ((key, value) in scheme) if (!key.startsWith("x-")) put(key, value)
                    credential(scheme)?.let { put("credential", it) }
                }
            }
        }
    }

    /** How a request carries the credential a security scheme asks for. */
    private fun credential(scheme: JsonObject): String? {
        return when (scheme["type"].asText()?.lowercase()) {
            "apikey" -> scheme["name"].asText()?.let { name ->
                when (scheme["in"].asText()) {
                    "header" -> "header $name: <api key>"
                    "query" -> "query parameter $name=<api key>"
                    "cookie" -> "cookie $name=<api key>"
                    else -> null
                }
            }
            "http" -> when (val httpScheme = scheme["scheme"].asText()?.lowercase()) {
                null -> null
                "basic" -> "header Authorization: Basic <base64(user:password)>"
                "bearer" -> "header Authorization: Bearer <token>"
                else -> "header Authorization: $httpScheme <credentials>"
            }
            "basic" -> "header Authorization: Basic <base64(user:password)>"
            "oauth2", "openidconnect" -> "header Authorization: Bearer <access token>"
            "mutualtls" -> "TLS client certificate"
            else -> null
        }
    }
}

/**
 * The text the requests of one import may still hold. The model shares a value reused through `$ref`s or YAML
 * aliases rather than copying it, so a small document can expand into more text than the heap holds: every
 * example is charged as it is measured and every text as it is made, and running out fails the whole import.
 */
internal class TextBudget(private var left: Long) {
    fun charge(length: Long) {
        left -= length
        if (left < 0) throw PlanTooLargeException()
    }

    /** [text], charged. */
    fun take(text: String): String = text.also { charge(it.length.toLong()) }

    /** Charges the JSON text of [element], measured no further than what is left. */
    fun chargeText(element: JsonElement) = charge(element.textLength(left))

    /** Fails the import once a text still being written has outgrown what is left. */
    fun check(length: Int) {
        if (length > left) throw PlanTooLargeException()
    }

    /**
     * Refuses [value] (an [IllegalArgumentException] naming [what]) when its text as the parameter or form
     * field [name] could pass [OpenApiImport.MAX_EXAMPLE_CHARS], a style repeating the name for every item it
     * spreads; what was measured is charged either way.
     */
    fun admit(what: String, name: String, value: JsonElement) {
        val items = when (value) {
            is JsonArray -> value.size
            is JsonObject -> value.size
            else -> 0
        }
        val length = value.textLength(OpenApiImport.MAX_EXAMPLE_CHARS) + (items + 1L) * name.length
        charge(minOf(length, OpenApiImport.MAX_EXAMPLE_CHARS))
        require(length <= OpenApiImport.MAX_EXAMPLE_CHARS) { "$what is larger than ${OpenApiImport.MAX_EXAMPLE_CHARS shr 20} MiB" }
    }
}

/** The import ran out of [TextBudget]: it fails as a whole, before anything reaches Burp. */
internal class PlanTooLargeException : IllegalArgumentException(
    "The requests planned from this document come to more than ${OpenApiImport.MAX_PLAN_CHARS shr 20} MiB of text " +
        "(examples reused through $REF or YAML aliases multiply it); nothing was imported"
)
