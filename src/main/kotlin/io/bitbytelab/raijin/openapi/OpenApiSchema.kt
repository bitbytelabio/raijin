package io.bitbytelab.raijin.openapi

import kotlinx.serialization.json.*

/**
 * Example values for OpenAPI 3.x / Swagger 2.0 schemas, so an imported operation is sent with a body
 * and parameters the API has a chance of accepting.
 *
 * A schema is first taken apart into its composition-free [parts] (`$ref` followed, `allOf` members,
 * the first usable `oneOf` / `anyOf` branch); each part contributes what it states (`example`,
 * `default`, `enum`, or a value built from `type` / `format`) and object contributions are merged.
 * A `$ref` that is already being expanded contributes nothing, which is what ends recursive schemas.
 */
object OpenApiSchema {
    private const val MAX_DEPTH = 24
    private const val MAX_COMPOSITION_DEPTH = 32

    /** Values one example may hold; what is left of a larger schema is left out. */
    private const val MAX_VALUES = 10_000
    private val ALTERNATIVES = listOf("oneOf", "anyOf")
    private val PLACEHOLDER = JsonPrimitive("test")

    /** One example in the making: the `$ref`s open on the current path and the values still allowed. */
    private class Generation(val doc: OpenApiDocument) {
        val active = HashSet<String>()
        var budget = MAX_VALUES
    }

    /** An example value for [schema]; `"test"` when the schema says nothing usable. */
    fun example(schema: JsonElement?, doc: OpenApiDocument): JsonElement =
        generate(schema, Generation(doc), 0) ?: PLACEHOLDER

    /**
     * The composition-free schemas [schema] is made of, most specific first: the schema itself, the
     * target of its `$ref`, its `allOf` members and the first usable `oneOf` / `anyOf` branch. Body
     * builders read serialisation hints (`format`, `xml`, property schemas) off these.
     */
    fun parts(schema: JsonElement?, doc: OpenApiDocument): List<JsonObject> {
        val parts = ArrayList<JsonObject>()
        if (schema is JsonObject) collect(schema, Generation(doc), ArrayList(), parts, 0)
        return parts
    }

    /** [keyword] as stated by the most specific of [parts] that has it. */
    fun keyword(parts: List<JsonObject>, keyword: String): JsonElement? = parts.firstNotNullOfOrNull { it[keyword] }

    /** The property schemas of [parts] together, the most specific part winning a name clash. */
    fun properties(parts: List<JsonObject>): Map<String, JsonElement> {
        val merged = LinkedHashMap<String, JsonElement>()
        for (part in parts) {
            (part["properties"] as? JsonObject)?.forEach { (name, schema) -> merged.putIfAbsent(name, schema) }
        }
        return merged
    }

    /** Null when [schema] can only be reached through a `$ref` that is already open, or the example is full. */
    private fun generate(schema: JsonElement?, gen: Generation, depth: Int): JsonElement? {
        if (schema !is JsonObject) return PLACEHOLDER // absent, or a boolean schema
        if (depth > MAX_DEPTH || gen.budget <= 0) return null
        gen.budget--
        // An example the schema states for itself is taken whole; what its parts state is merged below.
        explicit(schema)?.let { return it }
        val entered = ArrayList<String>()
        val parts = ArrayList<JsonObject>()
        try {
            if (!collect(schema, gen, entered, parts, 0)) return null
            val values = parts.mapNotNull { plain(it, gen, depth) }
            val first = values.firstOrNull() ?: return PLACEHOLDER
            // The most specific statement decides the kind of value; objects stated by several parts are merged.
            if (first !is JsonObject || values.size == 1) return first
            val merged = LinkedHashMap<String, JsonElement>()
            for (value in values) {
                if (value is JsonObject) for ((name, item) in value) merged.putIfAbsent(name, item)
            }
            return JsonObject(merged)
        } finally {
            for (ref in entered) gen.active.remove(ref)
        }
    }

    /**
     * Appends the parts of [schema] to [parts] and opens every `$ref` followed (recorded in [entered];
     * the caller closes them once it is done with the subtree). False, with [parts] as it was, when the
     * schema is a `$ref` that is already open.
     */
    private fun collect(
        schema: JsonObject,
        gen: Generation,
        entered: MutableList<String>,
        parts: MutableList<JsonObject>,
        depth: Int
    ): Boolean {
        if (depth > MAX_COMPOSITION_DEPTH) return false
        val mark = parts.size
        parts.add(schema)
        val ref = schema[REF].asText()
        val target = ref?.let { gen.doc.resolve(it) } as? JsonObject
        // A dangling or external reference leaves only its sibling keywords to go by.
        if (ref != null && target != null) {
            if (!gen.active.add(ref)) return rollback(parts, mark)
            entered.add(ref)
            if (!collect(target, gen, entered, parts, depth + 1)) return rollback(parts, mark)
        }
        (schema["allOf"] as? JsonArray)?.forEach { member ->
            if (member is JsonObject) collect(member, gen, entered, parts, depth + 1)
        }
        for (keyword in ALTERNATIVES) {
            val branches = (schema[keyword] as? JsonArray)?.filterIsInstance<JsonObject>() ?: continue
            // `anyOf: [{type: "null"}, {...}]` is how 3.1 spells nullable: the null branch is the last resort.
            for (branch in branches.filterNot(::isNullType) + branches.filter(::isNullType)) {
                if (resolvable(branch, gen.doc) && collect(branch, gen, entered, parts, depth + 1)) break
            }
        }
        return true
    }

    private fun rollback(parts: MutableList<JsonObject>, mark: Int): Boolean {
        parts.subList(mark, parts.size).clear()
        return false
    }

    private fun isNullType(schema: JsonObject): Boolean = schema["type"].asText() == "null"

    private fun resolvable(schema: JsonObject, doc: OpenApiDocument): Boolean {
        val ref = schema[REF].asText() ?: return true
        return doc.resolve(ref) is JsonObject
    }

    /** What one composition-free [schema] contributes; null when it says nothing about the value. */
    private fun plain(schema: JsonObject, gen: Generation, depth: Int): JsonElement? {
        explicit(schema)?.let { return it }
        return when (typeOf(schema)) {
            null -> null
            "object" -> {
                val out = LinkedHashMap<String, JsonElement>()
                (schema["properties"] as? JsonObject)?.forEach { (name, property) ->
                    generate(property, gen, depth + 1)?.let { out[name] = it }
                }
                JsonObject(out)
            }
            "array" -> {
                val items = schema["items"]
                JsonArray(if (items is JsonObject) listOfNotNull(generate(items, gen, depth + 1)) else listOf(PLACEHOLDER))
            }
            "string" -> JsonPrimitive(stringByFormat(schema["format"].asText()))
            "integer" -> JsonPrimitive(1)
            "number" -> when (schema["format"].asText()) {
                "float", "double" -> JsonPrimitive(1.5)
                else -> JsonPrimitive(1)
            }
            "boolean" -> JsonPrimitive(true)
            "null" -> JsonNull
            else -> PLACEHOLDER
        }
    }

    /** A value the schema states outright, the most deliberately chosen example first. */
    private fun explicit(schema: JsonObject): JsonElement? =
        schema["example"].orAbsent()
            ?: (schema["examples"] as? JsonArray)?.firstOrNull().orAbsent()
            ?: schema["x-example"].orAbsent()
            ?: schema["default"].orAbsent()
            ?: schema["const"].orAbsent()
            ?: (schema["enum"] as? JsonArray)?.firstOrNull { it !is JsonNull }

    /** The declared type (the first non-null one of an OpenAPI 3.1 type array), else what the keywords imply. */
    private fun typeOf(schema: JsonObject): String? {
        val declared = when (val type = schema["type"]) {
            is JsonArray -> {
                val names = type.mapNotNull { it.asText() }
                names.firstOrNull { it != "null" } ?: names.firstOrNull()
            }
            else -> type.asText()
        }
        return declared ?: when {
            schema["properties"] is JsonObject -> "object"
            schema["items"] is JsonObject -> "array"
            else -> null
        }
    }

    private fun stringByFormat(format: String?): String = when (format) {
        "email" -> "test@example.com"
        "date-time" -> "2020-01-01T00:00:00Z"
        "date" -> "2020-01-01"
        "uuid" -> "00000000-0000-0000-0000-000000000000"
        "uri", "url" -> "https://example.com"
        "hostname" -> "example.com"
        "ipv4" -> "127.0.0.1"
        "password" -> "P@ssw0rd!"
        "byte" -> "dGVzdA=="
        else -> "test"
    }
}
