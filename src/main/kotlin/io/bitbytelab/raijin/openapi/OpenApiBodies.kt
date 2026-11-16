package io.bitbytelab.raijin.openapi

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*

/** A request body ready to send, with the `Content-Type` it goes under. */
class PlannedBody(val contentType: String, val text: String)

/** One field of a form body. [file] marks an upload; [contentType] is a part type the description fixes. */
internal class FormField(
    val name: String,
    val value: JsonElement,
    val style: ParameterStyle = ParameterStyle.FORM,
    val file: Boolean = false,
    val contentType: String? = null
)

/** Builds request bodies: JSON, URL-encoded and multipart forms, XML, and plain text for anything else. */
internal object OpenApiBodies {
    const val BOUNDARY = "----RaijinFormBoundary7MA4YWxkTrZu0gW"

    private val XML_NAME_INVALID = Regex("[^\\p{L}\\p{N}_.-]")

    /** Media type families, in the order they are preferred when an operation accepts several. */
    private enum class Kind { JSON, FORM, MULTIPART, XML, TEXT, OTHER }

    /** Body for an OpenAPI 3 Request Body Object (already dereferenced); null when it declares no content. */
    fun fromRequestBody(requestBody: JsonObject, doc: OpenApiDocument): PlannedBody? {
        val content = requestBody["content"] as? JsonObject ?: return null
        val (mediaType, declared) = content.entries.minByOrNull { kindOf(it.key).ordinal } ?: return null
        val media = declared as? JsonObject ?: JsonObject(emptyMap())
        val schema = media["schema"].orAbsent()
        val value = media["example"].orAbsent()
            ?: doc.exampleValue(media["examples"])
            ?: schema?.let { OpenApiSchema.example(it, doc) }
        return render(mediaType, value, schema, media["encoding"] as? JsonObject, doc)
    }

    /** Body for a Swagger 2 `in: body` parameter, in the JSON (else XML, else first) type the operation consumes. */
    fun fromBodyParameter(parameter: JsonObject, consumes: List<String>, doc: OpenApiDocument): PlannedBody {
        val mediaType = consumes
            .filter { kindOf(it) != Kind.FORM && kindOf(it) != Kind.MULTIPART }
            .minByOrNull { kindOf(it).ordinal } ?: "application/json"
        val schema = parameter["schema"].orAbsent()
        return render(mediaType, schema?.let { OpenApiSchema.example(it, doc) }, schema, null, doc)
    }

    /** Body for Swagger 2 `in: formData` parameters: multipart when a file is uploaded or only multipart is consumed. */
    fun fromFormData(fields: List<FormField>, consumes: List<String>): PlannedBody {
        val kinds = consumes.map { kindOf(it) }
        val asMultipart = fields.any { it.file } || (Kind.MULTIPART in kinds && Kind.FORM !in kinds)
        return if (asMultipart) PlannedBody("multipart/form-data; boundary=$BOUNDARY", multipart(fields))
        else PlannedBody("application/x-www-form-urlencoded", urlEncoded(fields))
    }

    private fun kindOf(mediaType: String): Kind {
        val type = mediaType.substringBefore(';').trim().lowercase()
        return when {
            type == "application/x-www-form-urlencoded" -> Kind.FORM
            type.startsWith("multipart/") -> Kind.MULTIPART
            type.endsWith("/json") || type.endsWith("+json") || type == "*/*" || type == "application/*" -> Kind.JSON
            type.endsWith("/xml") || type.endsWith("+xml") -> Kind.XML
            type.startsWith("text/") -> Kind.TEXT
            else -> Kind.OTHER
        }
    }

    private fun render(
        mediaType: String,
        value: JsonElement?,
        schema: JsonElement?,
        encoding: JsonObject?,
        doc: OpenApiDocument
    ): PlannedBody {
        val kind = kindOf(mediaType)
        // A media type range cannot be sent as a Content-Type: name the concrete type the body is written in.
        val contentType = if ('*' !in mediaType) mediaType else when (kind) {
            Kind.JSON -> "application/json"
            Kind.MULTIPART -> "multipart/form-data"
            Kind.TEXT -> "text/plain"
            else -> "application/octet-stream"
        }
        return when (kind) {
            Kind.JSON -> PlannedBody(contentType, jsonText(value ?: JsonObject(emptyMap())))
            // A form example written as one string is already encoded.
            Kind.FORM -> PlannedBody(
                contentType,
                if (value is JsonPrimitive) value.asFieldText() else urlEncoded(fields(value, schema, encoding, doc))
            )
            Kind.MULTIPART -> PlannedBody(
                contentType.substringBefore(';').trim() + "; boundary=$BOUNDARY",
                multipart(fields(value, schema, encoding, doc))
            )
            Kind.XML -> PlannedBody(contentType, xmlText(value, schema, doc))
            Kind.TEXT, Kind.OTHER -> PlannedBody(contentType, value?.asFieldText() ?: "test")
        }
    }

    /** JSON body text. A string example that already holds a JSON document is that document, not a JSON string. */
    private fun jsonText(value: JsonElement): String {
        if (value is JsonPrimitive && value.isString) {
            val text = value.content.trim()
            if ((text.startsWith("{") || text.startsWith("[")) && parsesAsJson(text)) return text
        }
        return value.toString()
    }

    private fun parsesAsJson(text: String): Boolean = try {
        Json.parseToJsonElement(text)
        true
    } catch (_: SerializationException) {
        false
    } catch (_: StackOverflowError) { // brackets nested deeper than the parser can recurse
        false
    }

    /** The fields of a form body: the properties of its example value, with what the schema and `encoding` say of each. */
    private fun fields(value: JsonElement?, schema: JsonElement?, encoding: JsonObject?, doc: OpenApiDocument): List<FormField> {
        val properties = OpenApiSchema.properties(OpenApiSchema.parts(schema, doc))
        return (value as? JsonObject).orEmpty().map { (name, item) ->
            val rule = encoding?.get(name) as? JsonObject
            val style = rule?.get("style").asText() ?: "form"
            FormField(
                name = name,
                value = item,
                style = ParameterStyle(style, (rule?.get("explode") as? JsonPrimitive)?.booleanOrNull ?: (style == "form")),
                file = isUpload(properties[name], doc),
                contentType = rule?.get("contentType").asText()?.substringBefore(',')?.trim()
            )
        }
    }

    /** Whether a form property is a file, or an array of files. */
    private fun isUpload(schema: JsonElement?, doc: OpenApiDocument): Boolean {
        val parts = OpenApiSchema.parts(schema, doc)
        return declaresFile(parts) || declaresFile(OpenApiSchema.parts(OpenApiSchema.keyword(parts, "items"), doc))
    }

    /** `format: binary` (OpenAPI 3.0), `contentMediaType` (3.1) or `type: file` (Swagger 2). */
    private fun declaresFile(parts: List<JsonObject>): Boolean =
        OpenApiSchema.keyword(parts, "format").asText() == "binary" ||
            OpenApiSchema.keyword(parts, "contentMediaType") != null ||
            OpenApiSchema.keyword(parts, "type").asText() == "file"

    private fun urlEncoded(fields: List<FormField>): String =
        fields.flatMap { formPairs(it.name, it.value, it.style, ::formEncode) }
            .joinToString("&") { (name, value) -> "$name=$value" }

    private fun multipart(fields: List<FormField>): String = buildString {
        for (field in fields) {
            val value = field.value
            // An array is sent as one part per item, all under the field's name.
            for (item in value as? JsonArray ?: listOf(value)) {
                append("--").append(BOUNDARY).append("\r\n")
                append("Content-Disposition: form-data; name=\"").append(quoted(field.name)).append('"')
                if (field.file) append("; filename=\"test.txt\"")
                append("\r\n")
                val type = field.contentType ?: when {
                    field.file -> "application/octet-stream"
                    item is JsonObject || item is JsonArray -> "application/json"
                    else -> null
                }
                if (type != null) append("Content-Type: ").append(type).append("\r\n")
                append("\r\n").append(item.asFieldText()).append("\r\n")
            }
        }
        append("--").append(BOUNDARY).append("--\r\n")
    }

    /** A field name inside the quoted `name="..."` of a part header, escaped the way browsers do. */
    private fun quoted(name: String): String = name.replace("\"", "%22").replace("\r", "%0D").replace("\n", "%0A")

    private fun xmlText(value: JsonElement?, schema: JsonElement?, doc: OpenApiDocument): String {
        // An example that is already an XML document is sent as written.
        if (value is JsonPrimitive && value.isString && value.content.trimStart().startsWith("<")) return value.content
        val parts = OpenApiSchema.parts(schema, doc)
        val out = StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
        // A document has one root: a top-level array is wrapped, its items named after their own schema.
        val rootItem = refName(OpenApiSchema.keyword(parts, "items")) ?: "item"
        writeXml(out, refName(schema) ?: "root", value ?: JsonNull, parts, doc, rootItem)
        return out.toString()
    }

    /** Last segment of a schema's own `$ref` (`Pet` for `#/components/schemas/Pet`): its usual element name. */
    private fun refName(schema: JsonElement?): String? =
        (schema as? JsonObject)?.get(REF).asText()?.substringAfterLast('/')

    /**
     * Writes [value] as the element [name], or as what the schema's `xml` object says instead: another
     * `name`, a `prefix` and `namespace`, properties as attributes, an array `wrapped` in its own element.
     * A non-null [rootItem] wraps an array regardless and names its items.
     */
    private fun writeXml(
        out: StringBuilder,
        name: String,
        value: JsonElement,
        parts: List<JsonObject>,
        doc: OpenApiDocument,
        rootItem: String? = null
    ) {
        val hints = OpenApiSchema.keyword(parts, "xml") as? JsonObject
        if (value is JsonArray) {
            val wrapper = if (rootItem != null || hints.flag("wrapped")) xmlName(name, hints) else null
            // Unwrapped items take the property's name: an `xml.name` on the array only names its wrapper.
            val itemName = rootItem ?: if (wrapper != null) hints?.get("name").asText() ?: name else name
            val itemParts = OpenApiSchema.parts(OpenApiSchema.keyword(parts, "items"), doc)
            if (wrapper != null) out.append('<').append(wrapper).append('>')
            for (item in value) writeXml(out, itemName, item, itemParts, doc)
            if (wrapper != null) out.append("</").append(wrapper).append('>')
            return
        }
        val tag = xmlName(name, hints)
        out.append('<').append(tag)
        hints?.get("namespace").asText()?.let { namespace ->
            out.append(" xmlns")
            hints?.get("prefix").asText()?.let { out.append(':').append(it) }
            out.append("=\"").append(escapeXml(namespace)).append('"')
        }
        if (value is JsonObject) {
            val properties = OpenApiSchema.properties(parts)
            val schemas = value.mapValues { (key, _) -> OpenApiSchema.parts(properties[key], doc) }
            val (attributes, elements) = value.entries.partition { (key, item) ->
                item is JsonPrimitive && (OpenApiSchema.keyword(schemas.getValue(key), "xml") as? JsonObject).flag("attribute")
            }
            for ((key, item) in attributes) {
                val attribute = xmlName(key, OpenApiSchema.keyword(schemas.getValue(key), "xml") as? JsonObject)
                out.append(' ').append(attribute).append("=\"").append(escapeXml(item.asFieldText())).append('"')
            }
            out.append('>')
            for ((key, item) in elements) writeXml(out, key, item, schemas.getValue(key), doc)
        } else {
            out.append('>').append(escapeXml(value.asFieldText()))
        }
        out.append("</").append(tag).append('>')
    }

    private fun JsonObject?.flag(name: String): Boolean = (this?.get(name) as? JsonPrimitive)?.booleanOrNull == true

    /** The element or attribute name: `xml.name` over [fallback], made a legal XML name, behind any `xml.prefix`. */
    private fun xmlName(fallback: String, hints: JsonObject?): String {
        val local = XML_NAME_INVALID.replace(hints?.get("name").asText() ?: fallback, "_").ifEmpty { "_" }
        val name = if (local[0].isLetter() || local[0] == '_') local else "_$local"
        return hints?.get("prefix").asText()?.let { "$it:$name" } ?: name
    }

    private fun escapeXml(text: String): String = buildString(text.length) {
        for (char in text) {
            when (char) {
                '&' -> append("&amp;")
                '<' -> append("&lt;")
                '>' -> append("&gt;")
                '"' -> append("&quot;")
                '\'' -> append("&apos;")
                else -> append(char)
            }
        }
    }
}
