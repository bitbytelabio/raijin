package io.bitbytelab.raijin.openapi

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.*
import org.yaml.snakeyaml.DumperOptions
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor
import org.yaml.snakeyaml.error.YAMLException
import org.yaml.snakeyaml.nodes.MappingNode
import org.yaml.snakeyaml.nodes.Node
import org.yaml.snakeyaml.nodes.ScalarNode
import org.yaml.snakeyaml.nodes.SequenceNode
import org.yaml.snakeyaml.nodes.Tag
import org.yaml.snakeyaml.representer.Representer
import org.yaml.snakeyaml.resolver.Resolver
import java.io.ByteArrayOutputStream
import java.io.StringReader
import java.util.IdentityHashMap
import java.util.regex.Pattern

internal const val REF = "\$ref"

/** Text of a string, number or boolean; null for JSON null, objects and arrays. */
internal fun JsonElement?.asText(): String? = (this as? JsonPrimitive)?.contentOrNull

/** The element, unless it is missing or JSON null (how YAML spells an empty `example:`). */
internal fun JsonElement?.orAbsent(): JsonElement? = this?.takeUnless { it is JsonNull }

/**
 * Length of the element as compact JSON text, counted no further than just past [limit]. A value reused
 * through `$ref`s or YAML aliases is shared, not copied, in the model, so its text can be far longer than
 * the document it came from.
 */
internal fun JsonElement.textLength(limit: Long): Long {
    var length = 0L
    fun add(count: Long): Boolean {
        length += count
        return length <= limit
    }
    fun walk(element: JsonElement): Boolean = when (element) {
        is JsonObject -> add(1L + maxOf(element.size, 1)) &&
            element.all { (key, value) -> add(quotedLength(key, limit) + 1) && walk(value) }
        is JsonArray -> add(1L + maxOf(element.size, 1)) && element.all { walk(it) }
        is JsonPrimitive -> add(if (element.isString) quotedLength(element.content, limit) else element.content.length.toLong())
    }
    walk(this)
    return length
}

/** Length of [text] as a JSON string literal, escapes included; not scanned once it is longer than [limit]. */
private fun quotedLength(text: String, limit: Long): Long {
    var length = text.length + 2L
    if (text.length > limit) return length
    for (char in text) {
        when {
            char == '"' || char == '\\' -> length += 1
            char < ' ' -> length += if (char in "\b\t\n\u000C\r") 1 else 5
        }
    }
    return length
}

/**
 * A parsed OpenAPI 3.x / Swagger 2.0 document: the JSON model of a JSON or YAML source, plus the
 * same-document `$ref` lookup every other part of the import resolves references through.
 */
class OpenApiDocument(val root: JsonObject) {

    /**
     * Target of a same-document reference (`#/components/schemas/Pet`, `#/paths/~1pets~1%7Bid%7D/get`):
     * a JSON Pointer in URI-fragment form. Null when the reference is external or dangling.
     */
    fun resolve(ref: String): JsonElement? {
        if (!ref.startsWith("#")) return null
        val pointer = ref.substring(1)
        if (pointer.isEmpty()) return root
        if (!pointer.startsWith("/")) return null
        var node: JsonElement = root
        for (raw in pointer.substring(1).split('/')) {
            val current = node
            node = when (current) {
                // A name written without the escaping (a generic type's angle quotes, a literal `%`) is tried as typed too.
                is JsonObject -> current[unescape(percentDecode(raw))] ?: current[unescape(raw)]
                is JsonArray -> raw.toIntOrNull()?.let { current.getOrNull(it) }
                else -> null
            } ?: return null
        }
        return node
    }

    /**
     * [node], or what its `$ref` chain leads to: how the Reference Objects standing in for parameters,
     * request bodies, path items, examples and security schemes are read. Null for a non-object, a
     * dangling reference or a loop.
     */
    fun deref(node: JsonElement?): JsonObject? {
        var current = node as? JsonObject ?: return null
        val seen = HashSet<String>()
        while (true) {
            val ref = current[REF].asText() ?: return current
            if (!seen.add(ref)) return null
            current = resolve(ref) as? JsonObject ?: return null
        }
    }

    /** `value` of the first usable entry of an OpenAPI 3 `examples` map (Example Objects, `$ref` allowed). */
    fun exampleValue(examples: JsonElement?): JsonElement? =
        (examples as? JsonObject)?.values?.firstNotNullOfOrNull { deref(it)?.get("value").orAbsent() }

    companion object {
        /** Deepest nesting accepted, so the recursive walks over the model cannot exhaust the stack. */
        internal const val MAX_DEPTH = 256

        /**
         * Parses a JSON or YAML document into the JSON model.
         * @throws IllegalArgumentException saying why the text is not a usable document.
         */
        fun parse(text: String): OpenApiDocument {
            val source = text.removePrefix("\uFEFF")
            validateSourceSize(source.length)
            val start = source.trimStart()
            require(start.isNotEmpty()) { "The document is empty" }
            require(!start.startsWith("<")) {
                "The document looks like HTML or XML, not an OpenAPI/Swagger definition in JSON or YAML"
            }
            val jsonError: String? = if (start.startsWith("{")) {
                try {
                    val json = Json.parseToJsonElement(source)
                    requireBoundedDepth(json)
                    return OpenApiDocument(json.jsonObject)
                } catch (e: SerializationException) {
                    e.message?.lineSequence()?.firstOrNull() ?: "invalid JSON"
                } catch (_: StackOverflowError) {
                    // The JSON parser recurses on nested arrays, and a hostile document can out-nest the stack.
                    throw IllegalArgumentException("The document is nested more than $MAX_DEPTH levels deep")
                }
            } else {
                null
            }
            // Not JSON: YAML, which also reads a flow-style document that only looks like JSON.
            val node = try {
                composeYaml(source)
            } catch (e: YAMLException) {
                val yamlError = e.message?.take(MAX_ERROR_LENGTH) ?: "invalid YAML"
                throw IllegalArgumentException(
                    if (jsonError != null) "The document is neither valid JSON ($jsonError) nor valid YAML ($yamlError)"
                    else "The document is not valid YAML: $yamlError"
                )
            }
            val converted = node?.let { YamlToJson().convert(it) }
            return OpenApiDocument(
                converted as? JsonObject
                    ?: throw IllegalArgumentException("The document is not a JSON or YAML object at the top level")
            )
        }

        internal fun validateSourceSize(length: Int, maxChars: Long = MAX_YAML_CHARS) {
            require(length <= maxChars) {
                "The document exceeds ${maxChars shr 20} MiB ($length chars)"
            }
        }

        private fun composeYaml(source: String): Node? {
            val options = LoaderOptions().apply {
                codePointLimit = MAX_YAML_CHARS.toInt()
                nestingDepthLimit = MAX_DEPTH
                maxAliasesForCollections = Int.MAX_VALUE // YamlToJson bounds what aliases expand to instead
            }
            // Only the node graph is composed; the safe constructor is never asked to build objects from tags.
            return Yaml(SafeConstructor(options), Representer(DumperOptions()), DumperOptions(), options, CoreSchemaResolver())
                .compose(StringReader(source))
        }

        private fun requireBoundedDepth(root: JsonElement) {
            var level: List<JsonElement> = listOf(root)
            var depth = 0
            while (level.isNotEmpty()) {
                require(++depth <= MAX_DEPTH) { "The document is nested more than $MAX_DEPTH levels deep" }
                val next = ArrayList<JsonElement>()
                for (node in level) {
                    val children: Collection<JsonElement> = when (node) {
                        is JsonObject -> node.values
                        is JsonArray -> node
                        else -> emptyList()
                    }
                    children.filterTo(next) { it is JsonObject || it is JsonArray }
                }
                level = next
            }
        }
    }
}

private const val MAX_ERROR_LENGTH = 400
private const val MAX_YAML_VALUES = 10_000_000L

/** Text the YAML document may expand to, scalars and mapping keys together: 64 MiB. */
private const val MAX_YAML_CHARS = 64L shl 20

/** JSON Pointer token escapes (RFC 6901): `~1` is `/` and `~0` is `~`, decoded in that order. */
private fun unescape(token: String): String = token.replace("~1", "/").replace("~0", "~")

/** Decodes the `%XX` escapes a pointer carries as a URI fragment; a malformed escape is kept as typed. */
private fun percentDecode(text: String): String {
    if ('%' !in text) return text
    val bytes = ByteArrayOutputStream(text.length)
    var i = 0
    while (i < text.length) {
        val high = if (text[i] == '%' && i + 2 < text.length) Character.digit(text[i + 1], 16) else -1
        val low = if (high >= 0) Character.digit(text[i + 2], 16) else -1
        if (low >= 0) {
            bytes.write((high shl 4) or low)
            i += 3
        } else {
            val end = text.offsetByCodePoints(i, 1)
            bytes.write(text.substring(i, end).toByteArray(Charsets.UTF_8))
            i = end
        }
    }
    return bytes.toString(Charsets.UTF_8)
}

private val YAML_BOOL = Pattern.compile("^(?:true|True|TRUE|false|False|FALSE)$")
private val YAML_INT = Pattern.compile("^[-+]?(?:0|[1-9][0-9]*)$")
private val YAML_FLOAT = Pattern.compile(
    "^[-+]?(?:(?:0|[1-9][0-9]*)\\.[0-9]*(?:[eE][-+]?[0-9]+)?|\\.[0-9]+(?:[eE][-+]?[0-9]+)?|(?:0|[1-9][0-9]*)[eE][-+]?[0-9]+)$"
)
private val YAML_NULL = Pattern.compile("^(?:~|null|Null|NULL)$")

/**
 * Implicit scalar types of the YAML 1.2 core schema, which OpenAPI prescribes. SnakeYAML's default
 * resolver follows YAML 1.1 and would read `no`, `0755`, `12:30` and `2020-01-01` as a boolean, two
 * numbers and a date, silently changing enum values and examples.
 */
private class CoreSchemaResolver : Resolver() {
    // Called from the superclass constructor: it may only touch file-level state.
    override fun addImplicitResolvers() {
        addImplicitResolver(Tag.BOOL, YAML_BOOL, "tTfF", 10)
        addImplicitResolver(Tag.INT, YAML_INT, "-+0123456789")
        addImplicitResolver(Tag.FLOAT, YAML_FLOAT, "-+0123456789.")
        addImplicitResolver(Tag.MERGE, Resolver.MERGE, "<", 10)
        addImplicitResolver(Tag.NULL, YAML_NULL, "~nN", 10)
        addImplicitResolver(Tag.NULL, Resolver.EMPTY, null, 10)
    }
}

/**
 * Converts a composed YAML node graph to the JSON model. An aliased node is converted once and shared,
 * so anchors cost nothing, while the value count, the text (scalars and mapping keys) and the depth are
 * still those of the tree with every alias expanded: an alias bomb, including one that repeats a long
 * scalar, is refused here rather than blown up by a later walk or rendering. Mapping keys are taken as
 * their literal text, `<<` merge keys are applied, tags other than the JSON types are read as plain data.
 */
private class YamlToJson {
    private class Shared(val element: JsonElement, val values: Long, val chars: Long, val height: Int)

    private val shared = IdentityHashMap<Node, Shared>()
    private val open = IdentityHashMap<Node, Unit>()
    private var values = 0L
    private var chars = 0L

    /** Collection levels in the element [convert] returned last. */
    private var height = 0

    fun convert(node: Node, depth: Int = 1): JsonElement {
        shared[node]?.let {
            count(it.values, it.chars)
            requireDepth(depth + it.height - 1)
            height = it.height
            return it.element
        }
        if (node is ScalarNode) {
            val length = node.value.length.toLong()
            count(1, length)
            height = 0
            val element = scalar(node)
            // Only an anchored scalar can be aliased: its text is then read once, however often it is repeated.
            if (node.anchor != null) shared[node] = Shared(element, 1, length, 0)
            return element
        }
        count(1, 0)
        requireDepth(depth)
        if (open.put(node, Unit) != null) { // an alias to a collection it sits inside
            height = 0
            return JsonNull
        }
        val valuesBefore = values
        val charsBefore = chars
        var tallest = 0
        val element: JsonElement = try {
            if (node is MappingNode) {
                val entries = LinkedHashMap<String, JsonElement>()
                val merges = ArrayList<JsonObject>()
                for (tuple in node.value) {
                    val key = tuple.keyNode
                    if (key is ScalarNode) count(0, key.value.length.toLong())
                    val value = convert(tuple.valueNode, depth + 1)
                    tallest = maxOf(tallest, height)
                    if (key.tag == Tag.MERGE) {
                        if (value is JsonObject) merges.add(value)
                        else if (value is JsonArray) for (item in value) if (item is JsonObject) merges.add(item)
                    } else if (key is ScalarNode) {
                        entries[key.value] = value
                    }
                }
                // Merged-in keys never replace the mapping's own, and an earlier `<<` source wins over a later one.
                for (source in merges) for ((name, merged) in source) entries.putIfAbsent(name, merged)
                JsonObject(entries)
            } else {
                val items = (node as? SequenceNode)?.value.orEmpty()
                JsonArray(items.map { item -> convert(item, depth + 1).also { tallest = maxOf(tallest, height) } })
            }
        } finally {
            open.remove(node)
        }
        height = tallest + 1
        shared[node] = Shared(element, values - valuesBefore + 1, chars - charsBefore, height)
        return element
    }

    private fun scalar(node: ScalarNode): JsonElement {
        val text = node.value
        return when (node.tag) {
            Tag.NULL -> JsonNull
            Tag.BOOL -> text.lowercase().toBooleanStrictOrNull()?.let { JsonPrimitive(it) }
            Tag.INT -> integer(text)?.let { JsonPrimitive(it) }
            Tag.FLOAT -> text.toBigDecimalOrNull()?.let { JsonPrimitive(it) }
            else -> null
        } ?: JsonPrimitive(text)
    }

    private fun integer(text: String): Number? = text.toLongOrNull() ?: text.toBigIntegerOrNull()

    private fun count(addedValues: Long, addedChars: Long) {
        values += addedValues
        chars += addedChars
        require(values <= MAX_YAML_VALUES) {
            "The YAML document expands to more than $MAX_YAML_VALUES values (aliases nested too deeply)"
        }
        require(chars <= MAX_YAML_CHARS) {
            "The YAML document expands to more than ${MAX_YAML_CHARS shr 20} MiB of text (aliases repeat too much of it)"
        }
    }

    private fun requireDepth(depth: Int) = require(depth <= OpenApiDocument.MAX_DEPTH) {
        "The document is nested more than ${OpenApiDocument.MAX_DEPTH} levels deep"
    }
}
