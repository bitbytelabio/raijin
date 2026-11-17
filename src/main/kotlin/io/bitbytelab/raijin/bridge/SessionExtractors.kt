package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.safety.SafeRegex
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.w3c.dom.Node
import org.w3c.dom.NodeList
import org.xml.sax.Attributes
import org.xml.sax.ErrorHandler
import org.xml.sax.InputSource
import org.xml.sax.SAXException
import org.xml.sax.SAXParseException
import org.xml.sax.helpers.DefaultHandler
import java.io.StringReader
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.SAXParserFactory
import javax.xml.xpath.XPathConstants
import javax.xml.xpath.XPathFactory

/**
 * A JSONPath subset, enough to point at a value in a JSON response or request body:
 *
 * - `$` root (optional: `data.token` is read as `$.data.token`);
 * - `.name`, `['name']`, `["name"]` member;
 * - `[2]`, `[-1]` array element (negative counts from the end);
 * - `.*`, `[*]` every member or element;
 * - `..name`, `..[0]`, `..*` the same, at any depth below.
 *
 * Filters, slices and unions are not supported.
 */
internal object JsonPathLite {

    sealed class Step {
        /** Applies below the current node at any depth, not only to the node itself. */
        abstract val deep: Boolean

        data class Key(val name: String, override val deep: Boolean) : Step()
        data class Index(val index: Int, override val deep: Boolean) : Step()
        data class Wildcard(override val deep: Boolean) : Step()
    }

    /** Largest body parsed for a path: a session rule runs on Burp's HTTP threads. */
    const val MAX_DOCUMENT_CHARS = 2_000_000

    /** Largest object/array nesting depth: kotlinx's tree reader recurses with no depth guard of
     *  its own, so a document whose depth alone (regardless of [MAX_DOCUMENT_CHARS]) is enough to
     *  overflow the stack must be rejected before it ever reaches `Json.parseToJsonElement`. Matches
     *  [io.bitbytelab.raijin.bridge.JsonLeafSpans]'s bound. */
    private const val MAX_DEPTH = 256

    /** True once [json]'s object/array nesting would exceed [MAX_DEPTH], scanned without building a tree. */
    fun exceedsMaxDepth(json: String): Boolean {
        var depth = 0
        var inString = false
        var escaped = false
        for (ch in json) {
            if (inString) {
                when {
                    escaped -> escaped = false
                    ch == '\\' -> escaped = true
                    ch == '"' -> inString = false
                }
                continue
            }
            when (ch) {
                '"' -> inString = true
                '{', '[' -> { depth++; if (depth > MAX_DEPTH) return true }
                '}', ']' -> depth--
            }
        }
        return false
    }

    /**
     * Parses [path].
     * @throws IllegalArgumentException saying where it stops being a supported path.
     */
    fun parse(path: String): List<Step> {
        val text = path.trim()
        require(text.isNotEmpty()) { "JSONPath is empty" }
        val steps = ArrayList<Step>()
        var i = 0
        if (text[0] == '$') {
            i = 1
        } else if (text[0] != '.' && text[0] != '[') {
            // A bare first name: "data.token".
            val end = nameEnd(text, 0)
            steps += Step.Key(text.substring(0, end), deep = false)
            i = end
        }
        while (i < text.length) {
            when (text[i]) {
                '.' -> {
                    i++
                    val deep = i < text.length && text[i] == '.'
                    if (deep) i++
                    require(i < text.length) { "JSONPath '$path' ends after a '.'" }
                    when {
                        text[i] == '[' -> {
                            require(deep) { "JSONPath '$path': '.[' at offset ${i - 1}; write '[' or '..['" }
                            i = bracket(text, i, true, steps, path)
                        }
                        text[i] == '*' -> {
                            steps += Step.Wildcard(deep)
                            i++
                        }
                        else -> {
                            val end = nameEnd(text, i)
                            require(end > i) { "JSONPath '$path': a name is expected at offset $i" }
                            steps += Step.Key(text.substring(i, end), deep)
                            i = end
                        }
                    }
                }
                '[' -> i = bracket(text, i, false, steps, path)
                else -> throw IllegalArgumentException("JSONPath '$path': unexpected '${text[i]}' at offset $i")
            }
        }
        return steps
    }

    private fun nameEnd(text: String, from: Int): Int {
        var i = from
        while (i < text.length && text[i] != '.' && text[i] != '[') i++
        return i
    }

    /** Parses the `[...]` that opens at [open]; returns the offset after its `]`. */
    private fun bracket(text: String, open: Int, deep: Boolean, steps: MutableList<Step>, path: String): Int {
        var i = open + 1
        require(i < text.length) { "JSONPath '$path': '[' is not closed" }
        val quote = text[i]
        if (quote == '\'' || quote == '"') {
            val name = StringBuilder()
            i++
            while (true) {
                require(i < text.length) { "JSONPath '$path': quoted name is not closed" }
                val c = text[i++]
                if (c == quote) break
                if (c == '\\' && i < text.length) name.append(text[i++]) else name.append(c)
            }
            require(i < text.length && text[i] == ']') { "JSONPath '$path': ']' is expected at offset $i" }
            steps += Step.Key(name.toString(), deep)
            return i + 1
        }
        val close = text.indexOf(']', i)
        require(close > i) { "JSONPath '$path': '[' at offset $open needs an index, '*' or a quoted name" }
        val inner = text.substring(i, close).trim()
        steps += if (inner == "*") {
            Step.Wildcard(deep)
        } else {
            Step.Index(
                inner.toIntOrNull() ?: throw IllegalArgumentException(
                    "JSONPath '$path': '[$inner]' is not an index, '*' or a quoted name (filters and slices are not supported)"
                ),
                deep,
            )
        }
        return close + 1
    }

    /** Every element [steps] select below [root], in document order. */
    fun select(root: JsonElement, steps: List<Step>): List<JsonElement> {
        var current = listOf(root)
        for (step in steps) {
            val next = ArrayList<JsonElement>()
            for (node in current) {
                if (step.deep) descend(node) { apply(it, step, next) } else apply(node, step, next)
            }
            if (next.isEmpty()) return next
            current = next
        }
        return current
    }

    private fun apply(node: JsonElement, step: Step, into: MutableList<JsonElement>) {
        when (step) {
            is Step.Key -> (node as? JsonObject)?.get(step.name)?.let { into += it }
            is Step.Index -> (node as? JsonArray)?.let { array ->
                val at = if (step.index < 0) array.size + step.index else step.index
                array.getOrNull(at)?.let { into += it }
            }
            is Step.Wildcard -> when (node) {
                is JsonObject -> into.addAll(node.values)
                is JsonArray -> into.addAll(node)
                else -> Unit
            }
        }
    }

    /** [node] and everything below it, parents first. */
    private fun descend(node: JsonElement, visit: (JsonElement) -> Unit) {
        visit(node)
        when (node) {
            is JsonObject -> node.values.forEach { descend(it, visit) }
            is JsonArray -> node.forEach { descend(it, visit) }
            else -> Unit
        }
    }

    /**
     * The first value [path] selects in the JSON document [json] as text: a string's content, a
     * number or boolean as written, an object or array as compact JSON. Null when [json] is not
     * JSON, the path selects nothing, or it selects JSON `null`.
     */
    fun first(json: String, path: String): String? {
        if (json.length > MAX_DOCUMENT_CHARS || exceedsMaxDepth(json)) return null
        val steps = try { parse(path) } catch (_: IllegalArgumentException) { return null }
        val root = try { Json.parseToJsonElement(json) } catch (_: Exception) { return null }
        return select(root, steps).firstNotNullOfOrNull(::text)
    }

    private fun text(element: JsonElement): String? = when (element) {
        is JsonNull -> null
        is JsonPrimitive -> element.content
        else -> element.toString()
    }
}

/**
 * XPath 1.0 over an XML (or XHTML) body, with the JDK's own parser.
 *
 * The document comes from the target, so nothing outside it is ever fetched: external entities
 * and DTDs are not loaded and entity expansion is limited. Namespaces are ignored on purpose, so
 * `//token` also finds `<token xmlns="urn:x">`; an element written with a prefix (`<ns:token>`)
 * is matched by its local name: `//node()[local-name()='token']`. HTML that is not well-formed
 * XML does not parse: use a regex there.
 */
internal object XmlXPath {

    const val MAX_DOCUMENT_CHARS = JsonPathLite.MAX_DOCUMENT_CHARS
    const val MAX_DEPTH = 256

    private class DepthExceededException : SAXException("XML element depth exceeds $MAX_DEPTH")

    private val quietErrors = object : ErrorHandler {
        override fun warning(exception: SAXParseException) = Unit
        override fun error(exception: SAXParseException) = Unit
        override fun fatalError(exception: SAXParseException) = throw exception
    }

    /** Why [expression] is not valid XPath, or null when it compiles. */
    fun validate(expression: String): String? = try {
        xpathFactory().newXPath().compile(expression)
        null
    } catch (e: Exception) {
        e.cause?.message ?: e.message ?: "invalid XPath expression"
    }

    /**
     * The first thing [expression] selects in [xml] as text: a node's text content, or the result
     * of a string/number/boolean expression such as `string(//id/@value)`. Null when [xml] does
     * not parse, the expression is invalid, or the result is empty.
     */
    fun first(xml: String, expression: String): String? {
        if (xml.isBlank() || xml.length > MAX_DOCUMENT_CHARS) return null
        return try {
            if (exceedsMaxDepth(xml)) return null
            val document = builderFactory().newDocumentBuilder().apply {
                setEntityResolver { _, _ -> InputSource(StringReader("")) }
                setErrorHandler(quietErrors)
            }.parse(InputSource(StringReader(xml)))
            val xpath = xpathFactory().newXPath()
            val value = try {
                val nodes = xpath.evaluate(expression, document, XPathConstants.NODESET) as NodeList
                if (nodes.length == 0) null else nodeText(nodes.item(0))
            } catch (_: Exception) {
                // Not a node-set expression: string(), count(), concat(), ...
                xpath.evaluate(expression, document)
            }
            value?.takeIf { it.isNotEmpty() }
        } catch (_: Exception) {
            null
        }
    }

    private fun nodeText(node: Node): String? = node.textContent ?: node.nodeValue

    /*
     * The JDK's own implementations, whatever JAXP provider a library on the class path registers.
     * `newDefaultInstance` (Java 9) is looked up reflectively because the JAXP 1.4 classes bundled
     * in jython-standalone are what the compiler sees for `javax.xml`; at run time the JDK's win.
     */
    private fun xpathFactory(): XPathFactory =
        runCatching { XPathFactory::class.java.getMethod("newDefaultInstance").invoke(null) as XPathFactory }
            .getOrElse { XPathFactory.newInstance() }

    private fun builderFactory(): DocumentBuilderFactory {
        val factory = runCatching {
            DocumentBuilderFactory::class.java.getMethod("newDefaultInstance").invoke(null) as DocumentBuilderFactory
        }.getOrElse { DocumentBuilderFactory.newInstance() }
        factory.isNamespaceAware = false
        factory.isXIncludeAware = false
        factory.isExpandEntityReferences = false
        // Each is tried on its own: a parser that lacks one must not lose the others.
        runCatching { factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true) }
        runCatching { factory.setFeature("http://xml.org/sax/features/external-general-entities", false) }
        runCatching { factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false) }
        runCatching { factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false) }
        runCatching { factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalDTD", "") }
        runCatching { factory.setAttribute("http://javax.xml.XMLConstants/property/accessExternalSchema", "") }
        return factory
    }

    private fun exceedsMaxDepth(xml: String): Boolean {
        val sax = saxParserFactory().newSAXParser()
        runCatching { sax.setProperty("http://javax.xml.XMLConstants/property/accessExternalDTD", "") }
        runCatching { sax.setProperty("http://javax.xml.XMLConstants/property/accessExternalSchema", "") }
        val reader = sax.xmlReader
        reader.setEntityResolver { _, _ -> InputSource(StringReader("")) }
        reader.errorHandler = quietErrors
        var depth = 0
        reader.contentHandler = object : DefaultHandler() {
            override fun startElement(uri: String?, localName: String?, qName: String?, attributes: Attributes?) {
                depth += 1
                if (depth > MAX_DEPTH) throw DepthExceededException()
            }

            override fun endElement(uri: String?, localName: String?, qName: String?) {
                if (depth > 0) depth -= 1
            }
        }
        return try {
            reader.parse(InputSource(StringReader(xml)))
            false
        } catch (_: DepthExceededException) {
            true
        }
    }

    private fun saxParserFactory(): SAXParserFactory {
        val factory = runCatching {
            SAXParserFactory::class.java.getMethod("newDefaultInstance").invoke(null) as SAXParserFactory
        }.getOrElse { SAXParserFactory.newInstance() }
        factory.isNamespaceAware = false
        factory.isXIncludeAware = false
        runCatching { factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true) }
        runCatching { factory.setFeature("http://xml.org/sax/features/external-general-entities", false) }
        runCatching { factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false) }
        runCatching { factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false) }
        return factory
    }
}

/**
 * Picks a value out of a piece of response text: first by JSONPath or XPath when one is given,
 * then by regex (first capture group, or the whole match when the pattern has no group). With
 * both a path and a regex, the regex cuts a part out of what the path selected.
 */
internal object ValueSelector {

    /** @param regex applied last; null or empty for none. */
    fun select(source: String, jsonPath: String?, xpath: String?, regex: String?): String? {
        val selected = when {
            !jsonPath.isNullOrEmpty() -> JsonPathLite.first(source, jsonPath) ?: return null
            !xpath.isNullOrEmpty() -> XmlXPath.first(source, xpath) ?: return null
            else -> source
        }
        if (regex.isNullOrEmpty()) return selected
        val match = SafeRegex.find(regex, selected) ?: return null
        return if (match.groupValues.size > 1) match.groupValues[1] else match.value
    }

    /**
     * Why these selectors can never extract anything (no selector at all, both a JSONPath and an
     * XPath, a path or pattern that does not compile), or null when they are usable. The messages
     * call the selectors [jsonPathName], [xpathName] and [regexName] (the caller's parameter names).
     */
    fun validate(
        jsonPath: String?,
        xpath: String?,
        regex: String?,
        jsonPathName: String = "json_path",
        xpathName: String = "xpath",
        regexName: String = "regex",
    ): String? {
        if (jsonPath.isNullOrEmpty() && xpath.isNullOrEmpty() && regex.isNullOrEmpty()) {
            return "Give $regexName, $jsonPathName or $xpathName to extract the value with"
        }
        if (!jsonPath.isNullOrEmpty() && !xpath.isNullOrEmpty()) return "Give $jsonPathName or $xpathName, not both"
        if (!jsonPath.isNullOrEmpty()) {
            try { JsonPathLite.parse(jsonPath) } catch (e: IllegalArgumentException) { return "$jsonPathName: ${e.message}" }
        }
        if (!xpath.isNullOrEmpty()) XmlXPath.validate(xpath)?.let { return "$xpathName is not valid XPath: $it" }
        if (!regex.isNullOrEmpty()) SafeRegex.validate(regex)?.let { return "$regexName is not a valid regex: $it" }
        return null
    }
}
