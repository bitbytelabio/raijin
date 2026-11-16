package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.bambda.Bambda
import burp.api.montoya.bambda.BambdaImportResult
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.yaml.snakeyaml.Yaml
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The `.bambda` envelope handling of [BambdaBridge] (plan P2.5): which scripts already are an
 * envelope, what a wrapped lambda looks like, that no header value can add a header line, and
 * that the import result names the Bambda's id.
 */
class BambdaBridgeTest {

    private val id = "0d6e7a43-3f0e-4c1f-8a3e-5b1c2d3e4f50"

    private fun wrap(script: String, name: String? = null, function: String? = null, location: String? = null) =
        BambdaBridge.ensureEnvelope(script, id, name, function, location)

    /** Burp's Bambda API: records what it was given and answers with [status] and [errors]. */
    private class FakeBurp(
        private val status: BambdaImportResult.Status = BambdaImportResult.Status.LOADED_WITHOUT_ERRORS,
        private val errors: List<String> = emptyList(),
        private val failure: RuntimeException? = null,
    ) {
        val imported = mutableListOf<String>()

        val api: MontoyaApi = run {
            val result = Proxy.newProxyInstance(BambdaImportResult::class.java.classLoader, arrayOf(BambdaImportResult::class.java)) { _, method, _ ->
                when (method.name) {
                    "status" -> status
                    "importErrors" -> errors
                    else -> error("unexpected BambdaImportResult.${method.name}")
                }
            }
            val bambda = Proxy.newProxyInstance(Bambda::class.java.classLoader, arrayOf(Bambda::class.java)) { _, method, args ->
                check(method.name == "importBambda") { "unexpected Bambda.${method.name}" }
                failure?.let { throw it }
                imported += args[0] as String
                result
            }
            Proxy.newProxyInstance(MontoyaApi::class.java.classLoader, arrayOf(MontoyaApi::class.java)) { _, method, _ ->
                check(method.name == "bambda") { "unexpected MontoyaApi.${method.name}" }
                bambda
            } as MontoyaApi
        }
    }

    private fun JsonObject.text(key: String): String? = this[key]?.jsonPrimitive?.content

    // ---- wrapping a bare lambda ----------------------------------------------

    @Test
    fun `a bare lambda is wrapped into the envelope Burp writes itself`() {
        val envelope = wrap("return requestResponse.hasResponse();")
        assertEquals(
            """
            id: $id
            name: Raijin $id
            function: VIEW_FILTER
            location: PROXY_HTTP_HISTORY
            source: |+
              return requestResponse.hasResponse();

            """.trimIndent(),
            envelope,
        )
    }

    @Test
    fun `name function and location are used when given`() {
        val header = BambdaBridge.header(wrap("return true;", " Server errors ", "custom_column", " logger "))
        assertEquals("Server errors", header["name"])
        assertEquals("CUSTOM_COLUMN", header["function"])
        assertEquals("LOGGER", header["location"])
    }

    @Test
    fun `the lambda body survives wrapping line for line`() {
        val body = "    if (!requestResponse.hasResponse()) {\n        return false;\n    }\n\n  return true; // less indented than the first line\n"
        val envelope = wrap(body)
        // A YAML reader takes the block's indentation from its first line. Had that line kept its
        // four spaces, the less indented last line would end the block early.
        val source = (Yaml().load<Map<String, Any?>>(envelope))["source"] as String
        assertEquals(
            "if (!requestResponse.hasResponse()) {\n        return false;\n    }\n\n  return true; // less indented than the first line",
            source.trimEnd('\n'),
        )
        // And the line-based reading Burp's own tooling uses sees every source line indented.
        assertTrue(envelope.lines().dropWhile { !it.startsWith("source:") }.drop(1).all { it.isEmpty() || it.startsWith("  ") })
    }

    // ---- recognising an envelope --------------------------------------------

    @Test
    fun `a complete envelope is passed through untouched`() {
        val envelope = "id: $id\nname: Mine\nfunction: VIEW_FILTER\nlocation: LOGGER\nsource: |+\n  return true;\n"
        assertSame(envelope, wrap(envelope, name = "ignored", function = "CUSTOM_COLUMN"))
    }

    @Test
    fun `an envelope that starts with comments or with name is still an envelope`() {
        val commented = "# exported 2026-01-01\n# by me\nid: $id\nname: Mine\nfunction: VIEW_FILTER\nlocation: LOGGER\nsource: |+\n  return true;\n"
        assertSame(commented, wrap(commented))

        val nameFirst = "name: Mine\nlocation: LOGGER\nfunction: VIEW_FILTER\nid: $id\nsource: |\n  return true;\n"
        assertSame(nameFirst, wrap(nameFirst))
    }

    @Test
    fun `an envelope without an id gets one, not a second envelope around it`() {
        val noId = "# my filter\nname: Mine\nfunction: VIEW_FILTER\nlocation: LOGGER\nsource: |+\n  return true;\n"
        val envelope = wrap(noId)

        assertEquals("# my filter\nid: $id\nname: Mine\nfunction: VIEW_FILTER\nlocation: LOGGER\nsource: |+\n  return true;\n", envelope)
        assertEquals(1, envelope.lines().count { it.startsWith("source:") }, "wrapped twice:\n$envelope")
    }

    @Test
    fun `header lines an envelope lacks come from the parameters or the defaults`() {
        val partial = "name: Mine\nsource: |+\n  return true;\n"
        val header = BambdaBridge.header(wrap(partial, name = "ignored", function = "custom_column"))
        assertEquals(id, header["id"])
        assertEquals("Mine", header["name"], "the envelope's own value wins")
        assertEquals("CUSTOM_COLUMN", header["function"])
        assertEquals("PROXY_HTTP_HISTORY", header["location"])
    }

    @Test
    fun `an envelope pasted with a uniform indentation is recognised`() {
        val indented = "    id: $id\n    name: Mine\n    function: VIEW_FILTER\n    location: LOGGER\n    source: |+\n      return true;\n"
        assertEquals("id: $id\nname: Mine\nfunction: VIEW_FILTER\nlocation: LOGGER\nsource: |+\n  return true;", wrap(indented))
    }

    @Test
    fun `java that merely looks like a header line is still a lambda`() {
        val labelled = "source:\nfor (var h : requestResponse.request().headers()) {\n    if (h.name().isEmpty()) break source;\n}\nreturn true;"
        val wrapped = wrap(labelled)
        assertTrue(wrapped.startsWith("id: $id\n"), "one key cannot make an envelope:\n$wrapped")
        assertTrue("source: |+\n  source:\n  for (var h" in wrapped, wrapped)

        val commented = "  // id: 5\n  // name: x\n  return true;"
        assertTrue(wrap(commented).startsWith("id: $id\nname: Raijin $id\n"))
    }

    // ---- header values cannot add header lines ---------------------------------

    @Test
    fun `a name with line breaks stays one header line`() {
        val envelope = wrap("return true;", name = "Mine\r\nfunction: CUSTOM_ACTION\nsource: |\nevil();\n")
        val header = BambdaBridge.header(envelope)
        assertEquals("VIEW_FILTER", header["function"], "the name must not be able to set the function")
        assertEquals("Mine function: CUSTOM_ACTION source: | evil();", header["name"])
        assertEquals(1, envelope.lines().count { it.startsWith("source:") })
        assertFalse("evil();" in envelope.substringAfter("source: |+"), envelope)
    }

    @Test
    fun `a name is written as Burp writes names, without quoting`() {
        // The format is line-based: the value is the rest of the line, and quotes would become part of the name.
        val header = BambdaBridge.header(wrap("return true;", name = "RepeaterClip: New \"from\" #clipboard"))
        assertEquals("RepeaterClip: New \"from\" #clipboard", header["name"])
    }

    @Test
    fun `a blank name falls back to the default`() {
        assertEquals("Raijin $id", BambdaBridge.header(wrap("return true;", name = " \n "))["name"])
    }

    @Test
    fun `function and location must each be one name`() {
        assertFailsWith<IllegalArgumentException> { wrap("return true;", function = "VIEW_FILTER\nid: 1") }
        assertFailsWith<IllegalArgumentException> { wrap("return true;", location = "LOGGER # note") }
        assertFailsWith<IllegalArgumentException> { wrap("return true;", function = "view filter") }
    }

    @Test
    fun `the header is read the way the format defines it`() {
        val header = BambdaBridge.header("# name: not this\n  id: nor this\nname: first\nfunction:VIEW_FILTER\nname:  second  \nsource: |+\n  name: body\n")
        assertEquals(mapOf("name" to "second", "function" to "VIEW_FILTER", "source" to "|+"), header)
    }

    // ---- the import result ------------------------------------------------------

    @Test
    fun `the import result carries the id and the header as submitted`() {
        val ok = BambdaBridge.buildImportResponse(false, emptyList(), 120, id = id, name = "Mine", function = "VIEW_FILTER", location = "LOGGER")
        assertEquals("imported", ok.text("status"))
        assertEquals(id, ok.text("id"))
        assertEquals("Mine", ok.text("name"))
        assertEquals("VIEW_FILTER", ok.text("function"))
        assertEquals("LOGGER", ok.text("location"))
        assertNull(ok["error"])

        val broken = BambdaBridge.buildImportResponse(true, listOf("line 1: ';' expected"), 120, id = id)
        assertEquals("imported_with_errors", broken.text("status"))
        assertEquals(id, broken.text("id"), "the id is needed to re-import a fixed version over the broken one")
        assertTrue(broken.text("error")!!.contains("import_errors"))
    }

    @Test
    fun `importing a bare lambda submits an envelope and returns the generated id`() {
        val burp = FakeBurp()
        val result = BambdaBridge(burp.api).importBambda("return true;", name = "Mine", location = "logger")

        val submitted = BambdaBridge.header(burp.imported.single())
        assertEquals(submitted["id"], result.text("id"))
        assertEquals(36, result.text("id")!!.length, "a UUID")
        assertEquals("Mine", result.text("name"))
        assertEquals("VIEW_FILTER", result.text("function"))
        assertEquals("LOGGER", result.text("location"))
        assertEquals("imported", result.text("status"))
    }

    @Test
    fun `importing an envelope returns the id it already has`() {
        val burp = FakeBurp()
        val envelope = "name: Mine\nid: $id\nfunction: VIEW_FILTER\nlocation: LOGGER\nsource: |+\n  return true;\n"
        val result = BambdaBridge(burp.api).importBambda(envelope)
        assertEquals(id, result.text("id"))
        assertEquals(envelope, burp.imported.single())
    }

    @Test
    fun `a Bambda that does not compile is an error that still names its id`() {
        val burp = FakeBurp(BambdaImportResult.Status.LOADED_WITH_ERRORS, listOf("cannot find symbol"))
        val result = BambdaBridge(burp.api).importBambda("return nope;")
        assertEquals("imported_with_errors", result.text("status"))
        assertEquals(listOf("cannot find symbol"), result.getValue("import_errors").jsonArray.map { it.jsonPrimitive.content })
        assertTrue(result.containsKey("error"))
        assertEquals(36, result.text("id")!!.length)
    }

    @Test
    fun `a header value Burp could not read is refused before anything is imported`() {
        val burp = FakeBurp()
        val result = BambdaBridge(burp.api).importBambda("return true;", function = "VIEW_FILTER\nlocation: SCANNER")
        assertTrue(result.text("error")!!.contains("function"), result.toString())
        assertTrue(burp.imported.isEmpty())
    }

    @Test
    fun `a Burp without the Bambda API says so`() {
        val result = BambdaBridge(FakeBurp(failure = UnsupportedOperationException()).api).importBambda("return true;")
        assertEquals("false", result.text("available"))
        assertTrue(result.containsKey("error"))
    }

    // ---- templates -------------------------------------------------------------

    @Test
    fun `every template can be imported as it is listed`() {
        val templates = BambdaBridge.templates()
        val locationsOf = templates.getValue("functions").jsonArray.associate { entry ->
            val function = entry.jsonObject
            function.text("function")!! to function.getValue("locations").jsonArray.map { it.jsonPrimitive.content }
        }
        val listed = templates.getValue("templates").jsonArray.map { it.jsonObject }
        assertTrue(listed.size >= 8, "one starting point per kind of Bambda")

        for (template in listed) {
            val name = template.text("name")!!
            val function = template.text("function")!!
            val location = template.text("location")!!
            assertTrue(location in locationsOf.getValue(function), "$name: $function does not run in $location")

            val source = template.text("source")!!
            assertTrue("return" in source || "httpEditor" in source, "$name has no body")
            assertFalse(source.startsWith(" ") || source.startsWith("\n"), "$name is not trimmed:\n$source")

            // What bambda_import would submit for it.
            val header = BambdaBridge.header(wrap(source, name, function, location))
            assertEquals(mapOf("id" to id, "name" to name, "function" to function, "location" to location, "source" to "|+"), header)
        }
        assertEquals(listed.size, listed.map { it.text("name") }.toSet().size, "template names are how they are told apart")
    }

    @Test
    fun `the envelope example is a complete envelope`() {
        val example = BambdaBridge.templates().getValue("envelope").jsonObject.text("example")!!
        assertEquals(setOf("id", "name", "function", "location", "source"), BambdaBridge.header(example).keys)
        assertSame(example, BambdaBridge.ensureEnvelope(example, id, null, null, null))
    }
}
