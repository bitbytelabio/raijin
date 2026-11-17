package io.bitbytelab.raijin.bridge

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SessionExtractorsTest {

    private val doc = """
        {"data": {"token": "t-1", "ttl": 300, "ok": true, "none": null, "a.b": "dotted", "nested": {"token": "t-2"}},
         "items": [{"id": 7}, {"id": 8}], "list": ["x", "y"]}
    """.trimIndent()

    @Test
    fun `JSONPath selects members, indices, wildcards and descendants`() {
        assertEquals("t-1", JsonPathLite.first(doc, "$.data.token"))
        assertEquals("t-1", JsonPathLite.first(doc, "data.token"))
        assertEquals("t-1", JsonPathLite.first(doc, "$['data'][\"token\"]"))
        assertEquals("dotted", JsonPathLite.first(doc, "$.data['a.b']"))
        assertEquals("8", JsonPathLite.first(doc, "$.items[1].id"))
        assertEquals("8", JsonPathLite.first(doc, "$.items[-1].id"))
        assertEquals("7", JsonPathLite.first(doc, "$.items[*].id"))
        assertEquals("t-1", JsonPathLite.first(doc, "$..token"))
        assertEquals(listOf("t-1", "t-2"), JsonPathLite.select(Json.parseToJsonElement(doc), JsonPathLite.parse("$..token")).map { (it as JsonPrimitive).content })
        assertEquals("""{"id":7}""", JsonPathLite.first(doc, "$.items[0]"))
    }

    @Test
    fun `JSONPath gives scalars as written and nothing for null, misses and non-JSON`() {
        assertEquals("300", JsonPathLite.first(doc, "$.data.ttl"))
        assertEquals("true", JsonPathLite.first(doc, "$.data.ok"))
        assertNull(JsonPathLite.first(doc, "$.data.none"))
        assertNull(JsonPathLite.first(doc, "$.data.missing"))
        assertNull(JsonPathLite.first(doc, "$.items[5].id"))
        assertNull(JsonPathLite.first("<html/>", "$.a"))
        assertNull(JsonPathLite.first("{\"a\":\"" + "x".repeat(JsonPathLite.MAX_DOCUMENT_CHARS) + "\"}", "$.a"))
    }

    @Test
    fun `JSONPath parse rejects what it does not support, saying where`() {
        for (bad in listOf("", "$.", "$.a[", "$.a[?(@.x)]", "$.a[1:2]", "$.a.[0]", "$ a")) {
            assertFailsWith<IllegalArgumentException>(bad) { JsonPathLite.parse(bad) }
        }
        val message = assertFailsWith<IllegalArgumentException> { JsonPathLite.parse("$.a[1:2]") }.message.orEmpty()
        assertTrue("filters and slices are not supported" in message, message)
    }

    @Test
    fun `XPath reads elements, attributes and string expressions`() {
        val xml = """<?xml version="1.0"?><r xmlns="urn:x"><token>abc</token><form><input name="csrf" value="c5"/></form><n>4</n></r>"""
        assertEquals("abc", XmlXPath.first(xml, "//token"))
        assertEquals("c5", XmlXPath.first(xml, "//input[@name='csrf']/@value"))
        assertEquals("c5", XmlXPath.first(xml, "string(//input/@value)"))
        assertEquals("4", XmlXPath.first(xml, "count(//input) + 3"))
        assertEquals("p", XmlXPath.first("""<a xmlns:s="urn:s"><s:t>p</s:t></a>""", "//node()[local-name()='t']"))
        assertNull(XmlXPath.first(xml, "//missing"))
        assertNull(XmlXPath.first("<not-closed>", "//x"))
        assertNull(XmlXPath.first("", "//x"))
    }

    @Test
    fun `XPath never fetches an external entity`() {
        val secret = kotlin.io.path.createTempFile("raijin-xxe", ".txt").toFile().apply {
            writeText("TOP-SECRET")
            deleteOnExit()
        }
        val xxe = """<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "${secret.toURI()}">]><r><v>&e;</v></r>"""
        val value = XmlXPath.first(xxe, "//v")
        assertTrue(value == null || "TOP-SECRET" !in value, "external entity was resolved: $value")
    }

    @Test
    fun `XmlXPath validate explains an expression that does not compile`() {
        assertNull(XmlXPath.validate("//a[@b='c']"))
        assertNotNull(XmlXPath.validate("//a[@b="))
    }

    @Test
    fun `ValueSelector applies the path first and the regex to what it selected`() {
        assertEquals("abc", ValueSelector.select("""{"auth":"Bearer abc"}""", "$.auth", null, "Bearer (\\w+)"))
        assertEquals("Bearer abc", ValueSelector.select("""{"auth":"Bearer abc"}""", "$.auth", null, null))
        assertEquals("abc", ValueSelector.select("<a><b>id=abc</b></a>", null, "//b", "id=(\\w+)"))
        assertEquals("42", ValueSelector.select("x id=42 y", null, null, "id=(\\d+)"))
        assertNull(ValueSelector.select("""{"auth":"none"}""", "$.auth", null, "Bearer (\\w+)"))
        assertNull(ValueSelector.select("""{"auth":"Bearer abc"}""", "$.other", null, ".*"))
    }

    @Test
    fun `ValueSelector validate names the offending parameter`() {
        val names = arrayOf("extract_json_path", "extract_xpath", "extract_regex")
        fun validate(jsonPath: String?, xpath: String?, regex: String?) =
            ValueSelector.validate(jsonPath, xpath, regex, names[0], names[1], names[2])

        assertNull(validate("$.a", null, null))
        assertNull(validate(null, "//a", "(x)"))
        assertNull(validate(null, null, "x=(\\d+)"))
        assertEquals("Give extract_regex, extract_json_path or extract_xpath to extract the value with", validate(null, "", ""))
        assertEquals("Give extract_json_path or extract_xpath, not both", validate("$.a", "//a", null))
        assertTrue(validate("$.a[", null, null)!!.startsWith("extract_json_path: "))
        assertTrue(validate(null, "//a[", null)!!.startsWith("extract_xpath is not valid XPath"))
        assertTrue(validate("$.a", null, "(")!!.startsWith("extract_regex is not a valid regex"))
    }

    @Test
    fun `xml xpath refuses deeply nested XML beyond the depth limit`() {
        val overLimit = XmlXPath.MAX_DEPTH + 10
        val xml = "<a>".repeat(overLimit) + "ok" + "</a>".repeat(overLimit)
        assertNull(XmlXPath.first(xml, "//a[last()]/text()"))

        val atLimit = "<a>".repeat(XmlXPath.MAX_DEPTH) + "ok" + "</a>".repeat(XmlXPath.MAX_DEPTH)
        assertEquals("ok", XmlXPath.first(atLimit, "//a[not(a)]/text()"))
    }
}
