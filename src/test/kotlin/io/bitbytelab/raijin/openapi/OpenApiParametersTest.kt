package io.bitbytelab.raijin.openapi

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals

class OpenApiParametersTest {

    private fun json(text: String): JsonElement = Json.parseToJsonElement(text)

    private val plain: (String) -> String = { it }
    private val list = json("[1, 2]")
    private val map = json("""{"a": 1, "b": 2}""")

    private fun style(parameter: String, location: String, swagger2: Boolean = false): Pair<String, Boolean> =
        ParameterStyle.of(json(parameter).jsonObject, location, swagger2).let { it.style to it.explode }

    // --- escaping ---

    @Test
    fun `percentEncode escapes everything but unreserved characters, as UTF-8`() {
        assertEquals("a%20b%2Fc%3Fd%3D%C3%A9%26~-._", percentEncode("a b/c?d=\u00e9&~-._"))
        assertEquals("%F0%9F%98%80", percentEncode("\uD83D\uDE00"))
        assertEquals("100%25", percentEncode("100%"))
    }

    @Test
    fun `percentEncode keeps the characters it is told to`() {
        assertEquals("a/b%20c", percentEncode("a/b c", keep = "/"))
        assertEquals("%41/b", percentEncode("%41/b", keep = "/%"))
    }

    @Test
    fun `formEncode escapes the form way, a space as a plus`() {
        assertEquals("a+b%26c%3Dd%2Be", formEncode("a b&c=d+e"))
    }

    @Test
    fun `a value is written as its text, a container as JSON`() {
        assertEquals("x", json("\"x\"").asFieldText())
        assertEquals("5", json("5").asFieldText())
        assertEquals("true", json("true").asFieldText())
        assertEquals("", JsonNull.asFieldText())
        assertEquals("""{"a":1,"b":2}""", map.asFieldText())
    }

    // --- query, cookie and form parameters ---

    @Test
    fun `form style repeats an exploded array and comma-joins the other`() {
        assertEquals(listOf("ids" to "1", "ids" to "2"), formPairs("ids", list, ParameterStyle("form", true), plain))
        assertEquals(listOf("ids" to "1,2"), formPairs("ids", list, ParameterStyle("form", false), plain))
    }

    @Test
    fun `delimited styles join with their delimiter, escaped like a value`() {
        assertEquals(listOf("ids" to "1%202"), formPairs("ids", list, ParameterStyle("spaceDelimited", false)) { percentEncode(it) })
        assertEquals(listOf("ids" to "1%7C2"), formPairs("ids", list, ParameterStyle("pipeDelimited", false)) { percentEncode(it) })
        // Swagger 2 collectionFormat names
        assertEquals(listOf("ids" to "1+2"), formPairs("ids", list, ParameterStyle("ssv", false), ::formEncode))
        assertEquals(listOf("ids" to "1%7C2"), formPairs("ids", list, ParameterStyle("pipes", false), ::formEncode))
        assertEquals(listOf("ids" to "1%092"), formPairs("ids", list, ParameterStyle("tsv", false)) { percentEncode(it) })
    }

    @Test
    fun `a comma inside a value is escaped, the one joining values is not`() {
        assertEquals(
            listOf("tags" to "a%2Cb,c"),
            formPairs("tags", json("""["a,b", "c"]"""), ParameterStyle("form", false)) { percentEncode(it) }
        )
    }

    @Test
    fun `objects spread into their own keys, a joined list or bracketed names`() {
        assertEquals(listOf("a" to "1", "b" to "2"), formPairs("o", map, ParameterStyle("form", true), plain))
        assertEquals(listOf("o" to "a,1,b,2"), formPairs("o", map, ParameterStyle("form", false), plain))
        assertEquals(listOf("o[a]" to "1", "o[b]" to "2"), formPairs("o", map, ParameterStyle("deepObject", true), plain))
    }

    @Test
    fun `names are escaped like values, and nested containers travel as JSON`() {
        assertEquals(listOf("a+b" to "x+y"), formPairs("a b", json("\"x y\""), ParameterStyle.FORM, ::formEncode))
        assertEquals(
            listOf("items" to """{"k":1}"""),
            formPairs("items", json("""[{"k": 1}]"""), ParameterStyle.FORM, plain)
        )
    }

    // --- path and header parameters ---

    @Test
    fun `simple style comma-joins`() {
        assertEquals("5", pathText("id", json("5"), ParameterStyle("simple", false), plain))
        assertEquals("1,2", pathText("id", list, ParameterStyle("simple", false), plain))
        assertEquals("a,1,b,2", pathText("id", map, ParameterStyle("simple", false), plain))
        assertEquals("a=1,b=2", pathText("id", map, ParameterStyle("simple", true), plain))
    }

    @Test
    fun `label style prefixes a dot`() {
        assertEquals(".5", pathText("id", json("5"), ParameterStyle("label", false), plain))
        assertEquals(".1,2", pathText("id", list, ParameterStyle("label", false), plain))
        assertEquals(".1.2", pathText("id", list, ParameterStyle("label", true), plain))
        assertEquals(".a,1,b,2", pathText("id", map, ParameterStyle("label", false), plain))
        assertEquals(".a=1.b=2", pathText("id", map, ParameterStyle("label", true), plain))
    }

    @Test
    fun `matrix style writes semicolon-prefixed pairs`() {
        assertEquals(";id=5", pathText("id", json("5"), ParameterStyle("matrix", false), plain))
        assertEquals(";id=1,2", pathText("id", list, ParameterStyle("matrix", false), plain))
        assertEquals(";id=1;id=2", pathText("id", list, ParameterStyle("matrix", true), plain))
        assertEquals(";id=a,1,b,2", pathText("id", map, ParameterStyle("matrix", false), plain))
        assertEquals(";a=1;b=2", pathText("id", map, ParameterStyle("matrix", true), plain))
    }

    @Test
    fun `path values are escaped one by one, so a slash cannot add a segment`() {
        assertEquals("a%2Fb,c%20d", pathText("id", json("""["a/b", "c d"]"""), ParameterStyle("simple", false)) { percentEncode(it) })
    }

    @Test
    fun `a Swagger 2 collection format applies to headers too`() {
        assertEquals("1 2", pathText("X-Ids", list, ParameterStyle("ssv", false), plain))
        assertEquals("1|2", pathText("X-Ids", list, ParameterStyle("pipes", false), plain))
    }

    // --- style defaults ---

    @Test
    fun `OpenAPI 3 defaults are form and exploded for query and cookie, simple for path and header`() {
        assertEquals("form" to true, style("{}", "query"))
        assertEquals("form" to true, style("{}", "cookie"))
        assertEquals("simple" to false, style("{}", "path"))
        assertEquals("simple" to false, style("{}", "header"))
        assertEquals("spaceDelimited" to false, style("""{"style": "spaceDelimited"}""", "query"))
        assertEquals("form" to false, style("""{"explode": false}""", "query"))
        assertEquals("simple" to true, style("""{"explode": true}""", "path"))
    }

    @Test
    fun `Swagger 2 collectionFormat defaults to csv, and multi repeats the parameter`() {
        assertEquals("form" to false, style("{}", "query", swagger2 = true))
        assertEquals("form" to false, style("""{"collectionFormat": "csv"}""", "formData", swagger2 = true))
        assertEquals("form" to true, style("""{"collectionFormat": "multi"}""", "query", swagger2 = true))
        assertEquals("pipes" to false, style("""{"collectionFormat": "pipes"}""", "query", swagger2 = true))
        assertEquals("simple" to false, style("{}", "path", swagger2 = true))
    }
}
