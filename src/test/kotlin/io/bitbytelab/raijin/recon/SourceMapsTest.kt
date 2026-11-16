package io.bitbytelab.raijin.recon

import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SourceMapsTest {

    private val map = """
        {"version":3,"file":"app.js","sourceRoot":"webpack://app",
         "sources":["./src/api/users.js","./src/index.js"],
         "sourcesContent":["export const list = () => fetch('/api/v2/users');\nexport const one = id => fetch(`/api/v2/users/${'$'}{id}`);", null],
         "mappings":"AAAA"}
    """.trimIndent()

    @Test
    fun `the map reference is read from the script's trailing comment`() {
        assertEquals("app.js.map", SourceMaps.reference("x();\n//# sourceMappingURL=app.js.map"))
        assertEquals("app.js.map", SourceMaps.reference("x();\n//# sourceMappingURL=app.js.map\n"))
        assertEquals("legacy.map", SourceMaps.reference("x();\n//@ sourceMappingURL=legacy.map"))
        assertEquals("style.css.map", SourceMaps.reference("a{}\n/*# sourceMappingURL=style.css.map */"))
        assertEquals("style.css.map", SourceMaps.reference("a{}\n/*# sourceMappingURL=style.css.map*/"))
        assertEquals("https://cdn.example/maps/app.js.map?v=2", SourceMaps.reference("//#  sourceMappingURL=https://cdn.example/maps/app.js.map?v=2"))
        // The last one counts, as in a browser.
        assertEquals("b.map", SourceMaps.reference("//# sourceMappingURL=a.map\ny();\n//# sourceMappingURL=b.map"))
    }

    @Test
    fun `text that only mentions the marker has no map reference`() {
        assertNull(SourceMaps.reference("no reference here"))
        assertNull(SourceMaps.reference("var s = \"sourceMappingURL=x.map\";"))
        assertNull(SourceMaps.reference("docs: set sourceMappingURL=app.js.map"))
        assertNull(SourceMaps.reference("//# sourceMappingURL="))
    }

    @Test
    fun `the map reference is read from response headers`() {
        assertEquals("/static/app.js.map", SourceMaps.headerReference(mapOf("sourcemap" to " /static/app.js.map ")))
        assertEquals("old.map", SourceMaps.headerReference(mapOf("x-sourcemap" to "old.map")))
        assertNull(SourceMaps.headerReference(mapOf("content-type" to "text/javascript")))
        assertNull(SourceMaps.headerReference(mapOf("sourcemap" to "  ")))
    }

    @Test
    fun `a map URL is recognised by its path`() {
        assertTrue(SourceMaps.isMapUrl("https://t.example/static/app.js.map?v=1"))
        assertTrue(SourceMaps.isMapUrl("https://t.example/static/APP.CSS.MAP"))
        assertFalse(SourceMaps.isMapUrl("https://t.example/static/app.js"))
        assertFalse(SourceMaps.isMapUrl("https://t.example/sitemap?x=a.map"))
    }

    @Test
    fun `a reference is resolved against the script that carries it`() {
        val script = "https://t.example/static/js/app.js?v=3"
        assertEquals("https://t.example/static/js/app.js.map", SourceMaps.resolve(script, "app.js.map"))
        assertEquals("https://t.example/static/maps/app.js.map", SourceMaps.resolve(script, "../maps/app.js.map"))
        assertEquals("https://t.example/maps/app.js.map", SourceMaps.resolve(script, "/maps/app.js.map"))
        assertEquals("https://cdn.example/app.js.map", SourceMaps.resolve(script, "https://cdn.example/app.js.map"))
        assertEquals("https://cdn.example/app.js.map", SourceMaps.resolve(script, "//cdn.example/app.js.map"))
        assertNull(SourceMaps.resolve(script, "data:application/json;base64,e30="))
        assertNull(SourceMaps.resolve(script, "  "))
        // A script URL java.net.URI refuses is still resolved.
        assertEquals("https://t.example/js/app.js.map", SourceMaps.resolve("https://t.example/js/app|v2.js", "./app.js.map"))
    }

    @Test
    fun `an inline map is decoded from its data URI`() {
        val encoded = Base64.getEncoder().encodeToString("{\"version\":3}".toByteArray())
        assertEquals("{\"version\":3}", SourceMaps.inline("data:application/json;charset=utf-8;base64,$encoded"))
        assertEquals("{\"version\":3}", SourceMaps.inline("data:application/json,%7B%22version%22%3A3%7D"))
        assertNull(SourceMaps.inline("app.js.map"))
        assertNull(SourceMaps.inline("data:application/json;base64"))
    }

    @Test
    fun `a map gives its source files and the endpoints in their embedded text`() {
        val parsed = assertNotNull(SourceMaps.parse(map))
        assertEquals(listOf("webpack://app/./src/api/users.js", "webpack://app/./src/index.js"), parsed.sources)
        assertEquals(1, parsed.sourcesWithContent)
        assertEquals(setOf("/api/v2/users", "/api/v2/users/{id}"), parsed.endpoints)
        assertTrue(parsed.complete)
    }

    @Test
    fun `an index map is read section by section`() {
        val index = """
            {"version":3,"sections":[
              {"offset":{"line":0,"column":0},"map":{"version":3,"sources":["a.js"],"sourcesContent":["get('/a/one')"],"mappings":""}},
              {"offset":{"line":9,"column":0},"map":{"version":3,"sources":["b.js"],"sourcesContent":["get('/b/two')"],"mappings":""}}
            ]}
        """.trimIndent()
        val parsed = assertNotNull(SourceMaps.parse(index))
        assertEquals(listOf("a.js", "b.js"), parsed.sources)
        assertEquals(setOf("/a/one", "/b/two"), parsed.endpoints)
        assertEquals(2, parsed.sourcesWithContent)
    }

    @Test
    fun `a map behind an anti-hijacking prefix is still read`() {
        val parsed = assertNotNull(SourceMaps.parse(")]}'\n$map"))
        assertEquals(2, parsed.sources.size)
    }

    @Test
    fun `what is not a source map is not parsed as one`() {
        assertNull(SourceMaps.parse("{\"a\":1}"))
        assertNull(SourceMaps.parse("not json"))
        assertNull(SourceMaps.parse("[1,2,3]"))
        assertNull(SourceMaps.parse(""))
    }

    @Test
    fun `a map read without time left lists its sources and says the endpoints are incomplete`() {
        val parsed = assertNotNull(SourceMaps.parse(map, budgetMs = 0))
        assertEquals(2, parsed.sources.size)
        assertFalse(parsed.complete)
        assertTrue(parsed.endpoints.isEmpty())
    }
}
