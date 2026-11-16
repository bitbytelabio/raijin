package io.bitbytelab.raijin.recon

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JsEndpointsTest {

    @Test
    fun `extracts quoted absolute paths`() {
        val out = JsEndpoints.extract("""fetch("/api/v1/users").then(r=>r.json())""")
        assertTrue("/api/v1/users" in out)
    }

    @Test
    fun `extracts paths with query strings and full urls`() {
        val out = JsEndpoints.extract("""axios.get('/admin/settings?tab=1'); var b='https://api.example.com/v2/data';""")
        assertTrue("/admin/settings?tab=1" in out)
        assertTrue("https://api.example.com/v2/data" in out)
    }

    @Test
    fun `ignores a bare slash and protocol-relative noise`() {
        val out = JsEndpoints.extract("""var a="/"; var b="//cdn.example.com/lib.js";""")
        assertFalse("/" in out)
        assertTrue(out.isEmpty(), out.toString())
    }

    @Test
    fun `deduplicates repeated endpoints`() {
        val out = JsEndpoints.extract("""call("/api/x"); again("/api/x");""")
        assertTrue(out.count { it == "/api/x" } == 1)
    }

    @Test
    fun `template literals come back with their expressions as placeholders`() {
        val out = JsEndpoints.extract("fetch(`/users/\${id}/posts?x=\${y}`); axios.get(`\${API_BASE}/items/\${ item.id }`)")
        assertEquals(setOf("/users/{id}/posts?x={y}", "{API_BASE}/items/{item.id}"), out)
    }

    @Test
    fun `template URLs keep their host, literal or computed`() {
        val out = JsEndpoints.extract("a(`https://api.example.com/v1/\${id}`); b(`https://\${host}/v1/x`)")
        assertTrue("https://api.example.com/v1/{id}" in out, out.toString())
        assertTrue("https://{host}/v1/x" in out, out.toString())
    }

    @Test
    fun `a template literal that is not a path is not an endpoint`() {
        assertTrue(JsEndpoints.extract("log(`hello \${name}`); join(`\${a}\${b}`); root(`/`)").isEmpty())
        // Without an interpolation it is an ordinary quoted path.
        assertEquals(setOf("/plain/path"), JsEndpoints.extract("go(`/plain/path`)"))
    }

    @Test
    fun `route patterns with placeholders are kept`() {
        val out = JsEndpoints.extract("""route("/users/:id"); spec('/orders/{orderId}/items')""")
        assertEquals(setOf("/users/:id", "/orders/{orderId}/items"), out)
    }

    @Test
    fun `a scan reports whether it covered the whole text`() {
        val text = "fetch('/api/a');".repeat(200)
        val whole = JsEndpoints.scan(text)
        assertTrue(whole.complete)
        assertEquals(setOf("/api/a"), whole.endpoints)

        // No time left: nothing is matched, and the result says the scan was cut short.
        val cut = JsEndpoints.scan(text, budgetMs = -1)
        assertFalse(cut.complete)
        assertTrue(cut.endpoints.isEmpty())
    }
}
