package io.bitbytelab.raijin.recon

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ParamInjectionTest {

    private val base = ProbeRequest("GET", "/search?lang=en", listOf("Host" to "t.example", "Cookie" to "session=abc"))
    private val params = listOf("a" to "1", "b c" to "2")

    @Test
    fun `query candidates are appended to the query string`() {
        assertEquals("/search?lang=en&a=1&b%20c=2", ParamInjection.inject(base, ParamLocation.QUERY, params).target)
        assertEquals("/p?a=1", ParamInjection.inject(base.copy(target = "/p"), ParamLocation.QUERY, listOf("a" to "1")).target)
    }

    @Test
    fun `cookie candidates join the existing Cookie header`() {
        val request = ParamInjection.inject(base, ParamLocation.COOKIE, params)
        assertEquals("session=abc; a=1; b%20c=2", request.header("Cookie"))
        assertEquals(1, request.headers.count { it.first.equals("Cookie", ignoreCase = true) })
    }

    @Test
    fun `a header candidate is added, or takes over the header of that name`() {
        val request = ParamInjection.inject(base, ParamLocation.HEADER, listOf("X-Test" to "v", "host" to "other.example"))
        assertEquals(listOf("host" to "other.example", "Cookie" to "session=abc", "X-Test" to "v"), request.headers)
    }

    @Test
    fun `form candidates go into the body with a form content type`() {
        val post = base.copy(method = "POST")
        val fresh = ParamInjection.inject(post, ParamLocation.BODY, params)
        assertEquals("a=1&b%20c=2", fresh.body)
        assertEquals("application/x-www-form-urlencoded", fresh.header("Content-Type"))
        assertTrue(fresh.render().contains("Content-Length: 11\r\n"))

        val existing = ParamInjection.inject(post.withBody("x=1&").withHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"), ParamLocation.BODY, params)
        assertEquals("x=1&a=1&b%20c=2", existing.body)
        assertEquals("application/x-www-form-urlencoded; charset=UTF-8", existing.header("Content-Type"))
    }

    @Test
    fun `JSON candidates become top-level members, keeping what the body already has`() {
        val post = base.copy(method = "POST")
        val fresh = ParamInjection.inject(post, ParamLocation.JSON_BODY, params)
        assertEquals("{\"a\":\"1\",\"b c\":\"2\"}", fresh.body)
        assertEquals("application/json", fresh.header("Content-Type"))

        val merged = Json.parseToJsonElement(ParamInjection.inject(post.withBody("{\"k\":true}"), ParamLocation.JSON_BODY, listOf("a" to "1")).body).jsonObject
        assertEquals(setOf("k", "a"), merged.keys)
        assertEquals("1", merged.getValue("a").jsonPrimitive.content)

        // A body that is not a JSON object is replaced by one rather than sent unchanged.
        assertEquals("{\"a\":\"1\"}", ParamInjection.inject(post.withBody("[1,2]"), ParamLocation.JSON_BODY, listOf("a" to "1")).body)
    }

    @Test
    fun `a request without candidates still has the shape of a mined one`() {
        assertEquals(base, ParamInjection.inject(base, ParamLocation.QUERY, emptyList()))
        assertEquals(base, ParamInjection.inject(base, ParamLocation.COOKIE, emptyList()))
        assertEquals(base, ParamInjection.inject(base, ParamLocation.HEADER, emptyList()))

        val json = ParamInjection.inject(base.copy(method = "POST"), ParamLocation.JSON_BODY, emptyList())
        assertEquals("{}", json.body)
        assertEquals("application/json", json.header("Content-Type"))

        val form = ParamInjection.inject(base.copy(method = "POST").withBody("x=1"), ParamLocation.BODY, emptyList())
        assertEquals("x=1", form.body)
        assertEquals("application/x-www-form-urlencoded", form.header("Content-Type"))
    }

    @Test
    fun `names the request already carries are found per location`() {
        assertEquals(setOf("lang"), ParamInjection.existingNames(base, ParamLocation.QUERY))
        assertEquals(setOf("session"), ParamInjection.existingNames(base, ParamLocation.COOKIE))
        assertEquals(emptySet(), ParamInjection.existingNames(base, ParamLocation.HEADER))
        assertEquals(emptySet(), ParamInjection.existingNames(base.copy(target = "/p"), ParamLocation.QUERY))

        val form = base.withBody("x=1&y%5B%5D=2")
        assertEquals(setOf("x", "y%5B%5D", "y[]"), ParamInjection.existingNames(form, ParamLocation.BODY))
        assertEquals(setOf("k", "m"), ParamInjection.existingNames(base.withBody("{\"k\":1,\"m\":{\"n\":2}}"), ParamLocation.JSON_BODY))
        assertEquals(emptySet(), ParamInjection.existingNames(base.withBody("not json"), ParamLocation.JSON_BODY))
    }

    @Test
    fun `locations are looked up by id`() {
        assertEquals(listOf("query", "body", "json_body", "cookie", "header"), ParamLocation.IDS)
        assertEquals(ParamLocation.JSON_BODY, ParamLocation.of(" JSON_BODY "))
        assertNull(ParamLocation.of("path"))
        assertEquals("POST", ParamLocation.BODY.method)
        assertEquals("GET", ParamLocation.HEADER.method)
        assertTrue(ParamLocation.HEADER.ignoresNameCase && !ParamLocation.QUERY.ignoresNameCase)
        assertTrue(ParamLocation.HEADER.bucketSize < ParamLocation.QUERY.bucketSize, "a header block holds fewer names than a query string")
    }
}
