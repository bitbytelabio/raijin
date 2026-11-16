package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.bridge.IdorHunt.IdFormat
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.assertFalse

/**
 * Unit tests for the pure IDOR-hunting engine [IdorHunt]. Exercises the four
 * Burp-independent capabilities that back the `idor_hunt` MCP tool:
 * format recognition, transformation generation, request-ref location, and the
 * canary/signature verdict (the horizontal-IDOR confirmation auth_diff lacks).
 */
class IdorHuntTest {

    // ---- 1. format recognition -------------------------------------------

    @Test fun `classifies plain sequential integers`() {
        assertEquals(IdFormat.INT, IdorHunt.classify("1002").format)
        assertEquals(IdFormat.INT, IdorHunt.classify("42").format)
        assertEquals(IdFormat.INT, IdorHunt.classify("-1").format)
    }

    @Test fun `classifies UUID versions by the version nibble`() {
        assertEquals(IdFormat.UUID_V1, IdorHunt.classify("2c1b0e3a-7f6a-11e9-8f9e-2a86e4085a59").format)
        assertEquals(IdFormat.UUID_V4, IdorHunt.classify("f47ac10b-58cc-4372-a567-0e02b2c3d479").format)
        assertEquals(IdFormat.UUID_V7, IdorHunt.classify("018f6b3c-7e1a-7c2a-b3d4-1a2b3c4d5e6f").format)
    }

    @Test fun `classifies MongoDB ObjectID and hashes by length`() {
        assertEquals(IdFormat.OBJECTID, IdorHunt.classify("507f1f77bcf86cd799439011").format)
        assertEquals(IdFormat.HASH_MD5, IdorHunt.classify("c4ca4238a0b923820dcc509a6f75849b").format)
        assertEquals(IdFormat.HASH_SHA1, IdorHunt.classify("356a192b7913b04c54574d18c28d46e6395428ab").format)
        assertEquals(IdFormat.HASH_SHA256, IdorHunt.classify("6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b").format)
    }

    @Test fun `classifies snowflake-scale ids distinctly from small ints`() {
        assertEquals(IdFormat.SNOWFLAKE, IdorHunt.classify("175928847299117063").format)
        assertEquals(IdFormat.INT, IdorHunt.classify("1002").format)
    }

    @Test fun `classifies gid and base64 node ids and decodes them`() {
        val gid = IdorHunt.classify("gid://User/1001")
        assertEquals(IdFormat.GID, gid.format)
        assertEquals("1001", gid.decoded)

        val b64 = IdorHunt.classify("VXNlcjoxMDAx") // base64("User:1001")
        assertEquals(IdFormat.GID, b64.format)
        assertEquals("User:1001", b64.decoded)
    }

    @Test fun `classifies plain base64 opaque refs`() {
        val c = IdorHunt.classify("MTIz") // base64("123")
        assertEquals(IdFormat.BASE64, c.format)
        assertEquals("123", c.decoded)
    }

    @Test fun `unknown and empty inputs are low confidence`() {
        assertEquals(IdFormat.UNKNOWN, IdorHunt.classify("").format)
        assertEquals(0, IdorHunt.classify("").confidence)
        assertEquals(IdFormat.UNKNOWN, IdorHunt.classify("!!not-an-id!!").format)
    }

    // ---- 2. transformation generation ------------------------------------

    @Test fun `integer mutations include neighbors boundaries and encodings and are bounded`() {
        val muts = IdorHunt.mutations("1002")
        val values = muts.map { it.value }.toSet()
        assertTrue("1001" in values, "must include n-1")
        assertTrue("1003" in values, "must include n+1")
        assertTrue("0" in values, "must include boundary 0")
        assertTrue("2147483648" in values, "must include int32 overflow")
        assertTrue(muts.any { it.technique == "base64-encode" }, "must include a base64 transform")
        assertTrue(muts.any { it.technique == "null-byte-append" }, "must include a null-byte transform")
        assertTrue(muts.size <= 64, "must respect the max bound")
        // no dupes, never the original
        assertEquals(values.size, muts.size)
        assertFalse("1002" in values, "must never emit the original value")
    }

    @Test fun `uuid mutations include nil max and tail bump`() {
        val muts = IdorHunt.mutations("f47ac10b-58cc-4372-a567-0e02b2c3d479")
        val values = muts.map { it.value }.toSet()
        assertTrue("00000000-0000-0000-0000-000000000000" in values, "nil uuid")
        assertTrue("ffffffff-ffff-ffff-ffff-ffffffffffff" in values, "max uuid")
        assertTrue(muts.any { it.technique == "uuid-tail-decrement" }, "tail decrement")
        assertTrue(values.all { it != "f47ac10b-58cc-4372-a567-0e02b2c3d479" })
    }

    @Test fun `gid mutations decode modify and re-encode the numeric tail`() {
        val muts = IdorHunt.mutations("VXNlcjoxMDAx") // User:1001
        val decodedTails = muts.filter { it.technique == "decode-modify-reencode" }
            .map { IdorHunt.classify(it.value).decoded }
        assertTrue(decodedTails.contains("User:1000") || decodedTails.contains("User:1002"),
            "should produce User:1000/User:1002 re-encoded, got $decodedTails")
    }

    @Test fun `objectid mutations bump the trailing counter`() {
        val muts = IdorHunt.mutations("507f1f77bcf86cd799439011")
        assertTrue(muts.any { it.value == "507f1f77bcf86cd799439012" }, "counter+1")
        assertTrue(muts.any { it.value == "507f1f77bcf86cd799439010" }, "counter-1")
    }

    // ---- 3. request-ref location -----------------------------------------

    @Test fun `locates numeric id in the url path`() {
        val req = "GET /api/v1/users/1002/profile HTTP/1.1\r\nHost: x.com\r\n\r\n"
        val refs = IdorHunt.locateRefs(req)
        assertTrue(refs.any { it.location == "path" && it.value == "1002" }, "should find path id 1002: $refs")
    }

    @Test fun `locates id-ish query params and skips auth headers`() {
        val req = "GET /api/orders?order_id=5567&sort=asc HTTP/1.1\r\n" +
            "Host: x.com\r\nAuthorization: Bearer secrettoken\r\nX-User-Id: 42\r\n\r\n"
        val refs = IdorHunt.locateRefs(req)
        assertTrue(refs.any { it.location == "query" && it.name == "order_id" && it.value == "5567" }, "query id: $refs")
        assertTrue(refs.any { it.location == "header" && it.name == "X-User-Id" && it.value == "42" }, "header id: $refs")
        assertFalse(refs.any { it.value.contains("secrettoken") }, "must not surface the Authorization token as a ref")
        assertFalse(refs.any { it.name == "sort" }, "sort=asc is not an id")
    }

    @Test fun `locates id fields in a json body`() {
        val req = "POST /api/transfer HTTP/1.1\r\nHost: x.com\r\nContent-Type: application/json\r\n\r\n" +
            "{\"account_id\":\"9001\",\"amount\":50,\"note\":\"hi\"}"
        val refs = IdorHunt.locateRefs(req)
        assertTrue(refs.any { it.location == "body-json" && it.name == "account_id" && it.value == "9001" }, "json id: $refs")
        assertFalse(refs.any { it.name == "note" }, "note is not an id")
    }

    @Test fun `locates id-bearing cookies`() {
        val req = "GET /dashboard HTTP/1.1\r\nHost: x.com\r\nCookie: session=abc; user_id=7\r\n\r\n"
        val refs = IdorHunt.locateRefs(req)
        assertTrue(refs.any { it.location == "cookie" && it.name == "user_id" && it.value == "7" }, "cookie id: $refs")
    }

    // ---- 3b. location-scoped id swap -------------------------------------

    @Test fun `applySwap rewrites only the located path segment`() {
        val req = "GET /api/users/1002/orders/1002 HTTP/1.1\r\nHost: x.com\r\n\r\n"
        val ref = IdorHunt.locateRefs(req).first { it.location == "path" }
        val swapped = IdorHunt.applySwap(req, ref, "1003")
        // the located segment changes; the equal-valued one, the Host and the version are untouched
        assertEquals("GET /api/users/1003/orders/1002 HTTP/1.1\r\nHost: x.com\r\n\r\n", swapped)
    }

    @Test fun `applySwap rewrites a json body field without touching same-valued others`() {
        val req = "POST /t HTTP/1.1\r\nHost: x.com\r\n\r\n{\"account_id\":\"9001\",\"amount\":9001}"
        val ref = IdorHunt.locateRefs(req).first { it.name == "account_id" }
        val swapped = IdorHunt.applySwap(req, ref, "9002")
        assertTrue(swapped.contains("\"account_id\":\"9002\""), swapped)
        assertTrue(swapped.contains("\"amount\":9001"), "the amount field must be untouched: $swapped")
    }

    @Test fun `applySwap rewrites a cookie value only`() {
        val req = "GET /d HTTP/1.1\r\nHost: x.com\r\nCookie: session=abc; user_id=7\r\n\r\n"
        val ref = IdorHunt.locateRefs(req).first { it.location == "cookie" }
        val swapped = IdorHunt.applySwap(req, ref, "8")
        assertTrue(swapped.contains("user_id=8"), swapped)
        assertTrue(swapped.contains("session=abc"), "session cookie untouched")
    }

    // ---- 3c. swaps stop at parameter boundaries --------------------------

    private val tail = " HTTP/1.1\r\nHost: x.com\r\n\r\n"

    @Test fun `an id is never replaced inside a longer path segment`() {
        val req = "GET /v1/users/1$tail"
        val pinned = assertNotNull(IdorHunt.resolveRef(req, idValue = "1"))
        assertEquals("GET /v1/users/2$tail", IdorHunt.applySwap(req, pinned, "2"))

        val detected = assertNotNull(IdorHunt.resolveRef(req))
        assertEquals("GET /v1/users/2$tail", IdorHunt.applySwap(req, detected, "2"))
    }

    @Test fun `of two equal path segments the last is the object and the other can be pinned by index`() {
        val req = "GET /api/1/users/1$tail"
        val detected = assertNotNull(IdorHunt.resolveRef(req))
        assertEquals(3, detected.index)
        assertEquals("GET /api/1/users/2$tail", IdorHunt.applySwap(req, detected, "2"))

        val version = assertNotNull(IdorHunt.resolveRef(req, idValue = "1", idName = "1"))
        assertEquals("GET /api/2/users/1$tail", IdorHunt.applySwap(req, version, "2"))
    }

    @Test fun `a path id keeps its file extension and the query after it`() {
        val req = "GET /files/1002.json?v=2$tail"
        val ref = IdorHunt.locateRefs(req).first { it.location == "path" }
        assertEquals("1002", ref.value)
        assertEquals("GET /files/1003.json?v=2$tail", IdorHunt.applySwap(req, ref, "1003"))
    }

    @Test fun `a query swap touches one parameter value and no look-alike`() {
        val req = "GET /items?user_id=1&id=1&page=12&id2=1$tail"
        val ref = IdorHunt.locateRefs(req).first { it.location == "query" && it.name == "id" }
        assertEquals("GET /items?user_id=1&id=7&page=12&id2=1$tail", IdorHunt.applySwap(req, ref, "7"))

        // "1" is not found inside "12"
        val prefix = "GET /s?id=12&uid=1$tail"
        val pinned = assertNotNull(IdorHunt.resolveRef(prefix, idValue = "1"))
        assertEquals("uid", pinned.name)
        assertEquals("GET /s?id=12&uid=5$tail", IdorHunt.applySwap(prefix, pinned, "5"))
    }

    @Test fun `a json swap replaces one value found by parsing and keeps every other byte`() {
        val body = "{\n  \"user\": {\"id\": 5, \"name\": \"five\"},\n  \"ids\": [5, 6],\n  \"note\": \"5\"\n}"
        val req = "POST /t HTTP/1.1\r\nHost: x.com\r\nContent-Type: application/json\r\n\r\n$body"
        val ref = assertNotNull(IdorHunt.resolveRef(req, idValue = "5", idName = "user.id"))
        assertEquals("body-json", ref.location)
        assertEquals(req.replace("\"id\": 5", "\"id\": 7"), IdorHunt.applySwap(req, ref, "7"))

        // an array element is addressed by its own path
        val second = assertNotNull(IdorHunt.resolveRef(req, idValue = "6", idLocation = "body-json"))
        assertEquals("ids[1]", second.name)
        assertEquals(req.replace("[5, 6]", "[5, 9]"), IdorHunt.applySwap(req, second, "9"))
    }

    @Test fun `a json swap finds a nested field by its key`() {
        val req = "POST /t HTTP/1.1\r\nHost: x.com\r\n\r\n{\"data\":{\"account_id\":\"9001\"},\"amount\":9001}"
        val swapped = IdorHunt.applySwap(req, IdorHunt.ObjectRef("body-json", "account_id", "9001", IdFormat.INT), "9002")
        assertTrue(swapped.endsWith("{\"data\":{\"account_id\":\"9002\"},\"amount\":9001}"), swapped)
    }

    @Test fun `a json swap writes valid json for any new value`() {
        val req = "POST /t HTTP/1.1\r\nHost: x.com\r\n\r\n{\"id\":\"9\",\"n\":9}"
        val id = IdorHunt.ObjectRef("body-json", "id", "9", IdFormat.INT)
        val n = IdorHunt.ObjectRef("body-json", "n", "9", IdFormat.INT)

        assertTrue(IdorHunt.applySwap(req, id, "a\"b").endsWith("{\"id\":\"a\\\"b\",\"n\":9}"))
        assertTrue(IdorHunt.applySwap(req, n, "10").endsWith("{\"id\":\"9\",\"n\":10}"))
        // a number cannot hold text, so it becomes a string
        assertTrue(IdorHunt.applySwap(req, n, "9 ").endsWith("{\"id\":\"9\",\"n\":\"9 \"}"))
        // the array type-juggle mutation replaces the scalar with a real array
        assertTrue(IdorHunt.applySwap(req, id, "[\"9\"]").endsWith("{\"id\":[\"9\"],\"n\":9}"))
    }

    @Test fun `a form body swap touches one parameter value`() {
        val head = "POST /t HTTP/1.1\r\nHost: x.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n"
        val req = head + "amount=5&user_id=5&xuser_id=5"
        val ref = IdorHunt.locateRefs(req).first { it.location == "body-form" && it.name == "user_id" }
        assertEquals(head + "amount=5&user_id=6&xuser_id=5", IdorHunt.applySwap(req, ref, "6"))
    }

    @Test fun `a cookie swap touches one cookie and no look-alike`() {
        val req = "GET /d HTTP/1.1\r\nHost: x.com\r\nCookie: xuid=7; uid=7; uid2=77\r\n\r\n"
        val ref = IdorHunt.locateRefs(req).first { it.location == "cookie" && it.name == "uid" }
        assertEquals(
            "GET /d HTTP/1.1\r\nHost: x.com\r\nCookie: xuid=7; uid=8; uid2=77\r\n\r\n",
            IdorHunt.applySwap(req, ref, "8")
        )
    }

    @Test fun `a header swap touches the named header only`() {
        val req = "GET /me HTTP/1.1\r\nHost: x.com\r\nX-User-Id: 42\r\nX-Trace: 42\r\n\r\n"
        val ref = IdorHunt.locateRefs(req).first { it.location == "header" && it.name == "X-User-Id" }
        assertEquals(
            "GET /me HTTP/1.1\r\nHost: x.com\r\nX-User-Id: 43\r\nX-Trace: 42\r\n\r\n",
            IdorHunt.applySwap(req, ref, "43")
        )
    }

    @Test fun `a swapped value is encoded only as far as the request syntax needs`() {
        val req = "GET /u/5?id=5$tail"
        val path = assertNotNull(IdorHunt.resolveRef(req, idLocation = "path", idValue = "5"))
        val query = assertNotNull(IdorHunt.resolveRef(req, idLocation = "query", idValue = "5"))

        assertEquals("GET /u/5%20?id=5$tail", IdorHunt.applySwap(req, path, "5 "))
        // already-encoded and traversal mutations reach the wire as written
        assertEquals("GET /u/5%00?id=5$tail", IdorHunt.applySwap(req, path, "5%00"))
        assertEquals("GET /u/5/../5?id=5$tail", IdorHunt.applySwap(req, path, "5/../5"))
        assertEquals("GET /u/%C3%A9?id=5$tail", IdorHunt.applySwap(req, path, "\u00E9"))
        assertEquals("GET /u/5?id=a%2Bb%26c%20d$tail", IdorHunt.applySwap(req, query, "a+b&c d"))
        assertEquals("GET /u/5?id=NQ==$tail", IdorHunt.applySwap(req, query, "NQ=="))
    }

    @Test fun `a reference that is not in the request leaves it unchanged`() {
        val req = "GET /u/5$tail"
        assertEquals(req, IdorHunt.applySwap(req, IdorHunt.ObjectRef("query", "id", "5", IdFormat.INT), "6"))
        assertEquals(req, IdorHunt.applySwap(req, IdorHunt.ObjectRef("path", "segment", "55", IdFormat.INT), "6"))
        assertEquals(req, IdorHunt.applySwap(req, IdorHunt.ObjectRef("body-json", "id", "5", IdFormat.INT), "6"))
    }

    @Test fun `an unknown location still swaps at a boundary`() {
        val req = "GET /u/5?x=55$tail"
        val anywhere = IdorHunt.ObjectRef("somewhere", "", "5", IdFormat.INT)
        assertEquals("GET /u/6?x=55$tail", IdorHunt.applySwap(req, anywhere, "6"))
    }

    // ---- 3d. choosing the reference --------------------------------------

    @Test fun `a pinned value must stand at a parameter boundary`() {
        val req = "GET /u/5?x=55$tail"
        assertNull(IdorHunt.resolveRef(req, idValue = "9"), "not in the request")
        assertNull(IdorHunt.resolveRef(req, idValue = "u/5"), "spans two segments")
        assertNull(IdorHunt.resolveRef(req, idValue = "5", idLocation = "query"), "55 is not 5")
        assertNull(IdorHunt.resolveRef(req, idValue = "5", idName = "x"), "x holds 55")
        assertEquals("query", assertNotNull(IdorHunt.resolveRef(req, idName = "x")).location)
    }

    @Test fun `a pinned value may be a whole path segment, its id part, or its decoded form`() {
        val req = "GET /files/report.pdf$tail"
        val whole = assertNotNull(IdorHunt.resolveRef(req, idValue = "report.pdf"))
        assertEquals("GET /files/other.pdf$tail", IdorHunt.applySwap(req, whole, "other.pdf"))
        // the id part alone keeps the extension
        val stem = assertNotNull(IdorHunt.resolveRef(req, idValue = "report"))
        assertEquals("GET /files/summary.pdf$tail", IdorHunt.applySwap(req, stem, "summary"))

        val encoded = "GET /u/a%20b$tail"
        val decoded = assertNotNull(IdorHunt.resolveRef(encoded, idValue = "a b"))
        assertEquals("GET /u/c%20d$tail", IdorHunt.applySwap(encoded, decoded, "c d"))
    }

    @Test fun `a pinned value may begin a path segment when no letter or digit follows it`() {
        val req = "GET /users/42-alice$tail"
        val ref = assertNotNull(IdorHunt.resolveRef(req, idValue = "42"))
        assertEquals(Triple("path", "42", 1), Triple(ref.location, ref.value, ref.index))
        assertEquals("GET /users/1002-alice$tail", IdorHunt.applySwap(req, ref, "1002"))

        val withExtension = "GET /users/42_alice.json$tail"
        val pinned = assertNotNull(IdorHunt.resolveRef(withExtension, idValue = "42"))
        assertEquals("GET /users/7_alice.json$tail", IdorHunt.applySwap(withExtension, pinned, "7"))

        // a letter or a digit after it makes another value
        assertNull(IdorHunt.resolveRef("GET /users/42alice$tail", idValue = "42"))
        assertNull(IdorHunt.resolveRef("GET /users/420-x$tail", idValue = "42"))
        // a segment holding the value on its own wins over one that only begins with it
        assertEquals(1, assertNotNull(IdorHunt.resolveRef("GET /users/42/posts/42-draft$tail", idValue = "42")).index)
        // detection never cuts an id out of a segment, and neither does a ref that names no segment
        assertNull(IdorHunt.resolveRef("GET /products/1-click-buy$tail", ownedIds = listOf("1")))
        assertEquals(req, IdorHunt.applySwap(req, IdorHunt.ObjectRef("path", "segment", "42", IdFormat.INT), "1002"))
    }

    @Test fun `an id an identity owns is preferred over guessing`() {
        val req = "GET /orgs/7/items/900?page=41$tail"
        assertEquals("900", assertNotNull(IdorHunt.resolveRef(req)).value)
        assertEquals("7", assertNotNull(IdorHunt.resolveRef(req, ownedIds = listOf("7"))).value)
        // an owned id that only matches a non-id parameter does not beat a detected reference
        assertEquals("900", assertNotNull(IdorHunt.resolveRef(req, ownedIds = listOf("41"))).value)
        assertEquals("900", assertNotNull(IdorHunt.resolveRef(req, ownedIds = listOf("31337"))).value)
    }

    @Test fun `an owned id is never taken from a header that is not named like an id`() {
        val flags = "GET /account HTTP/1.1\r\nHost: x.com\r\nUpgrade-Insecure-Requests: 1\r\nDNT: 1\r\nCookie: session=abc\r\n\r\n"
        assertNull(IdorHunt.resolveRef(flags, ownedIds = listOf("1", "2")))

        // an id-named header still holds it, and so does a query parameter that is not named like one
        val named = "GET /account HTTP/1.1\r\nHost: x.com\r\nUpgrade-Insecure-Requests: 1\r\nX-Account-Id: 1\r\n\r\n"
        assertEquals("X-Account-Id", assertNotNull(IdorHunt.resolveRef(named, ownedIds = listOf("1", "2"))).name)
        val slug = "GET /profile?u=alice HTTP/1.1\r\nHost: x.com\r\nUpgrade-Insecure-Requests: 1\r\n\r\n"
        val bySlug = assertNotNull(IdorHunt.resolveRef(slug, ownedIds = listOf("alice", "bob")))
        assertEquals("query" to "u", bySlug.location to bySlug.name)
    }

    @Test fun `json references are named by path and literals are not references`() {
        val req = "POST /t HTTP/1.1\r\nHost: x.com\r\n\r\n" +
            "{\"user\":{\"id\":5,\"active\":true},\"owner_id\":null,\"tags\":[\"a\"]}"
        val refs = IdorHunt.locateRefs(req)
        assertTrue(refs.any { it.location == "body-json" && it.name == "user.id" && it.value == "5" }, refs.toString())
        assertFalse(refs.any { it.value == "null" || it.value == "true" }, refs.toString())
    }

    // ---- 4. canary / signature verdict -----------------------------------

    @Test fun `confirms horizontal idor when reader sees the owner canary and not its own`() {
        val probes = listOf(
            IdorHunt.CanaryProbe("alice", "bob", "1002", 200, "{\"ssn\":\"BOB-CANARY-9f\"}", "BOB-CANARY-9f", "ALICE-CANARY-1a")
        )
        val f = IdorHunt.assessCanary(probes)
        assertEquals(1, f.size)
        assertEquals("critical", f[0].severity)
        assertEquals("confirmed_horizontal_idor", f[0].id)
        assertEquals("critical", IdorHunt.topSeverity(f))
    }

    @Test fun `filters own-data-reflection false positive`() {
        val probes = listOf(
            IdorHunt.CanaryProbe("alice", "bob", "1002", 200, "{\"ssn\":\"ALICE-CANARY-1a\"}", "BOB-CANARY-9f", "ALICE-CANARY-1a")
        )
        val f = IdorHunt.assessCanary(probes)
        assertEquals("own_data_reflection_fp", f[0].id)
        assertEquals("info", f[0].severity)
    }

    @Test fun `properly denied cross reads produce no finding`() {
        val probes = listOf(
            IdorHunt.CanaryProbe("alice", "bob", "1002", 403, "Forbidden", "BOB-CANARY-9f", "ALICE-CANARY-1a")
        )
        assertTrue(IdorHunt.assessCanary(probes).isEmpty(), "a 403 cross-read is correct behavior")
    }

    @Test fun `2xx without a canary is a candidate not a confirmation`() {
        val probes = listOf(
            IdorHunt.CanaryProbe("alice", "bob", "1002", 200, "{\"data\":\"...\"}", null, null)
        )
        val f = IdorHunt.assessCanary(probes)
        assertEquals("candidate_needs_canary", f[0].id)
        assertEquals("high", f[0].severity)
    }

    @Test fun `same-identity baseline reads are ignored`() {
        val probes = listOf(
            IdorHunt.CanaryProbe("alice", "alice", "1001", 200, "own", "A", "A")
        )
        assertTrue(IdorHunt.assessCanary(probes).isEmpty())
    }

    @Test fun `a 2xx that only carries a denial is not a candidate`() {
        val probes = listOf(
            IdorHunt.CanaryProbe("alice", "bob", "1002", 200, "{\"error\":\"Access denied\"}", "BOB-CANARY", "ALICE-CANARY"),
            IdorHunt.CanaryProbe("alice", "bob", "1002", 200, "Forbidden", null, null)
        )
        val f = IdorHunt.assessCanary(probes)
        assertEquals(listOf("soft_denied", "soft_denied"), f.map { it.id })
        assertEquals("info", IdorHunt.topSeverity(f))
    }

    @Test fun `the owner canary outweighs denial wording in the body`() {
        val probes = listOf(
            IdorHunt.CanaryProbe(
                "alice", "bob", "1002", 200, "{\"note\":\"access denied twice\",\"ssn\":\"BOB-CANARY\"}", "BOB-CANARY", "ALICE-CANARY"
            )
        )
        assertEquals("confirmed_horizontal_idor", IdorHunt.assessCanary(probes).single().id)
    }

    @Test fun `a canary is found in a body that holds UTF-8 one char per byte`() {
        val canary = "Nguy\u1EC5n"
        val asBurpHandsItOver = String(canary.toByteArray(Charsets.UTF_8), Charsets.ISO_8859_1)
        assertTrue(IdorHunt.containsCanary("{\"name\":\"$asBurpHandsItOver\"}", canary))
        assertTrue(IdorHunt.containsCanary("{\"name\":\"$canary\"}", canary))
        assertFalse(IdorHunt.containsCanary("{\"name\":\"Nguyen\"}", canary))
        assertFalse(IdorHunt.containsCanary("anything", ""))
        assertFalse(IdorHunt.containsCanary("anything", null))
    }

    // ---- 5. transformation verdict ---------------------------------------

    private val exact = { a: String, b: String -> if (a == b) 100.0 else 0.0 }
    private val ownView = "{\"owner\":\"ALICE-CANARY\",\"id\":1002}"
    private val notFound = "{\"result\":\"no such order\"}"
    private val bobView = "{\"owner\":\"BOB-CANARY\",\"id\":1003}"
    private val baseline = IdorHunt.TransformBaseline(
        ownBody = ownView,
        missBody = notFound,
        readerCanary = "ALICE-CANARY",
        others = listOf(IdorHunt.OtherIdentity("bob", "BOB-CANARY", bobView))
    )

    private fun transform(
        status: Int,
        body: String,
        against: IdorHunt.TransformBaseline = baseline,
        similarity: (String, String) -> Double = exact
    ) = IdorHunt.assessTransform("alice", "numeric-neighbor", "1003", status, body, against, similarity)

    @Test fun `a transformed id is confirmed only when another identity's canary appears`() {
        val confirmed = transform(200, bobView)
        assertEquals("confirmed_cross_identity_read", confirmed.id)
        assertEquals("critical", confirmed.severity)
        assertEquals("bob", confirmed.matchedIdentity)
        assertTrue(confirmed.candidate)

        val both = transform(200, "{\"orders\":[\"ALICE-CANARY\",\"BOB-CANARY\"]}")
        assertEquals("canary_ambiguous", both.id)
        assertEquals("high", both.severity)
    }

    @Test fun `a 2xx for a transformed id is not reported on its own`() {
        // the server resolved the id back to the reader's own object
        assertEquals("own_object", transform(200, ownView).id)
        assertEquals("own_object", transform(200, "{\"id\":1002,\"owner\":\"ALICE-CANARY\",\"extra\":1}").id)
        // the server's answer for an id that does not exist
        assertEquals("not_found_like", transform(200, notFound).id)
        assertEquals("empty_response", transform(200, "  ").id)
        // a refusal served with 200
        assertEquals("soft_denied", transform(200, "{\"error\":\"Access denied\"}").id)
        assertEquals("denied", transform(403, "Forbidden").id)
        assertEquals("no_response", transform(0, "").id)

        val quiet = listOf(
            transform(200, ownView), transform(200, notFound), transform(200, "  "),
            transform(200, "{\"error\":\"Access denied\"}"), transform(403, "Forbidden"), transform(0, "")
        )
        quiet.forEach {
            assertFalse(it.candidate, it.id)
            assertTrue(it.severity == "none" || it.severity == "info", "${it.id}: ${it.severity}")
        }
    }

    @Test fun `another object without a canary to place it is a medium candidate`() {
        val v = transform(200, "{\"owner\":\"carol\",\"id\":1004}")
        assertEquals("unverified_object", v.id)
        assertEquals("medium", v.severity)
        assertTrue(v.candidate)
        assertEquals(0.0, v.similarityToOwn)
    }

    @Test fun `a response matching another identity's own view is a high candidate without its canary`() {
        val noCanary = baseline.copy(others = listOf(IdorHunt.OtherIdentity("bob", null, bobView)))
        val v = transform(200, bobView, noCanary)
        assertEquals("matches_other_identity_view", v.id)
        assertEquals("high", v.severity)
        assertEquals("bob", v.matchedIdentity)
    }

    @Test fun `a near copy of the own view is the own object unless the reader's canary says otherwise`() {
        val lookAlike = { a: String, b: String -> if (a == b) 100.0 else if (a.take(4) == b.take(4)) 96.0 else 0.0 }

        val noCanaries = IdorHunt.TransformBaseline("PAGE own", null, null, emptyList())
        assertEquals("own_object", transform(200, "PAGE other", noCanaries, lookAlike).id)

        // The reader's canary is in its own view and missing here: this is someone else's page.
        val withCanary = IdorHunt.TransformBaseline("PAGE own ALICE-CANARY", null, "ALICE-CANARY", emptyList())
        assertEquals("unverified_object", transform(200, "PAGE other", withCanary, lookAlike).id)
    }

    @Test fun `a canary the reader's own view also carries proves nothing`() {
        val shared = IdorHunt.TransformBaseline(
            ownBody = "team TEAM-CANARY mine ALICE-CANARY",
            missBody = null,
            readerCanary = "ALICE-CANARY",
            others = listOf(IdorHunt.OtherIdentity("bob", "TEAM-CANARY"))
        )
        val v = transform(200, "team TEAM-CANARY other", shared)
        assertEquals("unverified_object", v.id)
        assertNull(v.matchedIdentity)
    }

    @Test fun `without the reader's own view a response is not placed by similarity`() {
        val noOwnView = baseline.copy(ownBody = null, others = listOf(IdorHunt.OtherIdentity("bob", null, bobView)))
        // another object built on the same template as bob's view, with no canary to place it
        val sameTemplate = { a: String, b: String -> if (a == b) 100.0 else 92.0 }
        val lookAlike = transform(200, "{\"owner\":\"carol\",\"id\":1004}", noOwnView, sameTemplate)
        assertEquals("own_view_missing", lookAlike.id)
        assertEquals("info", lookAlike.severity)
        assertFalse(lookAlike.candidate)
        assertNull(lookAlike.matchedIdentity)
        // nor is an object unlike anything a medium candidate
        assertEquals("own_view_missing", transform(200, "{\"owner\":\"carol\",\"id\":1004}", noOwnView).id)

        // a canary is evidence of its own: it still confirms a cross-identity read
        val confirmed = transform(200, bobView, baseline.copy(ownBody = null))
        assertEquals("confirmed_cross_identity_read", confirmed.id)
        assertEquals("critical", confirmed.severity)
    }

    @Test fun `the unknown-id probe keeps the shape of the id and does not collide with it`() {
        val random = kotlin.random.Random(7)

        val small = IdorHunt.missProbeValue("1002", random = random).toLong()
        assertTrue(small in 1_900_000_000L..Int.MAX_VALUE.toLong(), "$small")
        val large = IdorHunt.missProbeValue("3000000000", random = random).toLong()
        assertTrue(large >= 30_000_000_000L, "$large")

        val uuid = IdorHunt.missProbeValue("f47ac10b-58cc-4372-a567-0e02b2c3d479", random = random)
        assertEquals(IdFormat.UUID_V4, IdorHunt.classify(uuid).format)
        assertNotEquals("f47ac10b-58cc-4372-a567-0e02b2c3d479", uuid)

        val objectId = IdorHunt.missProbeValue("507f1f77bcf86cd799439011", random = random)
        assertEquals(IdFormat.OBJECTID, IdorHunt.classify(objectId).format)
        assertNotEquals("507f1f77bcf86cd799439011", objectId)

        val gid = IdorHunt.missProbeValue("gid://User/1001", random = random)
        assertTrue(gid.startsWith("gid://User/") && gid != "gid://User/1001", gid)

        val nodeId = IdorHunt.missProbeValue("VXNlcjoxMDAx", random = random) // base64("User:1001")
        val decoded = assertNotNull(IdorHunt.classify(nodeId).decoded, nodeId)
        assertTrue(decoded.startsWith("User:") && decoded != "User:1001", decoded)

        // a short keyword is a slug; a longer one reads as an opaque base64 ref and stays one
        assertTrue(IdorHunt.missProbeValue("me", random = random).startsWith("zz-"))
        assertNotEquals("john-doe", IdorHunt.missProbeValue("john-doe", random = random))
    }

    // ---- 6. what a cross-identity replay sends ---------------------------

    @Test fun `a swapped body id leaves with the reader's identity and a matching Content-Length`() {
        val head = "POST /t HTTP/1.1\r\nHost: x.com\r\n"
        val req = head + "Cookie: s=alice\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{\"id\":\"9\"}"
        val ref = IdorHunt.locateRefs(req).first { it.location == "body-json" }

        // The replay IdorHuntBridge sends: owner's id swapped in, then the reader applied.
        val swapped = IdorHunt.applySwap(req, ref, "1002")
        val sent = AuthIdentityApplier.apply(swapped, AuthIdentityApplier.Identity("bob", listOf("Cookie" to "s=bob"))).request

        assertEquals(
            head + "Cookie: s=bob\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"id\":\"1002\"}",
            sent
        )
    }
}
