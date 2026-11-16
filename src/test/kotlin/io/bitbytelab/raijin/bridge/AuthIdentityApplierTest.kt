package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.bridge.AuthIdentityApplier.Identity
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [AuthIdentityApplier] turns "this request, as that identity" into the text that is sent: what
 * leaves for an unauthenticated level, that a header is replaced and never doubled, and that the
 * `Content-Length` matches the body.
 */
class AuthIdentityApplierTest {

    private val body = "{\"item\":\"book\"}" // 15 bytes

    // Captured as the admin, with a stale Content-Length the way hand-written requests have one.
    private val base = "POST /api/orders HTTP/1.1\r\n" +
        "Host: shop.example\r\n" +
        "Cookie: session=admin-session\r\n" +
        "Authorization: Bearer admin-token\r\n" +
        "X-Session-Key: admin-key\r\n" +
        "Content-Type: application/json\r\n" +
        "Content-Length: 5\r\n" +
        "\r\n" +
        body

    // ---- unauthenticated levels ----

    @Test
    fun `an unauthenticated level leaves with no credential header and a correct Content-Length`() {
        val applied = AuthIdentityApplier.apply(base, Identity("none"), identityHeaders = setOf("x-session-key"))

        assertEquals(
            "POST /api/orders HTTP/1.1\r\n" +
                "Host: shop.example\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: 15\r\n" +
                "\r\n" +
                body,
            applied.request
        )
        assertEquals(listOf("Cookie", "Authorization", "X-Session-Key"), applied.removed)
        assertTrue(applied.set.isEmpty())
        assertTrue(applied.keptCredentials.isEmpty())
    }

    @Test
    fun `none unauth and anonymous are unauthenticated in any case and nothing else is`() {
        for (name in listOf("none", "unauth", "anonymous", "NONE", "Unauth", "Anonymous")) {
            assertTrue(AuthIdentityApplier.isUnauthenticated(name), name)
            val head = AuthIdentityApplier.apply(base, Identity(name)).request.substringBefore("\r\n\r\n")
            assertFalse(head.contains("Cookie:", ignoreCase = true), "$name: $head")
            assertFalse(head.contains("Authorization:", ignoreCase = true), "$name: $head")
        }
        for (name in listOf("guest", "user", "unauthenticated", "", null)) {
            assertFalse(AuthIdentityApplier.isUnauthenticated(name), name.toString())
        }
    }

    @Test
    fun `an unauthenticated level strips every well-known credential header`() {
        val request = "GET /me HTTP/1.1\r\nHost: a\r\n" +
            AuthIdentityApplier.CREDENTIAL_HEADERS.joinToString("") { "${it.lowercase()}: secret\r\n" } +
            "X-CSRF-Token: t\r\nAccept: */*\r\n\r\n"
        val applied = AuthIdentityApplier.apply(request, Identity("anonymous"))
        // A CSRF token is not a credential on its own and stays.
        assertEquals("GET /me HTTP/1.1\r\nHost: a\r\nX-CSRF-Token: t\r\nAccept: */*\r\n\r\n", applied.request)
        assertEquals(AuthIdentityApplier.CREDENTIAL_HEADERS.map { it.lowercase() }, applied.removed)
    }

    @Test
    fun `an unauthenticated level that names a header loses the credentials first and then sends its own`() {
        val applied = AuthIdentityApplier.apply(base, Identity("anonymous", listOf("Cookie" to "guest=1")))

        assertEquals(
            "POST /api/orders HTTP/1.1\r\n" +
                "Host: shop.example\r\n" +
                "Cookie: guest=1\r\n" +
                "X-Session-Key: admin-key\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: 15\r\n" +
                "\r\n" +
                body,
            applied.request
        )
        assertEquals(listOf("Authorization"), applied.removed)
        assertEquals(listOf("Cookie"), applied.set)
    }

    @Test
    fun `a folded continuation line goes with the header it belongs to`() {
        val request = "GET /a HTTP/1.1\r\nHost: a\r\nCookie: s=1;\r\n\tt=2\r\nAccept: */*\r\n\r\n"
        assertEquals("GET /a HTTP/1.1\r\nHost: a\r\nAccept: */*\r\n\r\n", AuthIdentityApplier.apply(request, Identity("none")).request)
    }

    // ---- authenticated levels ----

    @Test
    fun `an identity header replaces every existing occurrence instead of adding another one`() {
        val twice = base.replace(
            "Authorization: Bearer admin-token\r\n",
            "Authorization: Bearer admin-token\r\nauthorization: Bearer stale\r\n"
        )
        val applied = AuthIdentityApplier.apply(twice, Identity("user", listOf("Authorization" to "Bearer user-token")))

        val authorization = applied.request.lines().filter { it.startsWith("authorization", ignoreCase = true) }
        assertEquals(listOf("Authorization: Bearer user-token"), authorization)
        // The replacement keeps the place of the header it replaces.
        assertTrue(
            applied.request.contains("Cookie: session=admin-session\r\nAuthorization: Bearer user-token\r\nX-Session-Key: admin-key\r\n"),
            applied.request
        )
        assertEquals(listOf("Authorization"), applied.set)
        assertTrue(applied.removed.isEmpty())
        // The captured cookie still travels with the user's token, and says so.
        assertEquals(listOf("Cookie"), applied.keptCredentials)
    }

    @Test
    fun `a header the request does not have is added once at the end of the header block`() {
        val applied = AuthIdentityApplier.apply("GET /me HTTP/1.1\r\nHost: a\r\n\r\n", Identity("user", listOf("X-Api-Key" to "k1")))
        assertEquals("GET /me HTTP/1.1\r\nHost: a\r\nX-Api-Key: k1\r\n\r\n", applied.request)
    }

    @Test
    fun `an identity can set several headers and remove others`() {
        val identity = Identity("user", listOf("Cookie" to "session=user", "X-CSRF-Token" to "u1"), listOf("x-session-key"))
        val applied = AuthIdentityApplier.apply(base, identity)

        val head = applied.request.substringBefore("\r\n\r\n")
        assertTrue(head.contains("\r\nCookie: session=user\r\n"), head)
        assertTrue(head.contains("\r\nX-CSRF-Token: u1"), head)
        assertFalse(head.contains("X-Session-Key"), head)
        assertFalse(head.contains("admin-session"), head)
        assertEquals(listOf("X-Session-Key"), applied.removed)
        assertEquals(listOf("Authorization"), applied.keptCredentials)
    }

    @Test
    fun `an identity that changes nothing sends the request as it is`() {
        val request = "GET /me HTTP/1.1\r\nHost: a\r\nCookie: s=1\r\n\r\n"
        val identity = Identity("captured")
        assertTrue(identity.sendsRequestUnchanged)
        assertEquals(request, AuthIdentityApplier.apply(request, identity).request)

        assertFalse(Identity("none").sendsRequestUnchanged)
        assertFalse(Identity("user", listOf("Cookie" to "s=2")).sendsRequestUnchanged)
    }

    // ---- request shape ----

    @Test
    fun `bare line feeds are normalised and a missing blank line is added`() {
        val applied = AuthIdentityApplier.apply("GET /a HTTP/1.1\nHost: a\nCookie: s=1", Identity("none"))
        assertEquals("GET /a HTTP/1.1\r\nHost: a\r\n\r\n", applied.request)
    }

    @Test
    fun `a blank request is returned untouched`() {
        assertEquals("", AuthIdentityApplier.apply("", Identity("none")).request)
    }

    // ---- Content-Length ----

    @Test
    fun `a missing Content-Length is added for a body and a stale one is corrected`() {
        val added = AuthIdentityApplier.apply("POST /a HTTP/1.1\r\nHost: a\r\n\r\nx=1", Identity("none"))
        assertEquals("POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nx=1", added.request)

        val stale = AuthIdentityApplier.apply("GET /a HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\n\r\n", Identity("none"))
        assertEquals("GET /a HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n", stale.request)

        // Trailing line breaks after a bodyless request are not a body to frame.
        val trailing = "GET /a HTTP/1.1\r\nHost: a\r\n\r\n\r\n"
        assertEquals(trailing, AuthIdentityApplier.apply(trailing, Identity("none")).request)
    }

    @Test
    fun `Content-Length counts the bytes that are sent`() {
        val request = "POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\n{\"n\":\"Vi\u1EC7t\"}"
        val applied = AuthIdentityApplier.apply(request, Identity("none")).request

        // U+1EC7 takes three bytes in UTF-8: 11 single-byte characters + 3.
        assertTrue(applied.contains("\r\nContent-Length: 14\r\n"), applied)
        val wire = AuthIdentityApplier.wireBytes(applied)
        assertEquals(applied, String(wire, Charsets.UTF_8))
        val bodyBytes = wire.size - applied.substringBefore("\r\n\r\n").toByteArray(Charsets.UTF_8).size - 4
        assertEquals(14, bodyBytes)
    }

    @Test
    fun `deliberate framing is never rewritten`() {
        val chunked = "POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        assertEquals(chunked, AuthIdentityApplier.apply(chunked, Identity("none")).request)

        val twoLengths = "POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nContent-Length: 100\r\n\r\nabcd"
        assertEquals(twoLengths, AuthIdentityApplier.apply(twoLengths, Identity("none")).request)

        val chunkedOnly = "POST /a HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
        assertEquals(chunkedOnly, AuthIdentityApplier.apply(chunkedOnly, Identity("none")).request)
    }

    // ---- reading identities ----

    @Test
    fun `parse merges the header pair and the headers map and reads remove_headers`() {
        val identity = AuthIdentityApplier.parse(buildJsonObject {
            put("name", "user")
            put("header_name", "Authorization:")
            put("header_value", "Bearer u")
            putJsonObject("headers") {
                put("Cookie", "s=1")
                put("authorization", "Bearer v")
            }
            putJsonArray("remove_headers") { add("X-Debug") }
        })
        assertEquals(Identity("user", listOf("authorization" to "Bearer v", "Cookie" to "s=1"), listOf("X-Debug")), identity)
    }

    @Test
    fun `parse ignores half a header pair and names a nameless identity`() {
        val identity = AuthIdentityApplier.parse(buildJsonObject { put("header_name", "Cookie") }, defaultName = "level_2")
        assertEquals(Identity("level_2"), identity)
        assertEquals("unknown", AuthIdentityApplier.parse(buildJsonObject { }).name)
    }

    @Test
    fun `identity headers of a run are every header an identity sets or removes`() {
        val identities = listOf(
            Identity("admin", listOf("Authorization" to "a")),
            Identity("user", listOf("X-Session-Key" to "u"), listOf("X-Debug")),
            Identity("none")
        )
        assertEquals(setOf("authorization", "x-session-key", "x-debug"), AuthIdentityApplier.identityHeaders(identities))
    }

    @Test
    fun `two identities that change nothing cannot be told apart and are refused`() {
        val error = assertNotNull(
            AuthIdentityApplier.indistinguishableError(listOf(Identity("admin"), Identity("user"), Identity("none")))
        )
        assertTrue("'admin'" in error && "'user'" in error, error)
        assertFalse("'none'" in error, error)

        // One level may stand for the request as captured.
        val workable = listOf(Identity("captured"), Identity("user", listOf("Cookie" to "s=2")), Identity("none"))
        assertNull(AuthIdentityApplier.indistinguishableError(workable))
    }
}
