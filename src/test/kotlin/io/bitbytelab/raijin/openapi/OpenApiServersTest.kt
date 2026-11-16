package io.bitbytelab.raijin.openapi

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class OpenApiServersTest {

    private fun json(text: String): JsonElement = Json.parseToJsonElement(text)

    private fun serverOf(url: String, documentUrl: String? = null): String? =
        OpenApiServers.fromServers(json("""[{"url": "$url"}]"""), documentUrl)?.url

    private fun swagger(root: String, documentUrl: String? = null): String? =
        OpenApiServers.swagger2(json(root).jsonObject, documentUrl)?.url

    // --- BUG #21: path-join normalization (no double slashes) ---

    @Test
    fun `root basePath joined with slashed path yields single-slash endpoint`() {
        assertEquals("/blog", OpenApiServers.joinPaths("/", "/blog"))
    }

    @Test
    fun `non-root basePath joined with slashed path preserves both segments`() {
        assertEquals("/api/blog", OpenApiServers.joinPaths("/api", "/blog"))
    }

    @Test
    fun `trailing-slash basePath (from servers url) collapses the boundary slash`() {
        assertEquals("/api/blog", OpenApiServers.joinPaths("/api/", "/blog"))
    }

    @Test
    fun `root basePath joined with root path yields a single slash`() {
        assertEquals("/", OpenApiServers.joinPaths("/", "/"))
    }

    @Test
    fun `empty basePath still produces a rooted path`() {
        assertEquals("/blog", OpenApiServers.joinPaths("", "/blog"))
    }

    @Test
    fun `path without leading slash is rooted onto basePath`() {
        assertEquals("/api/blog", OpenApiServers.joinPaths("/api", "blog"))
    }

    @Test
    fun `no double slash ever appears at the join boundary`() {
        val cases = listOf(
            "/" to "/blog",
            "/api/" to "/blog",
            "/api" to "/blog",
            "" to "/blog"
        )
        for ((bp, p) in cases) {
            val joined = OpenApiServers.joinPaths(bp, p)
            assertFalse(joined.contains("//"), "unexpected '//' in '$joined' for ('$bp','$p')")
        }
    }

    // --- BUG #21: base URL validation ---

    @Test
    fun `valid https url with dotted host is accepted`() {
        assertEquals(ServerUrl("https", "api.example.com", 443, ""), OpenApiServers.parse("https://api.example.com"))
    }

    @Test
    fun `valid http url with path and port is accepted`() {
        assertEquals(ServerUrl("http", "api.example.com", 8080, "/v1"), OpenApiServers.parse("http://api.example.com:8080/v1"))
    }

    @Test
    fun `localhost is accepted`() {
        assertEquals(ServerUrl("http", "localhost", 3000, ""), OpenApiServers.parse("http://localhost:3000"))
    }

    @Test
    fun `dotted ipv4 host is accepted`() {
        assertEquals(ServerUrl("http", "127.0.0.1", 8000, "/api"), OpenApiServers.parse("http://127.0.0.1:8000/api"))
    }

    @Test
    fun `missing scheme is rejected`() {
        assertNull(OpenApiServers.parse("api.example.com"))
    }

    @Test
    fun `non-http scheme is rejected`() {
        assertNull(OpenApiServers.parse("ftp://api.example.com"))
    }

    @Test
    fun `host containing a space is rejected`() {
        assertNull(OpenApiServers.parse("https://bad host.com"))
    }

    @Test
    fun `scheme with empty host is rejected`() {
        assertNull(OpenApiServers.parse("https://"))
    }

    @Test
    fun `bare single-label host without a dot is rejected`() {
        assertNull(OpenApiServers.parse("http://notahost"))
    }

    @Test
    fun `non-numeric port is rejected`() {
        assertNull(OpenApiServers.parse("http://api.example.com:notaport"))
    }

    @Test
    fun `a port outside 1 to 65535 is rejected`() {
        assertNull(OpenApiServers.parse("https://api.example.com:0"))
        assertNull(OpenApiServers.parse("https://api.example.com:70000"))
    }

    @Test
    fun `query and fragment are not part of the base path, and the scheme is case-insensitive`() {
        assertEquals(ServerUrl("http", "api.example.com", 80, "/v1"), OpenApiServers.parse("http://api.example.com/v1?x=1#top"))
        assertEquals(ServerUrl("https", "api.example.com", 443, ""), OpenApiServers.parse("HTTPS://api.example.com?x=1"))
    }

    @Test
    fun `the origin names the port only when it is not the default`() {
        assertEquals("https://api.example.com/v1", ServerUrl("https", "api.example.com", 443, "/v1").url)
        assertEquals("http://localhost", ServerUrl("http", "localhost", 80, "").origin)
        assertEquals("https://api.example.com:8443", ServerUrl("https", "api.example.com", 8443, "").origin)
        assertEquals("http://api.example.com:443", ServerUrl("http", "api.example.com", 443, "").origin)
    }

    // --- OpenAPI 3 servers ---

    @Test
    fun `server variables are filled with their default, else their first enum value`() {
        val servers = json(
            """
            [{"url": "https://{tenant}.example.com:{port}/{base}",
              "variables": {"tenant": {"default": "acme", "enum": ["other", "acme"]},
                            "port": {"enum": ["8443", "443"]},
                            "base": {"default": "v2"}}}]
            """
        )
        assertEquals("https://acme.example.com:8443/v2", OpenApiServers.fromServers(servers, null)?.url)
    }

    @Test
    fun `the first usable server is taken`() {
        val servers = json(
            """
            [{"url": "https://{undeclared}.example.com"},
             {"url": "wss://stream.example.com"},
             "not a server object",
             {"url": "http://second.example.com/api"},
             {"url": "https://third.example.com"}]
            """
        )
        assertEquals("http://second.example.com/api", OpenApiServers.fromServers(servers, null)?.url)
        assertEquals("http://second.example.com/api", OpenApiServers.fromServers(servers, "https://docs.example.com/openapi.json")?.url)
        assertNull(OpenApiServers.fromServers(json("[]"), null))
        assertNull(OpenApiServers.fromServers(null, null))
    }

    @Test
    fun `a relative server URL resolves against the document URL`() {
        val document = "https://docs.example.com/specs/v1/openapi.yaml"
        assertEquals("https://docs.example.com/api", serverOf("/api", document))
        assertEquals("https://docs.example.com/specs/v1/v2", serverOf("v2", document))
        assertEquals("https://docs.example.com/specs/v2", serverOf("../v2", document))
        assertEquals("https://docs.example.com/specs/v1/", serverOf("./", document))
        assertEquals("https://docs.example.com/", serverOf("", document))
        assertEquals("https://cdn.example.com/x", serverOf("//cdn.example.com/x", document))
    }

    @Test
    fun `a relative server URL resolves against a document URL that has no path`() {
        assertEquals("https://docs.example.com/v1", serverOf("v1", "https://docs.example.com"))
        assertEquals("http://localhost:8080/v1", serverOf("/v1", "http://localhost:8080"))
    }

    @Test
    fun `a relative server URL without a usable document URL yields nothing`() {
        assertNull(serverOf("/api"))
        assertNull(serverOf("/api", "   "))
        assertNull(serverOf("/api", "not a url"))
        assertNull(serverOf("/api", "file:///tmp/openapi.json"))
    }

    @Test
    fun `an OpenAPI 3 document without servers is served from the root of its own host`() {
        val root = json("""{"openapi": "3.0.3"}""").jsonObject
        assertEquals("https://docs.example.com/", OpenApiServers.openApi3(root, "https://docs.example.com/specs/openapi.json")?.url)
        assertNull(OpenApiServers.openApi3(root, null))

        val unusable = json("""{"openapi": "3.0.3", "servers": [{"url": "wss://stream.example.com"}]}""").jsonObject
        assertEquals("https://docs.example.com/", OpenApiServers.openApi3(unusable, "https://docs.example.com/specs/openapi.json")?.url)
    }

    @Test
    fun `a rejected http(s) server is an error, never the document's own host`() {
        val document = "https://docs.example.com/specs/openapi.json"
        for (url in listOf("http://notahost", "https://bad host.com", "https://[::1]:8443/api", "http://api.example.com:70000", "//cdn/x")) {
            val failure = assertFailsWith<IllegalArgumentException>(url) { serverOf(url, document) }
            val message = failure.message.orEmpty()
            assertTrue("No usable server URL" in message && "'$url'" in message && "base_url" in message, message)
            val root = json("""{"openapi": "3.0.3", "servers": [{"url": "$url"}]}""").jsonObject
            assertFailsWith<IllegalArgumentException>(url) { OpenApiServers.openApi3(root, document) }
        }
        val template = assertFailsWith<IllegalArgumentException> { serverOf("https://{tenant}.example.com", document) }
        assertTrue("{variable} without a default" in template.message.orEmpty(), template.message)

        // another entry that is usable is still taken
        val servers = json("""[{"url": "http://notahost"}, {"url": "https://api.example.com"}]""")
        assertEquals("https://api.example.com", OpenApiServers.fromServers(servers, document)?.url)
        val relative = json("""[{"url": "https://{undeclared}.example.com"}, {"url": "/api"}]""")
        assertEquals("https://docs.example.com/api", OpenApiServers.fromServers(relative, document)?.url)
    }

    // --- Swagger 2 host / basePath / schemes ---

    @Test
    fun `Swagger 2 host, basePath and schemes make the base URL, https preferred`() {
        assertEquals(
            "https://api.example.com:8443/v1",
            swagger("""{"host": "api.example.com:8443", "basePath": "/v1", "schemes": ["http", "https"]}""")
        )
        assertEquals("http://api.example.com/v1", swagger("""{"host": "api.example.com", "basePath": "v1", "schemes": ["http"]}"""))
        assertEquals("https://api.example.com", swagger("""{"host": "api.example.com", "schemes": ["ws", "wss"]}"""))
        assertEquals("https://api.example.com", swagger("""{"host": "api.example.com"}"""))
    }

    @Test
    fun `Swagger 2 falls back to where the document was served from`() {
        val document = "http://shop.example.com:8080/docs/swagger.json"
        // No schemes: the scheme the document was fetched with.
        assertEquals("http://api.example.com/v1", swagger("""{"host": "api.example.com", "basePath": "/v1"}""", document))
        // No host: the document's host, port included.
        assertEquals("http://shop.example.com:8080/api", swagger("""{"basePath": "/api"}""", document))
        assertEquals("https://shop.example.com:8080", swagger("""{"schemes": ["https"]}""", document))
        assertNull(swagger("""{"basePath": "/api"}"""))
    }

    @Test
    fun `a Swagger 2 host that is not a usable host name yields nothing`() {
        assertNull(swagger("""{"host": "not a host"}"""))
        assertNotNull(swagger("""{"host": "localhost:8080"}"""))
    }
}
