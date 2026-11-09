package io.bitbytelab.raijin.turbo

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DesyncCanaryTest {

    @Test
    fun `generate produces a canary findCanary can parse back`() {
        val canary = DesyncCanary.generate(techniqueId = 7, batch = 2, position = 3)
        val parsed = DesyncCanary.findCanary("some response text ...$canary... more text")
        requireNotNull(parsed)
        assertEquals(7, parsed.techniqueId)
        assertEquals(2, parsed.batch)
        assertEquals(3, parsed.position)
    }

    @Test
    fun `findCanary returns null when no canary is present`() {
        assertNull(DesyncCanary.findCanary("just a normal response body"))
        assertNull(DesyncCanary.findCanary(null))
    }

    @Test
    fun `isReflectionOfEarlierRequest is true only for an earlier batch or earlier position in the same batch`() {
        val earlierBatch = DesyncCanary.Parsed(techniqueId = 1, batch = 1, position = 0)
        val samBatchEarlierPos = DesyncCanary.Parsed(techniqueId = 1, batch = 2, position = 0)
        val currentRequest = DesyncCanary.Parsed(techniqueId = 1, batch = 2, position = 1)
        val laterBatch = DesyncCanary.Parsed(techniqueId = 1, batch = 3, position = 0)

        assertTrue(DesyncCanary.isReflectionOfEarlierRequest(earlierBatch, 1, 2, 1))
        assertTrue(DesyncCanary.isReflectionOfEarlierRequest(samBatchEarlierPos, 1, 2, 1))
        assertFalse(DesyncCanary.isReflectionOfEarlierRequest(currentRequest, 1, 2, 1))
        assertFalse(DesyncCanary.isReflectionOfEarlierRequest(laterBatch, 1, 2, 1))
    }

    @Test
    fun `isCrossTechniqueReflection flags a canary from a different technique`() {
        val other = DesyncCanary.Parsed(techniqueId = 9, batch = 1, position = 0)
        assertTrue(DesyncCanary.isCrossTechniqueReflection(other, currentTechniqueId = 1))
        assertFalse(DesyncCanary.isReflectionOfEarlierRequest(other, 1, 99, 99))
    }

    @Test
    fun `injectIntoRequestLine replaces a generic path entirely`() {
        val result = DesyncCanary.injectIntoRequestLine("GET /asdf HTTP/1.1\r\nHost: x", 1, 1, 0)
        assertTrue(result.startsWith("GET /${DesyncCanary.PREFIX}1x1x0 HTTP/1.1"))
    }

    @Test
    fun `injectIntoRequestLine uses a query parameter for the root path`() {
        val result = DesyncCanary.injectIntoRequestLine("GET / HTTP/1.1\r\nHost: x", 1, 1, 0)
        assertTrue(result.startsWith("GET /?xyz=${DesyncCanary.PREFIX}1x1x0 HTTP/1.1"))
    }

    @Test
    fun `injectIntoRequestLine appends to an existing query string`() {
        val result = DesyncCanary.injectIntoRequestLine("GET /search?q=foo HTTP/1.1\r\nHost: x", 1, 1, 0)
        assertTrue(result.startsWith("GET /search?q=foo&xyz=${DesyncCanary.PREFIX}1x1x0 HTTP/1.1"))
    }
}
