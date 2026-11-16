package io.bitbytelab.raijin.core

import io.bitbytelab.raijin.core.WebSocketHistoryCriteria.DirectionFilter
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Per-item filters of `proxy_history` and the proxy WebSocket history tools: an item that lacks
 * the data a filter needs (no response, unparseable request, unknown upgrade host) never matches.
 */
class HistoryCriteriaTest {

    @Test
    fun `status code filter never matches an item without a response`() {
        val criteria = HistoryCriteria(statusCode = 200)
        assertTrue(criteria.needsStatus)
        assertTrue(criteria.matches(host = "a.test", method = "GET", status = 200))
        assertFalse(criteria.matches(host = "a.test", method = "GET", status = null))
        assertFalse(criteria.matches(host = "a.test", method = "GET", status = 404))
    }

    @Test
    fun `status range filter never matches an item without a response`() {
        val range = (StatusCodeRange.parse("0-299") as StatusCodeRange.Result.Ok).range
        val criteria = HistoryCriteria(statusRange = range)
        assertTrue(criteria.matches(null, null, 0))
        assertTrue(criteria.matches(null, null, 204))
        assertFalse(criteria.matches(null, null, null))
        assertFalse(criteria.matches(null, null, 302))
    }

    @Test
    fun `host and method filters reject items whose request could not be parsed`() {
        val criteria = HistoryCriteria(host = "example.com", method = "post")
        assertTrue(criteria.matches("api.EXAMPLE.com", "POST", null))
        assertFalse(criteria.matches(null, "POST", null))
        assertFalse(criteria.matches("api.example.com", null, null))
        assertFalse(criteria.matches("api.example.org", "POST", null))
    }

    @Test
    fun `no criteria matches everything, including malformed items`() {
        val criteria = HistoryCriteria()
        assertFalse(criteria.needsStatus)
        assertTrue(criteria.matches(null, null, null))
    }

    @Test
    fun `websocket host filter excludes messages with an unknown upgrade host`() {
        val criteria = WebSocketHistoryCriteria(host = "chat")
        assertTrue(criteria.matches("CHAT.example.com", "CLIENT_TO_SERVER"))
        assertFalse(criteria.matches(null, "CLIENT_TO_SERVER"))
        assertTrue(WebSocketHistoryCriteria().matches(null, null))
    }

    @Test
    fun `websocket direction filter compares Montoya direction names`() {
        val criteria = WebSocketHistoryCriteria(direction = "SERVER_TO_CLIENT")
        assertTrue(criteria.matches(null, "SERVER_TO_CLIENT"))
        assertFalse(criteria.matches(null, "CLIENT_TO_SERVER"))
        assertFalse(criteria.matches(null, null))
    }

    @Test
    fun `direction accepts either case, and both or nothing means no filter`() {
        assertEquals(DirectionFilter.Only("CLIENT_TO_SERVER"), WebSocketHistoryCriteria.parseDirection("client_to_server"))
        assertEquals(DirectionFilter.Only("SERVER_TO_CLIENT"), WebSocketHistoryCriteria.parseDirection(" SERVER_TO_CLIENT "))
        assertEquals(DirectionFilter.All, WebSocketHistoryCriteria.parseDirection("both"))
        assertEquals(DirectionFilter.All, WebSocketHistoryCriteria.parseDirection(null))
        assertEquals(DirectionFilter.All, WebSocketHistoryCriteria.parseDirection(""))
    }

    @Test
    fun `an unknown direction is an error, not a silently dropped filter`() {
        val parsed = WebSocketHistoryCriteria.parseDirection("sideways")
        assertTrue(parsed is DirectionFilter.Invalid)
        assertTrue("sideways" in parsed.message)
    }
}
