package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.organizer.Organizer
import burp.api.montoya.organizer.OrganizerItem
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Unit tests for the pure, Montoya-free logic in [OrganizerBridge].
 *
 * These cover the regressions in the `organizer_get_items` read path:
 *  - a `url_prefix` filter that used to return 0 for every item (because URL
 *    extraction threw and was swallowed to `false`), and
 *  - a negative `max_results` that used to leak the raw [IllegalArgumentException]
 *    thrown by [List.take].
 *
 * The item-reading path runs against proxy stubs of the Montoya interfaces ([OrganizerBridgeItemsTest]).
 */
class OrganizerBridgeTest {

    @Test
    fun `url filter matches a contained substring case-insensitively`() {
        assertTrue(OrganizerBridge.matchesUrlFilter("https://example.com/api/v1", "example.com"))
        assertTrue(OrganizerBridge.matchesUrlFilter("https://EXAMPLE.com/api/v1", "example.com"))
        assertTrue(OrganizerBridge.matchesUrlFilter("https://host/API/v1", "api/v1"))
    }

    @Test
    fun `url filter does not match when the substring is absent`() {
        assertFalse(OrganizerBridge.matchesUrlFilter("https://example.com/api", "other.com"))
    }

    @Test
    fun `url filter treats a null or empty filter as match-all and a null url as no-match`() {
        assertTrue(OrganizerBridge.matchesUrlFilter("https://example.com", null))
        assertTrue(OrganizerBridge.matchesUrlFilter("https://example.com", ""))
        // A null URL (unreadable item) must never match a real filter — this is
        // exactly the case that previously made every item drop out of the filter.
        assertFalse(OrganizerBridge.matchesUrlFilter(null, "example.com"))
        // ...but a null URL with a match-all filter is still counted.
        assertTrue(OrganizerBridge.matchesUrlFilter(null, null))
    }

    @Test
    fun `effective return count clamps to available items and never goes negative`() {
        assertEquals(3, OrganizerBridge.effectiveReturnCount(available = 3, maxResults = 100))
        assertEquals(2, OrganizerBridge.effectiveReturnCount(available = 5, maxResults = 2))
        assertEquals(0, OrganizerBridge.effectiveReturnCount(available = 5, maxResults = 0))
        // Negative limits collapse to zero rather than throwing (mirrors the
        // guard that getItems applies before ever calling List.take).
        assertEquals(0, OrganizerBridge.effectiveReturnCount(available = 5, maxResults = -3))
    }
}

private inline fun <reified T> stub(crossinline answer: (String) -> Any?): T =
    Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { _, m, _ -> answer(m.name) } as T

class OrganizerBridgeItemsTest {

    private fun item(id: Int, url: String, notes: String?, color: HighlightColor?): OrganizerItem {
        val annotations = stub<Annotations> { name ->
            when (name) {
                "hasNotes" -> notes != null
                "notes" -> notes
                "hasHighlightColor" -> color != null
                "highlightColor" -> color
                else -> null
            }
        }
        return stub<OrganizerItem> { name ->
            when (name) {
                "id" -> id
                "url" -> url
                "annotations" -> annotations
                "hasResponse" -> false
                else -> null
            }
        }
    }

    private fun api(items: List<OrganizerItem>): MontoyaApi {
        val organizer = stub<Organizer> { name -> if (name == "items") items else null }
        return stub<MontoyaApi> { name -> if (name == "organizer") organizer else null }
    }

    @Test
    fun `getItems returns the id annotate needs plus notes and highlight`() {
        val bridge = OrganizerBridge(api(listOf(
            item(7, "https://a.test/x", "checked", HighlightColor.RED),
            item(9, "https://b.test/y", null, null),
        )))
        val result = bridge.getItems(urlPrefix = "a.test", maxResults = 10)
        assertEquals(2, result["total_items"]?.jsonPrimitive?.int)
        val items = result.getValue("items").jsonArray
        assertEquals(1, items.size)
        val first = items[0].jsonObject
        assertEquals(7, first["id"]?.jsonPrimitive?.int)
        assertEquals("https://a.test/x", first["url"]?.jsonPrimitive?.content)
        assertEquals("checked", first["notes"]?.jsonPrimitive?.content)
        assertEquals("RED", first["highlight"]?.jsonPrimitive?.content)

        val all = bridge.getItems(urlPrefix = null, maxResults = 10).getValue("items").jsonArray
        val second = all[1].jsonObject
        assertEquals(9, second["id"]?.jsonPrimitive?.int)
        assertFalse("notes" in second || "highlight" in second)
    }

    @Test
    fun `getItems rejects a negative limit with an error object`() {
        val result = OrganizerBridge(api(emptyList())).getItems(urlPrefix = null, maxResults = -1)
        assertTrue(result["error"]?.jsonPrimitive?.content?.contains("max_results") == true)
    }
}
