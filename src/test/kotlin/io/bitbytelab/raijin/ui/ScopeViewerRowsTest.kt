package io.bitbytelab.raijin.ui

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals

class ScopeViewerRowsTest {

    private fun obj(json: String) = Json.parseToJsonElement(json).jsonObject

    @Test
    fun `simple-mode rules show their URL prefix`() {
        assertEquals("https://example.com", ScopeViewerPanel.ruleText(obj("""{"enabled":true,"prefix":"https://example.com"}""")))
        assertEquals(
            "https://example.com (and subdomains)",
            ScopeViewerPanel.ruleText(obj("""{"prefix":"https://example.com","include_subdomains":true}""")),
        )
    }

    @Test
    fun `advanced-mode rules list their patterns`() {
        assertEquals(
            "protocol https · host ^example\\.com$ · port ^443$ · file ^/api/.*",
            ScopeViewerPanel.ruleText(obj("""{"enabled":true,"protocol":"https","host":"^example\\.com$","port":"^443$","file":"^/api/.*"}""")),
        )
        assertEquals("(any)", ScopeViewerPanel.ruleText(obj("""{"enabled":false}""")))
    }

    @Test
    fun `rows keep list, index and enabled state from ScopeBridge list`() {
        val rows = ScopeViewerPanel.rowsOf(obj(
            """{"include":[{"index":0,"enabled":true,"prefix":"https://a.test"},{"index":1,"enabled":false,"prefix":"https://b.test"}],
               "exclude":[{"index":0,"prefix":"https://a.test/logout"}]}"""
        ))
        assertEquals(
            listOf(
                listOf<Any?>("Include", 0, true, "https://a.test"),
                listOf<Any?>("Include", 1, false, "https://b.test"),
                listOf<Any?>("Exclude", 0, true, "https://a.test/logout"),
            ),
            rows,
        )
        assertEquals(emptyList<List<Any?>>(), ScopeViewerPanel.rowsOf(obj("""{"error":"Failed to list scope rules"}""")))
    }
}
