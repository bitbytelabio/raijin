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

    private fun row(list: String, index: Int, rule: String, enabled: Boolean = true) = listOf<Any?>(list, index, enabled, rule)

    @Test
    fun `a reload keeps the selection on the same rule, not the first rule of its list`() {
        val before = listOf(row("Include", 0, "https://a.test"), row("Include", 1, "https://b.test"), row("Exclude", 0, "https://a.test"))
        val after = listOf(
            row("Include", 0, "https://new.test"),
            row("Include", 1, "https://a.test"),
            row("Include", 2, "https://b.test", enabled = false),
            row("Exclude", 0, "https://a.test"),
        )

        assertEquals(2, ScopeViewerPanel.sameRuleRow(before, 1, after), "moved down a row and disabled, still the same rule")
        assertEquals(3, ScopeViewerPanel.sameRuleRow(before, 2, after), "the exclude rule, not the include rule with the same text")
        assertEquals(-1, ScopeViewerPanel.sameRuleRow(before, -1, after), "nothing was selected")
        val removed = after.filterNot { it[0] == "Include" && it[3] == "https://a.test" }
        assertEquals(-1, ScopeViewerPanel.sameRuleRow(before, 0, removed), "the selected rule is gone")
    }

    @Test
    fun `repeated rules keep which repeat was selected`() {
        val before = listOf(row("Include", 0, "https://a.test"), row("Include", 1, "https://a.test"))
        val after = listOf(row("Include", 0, "https://z.test"), row("Include", 1, "https://a.test"), row("Include", 2, "https://a.test"))

        assertEquals(1, ScopeViewerPanel.sameRuleRow(before, 0, after))
        assertEquals(2, ScopeViewerPanel.sameRuleRow(before, 1, after))
    }
}
