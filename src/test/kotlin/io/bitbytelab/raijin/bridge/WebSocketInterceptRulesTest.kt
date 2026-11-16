package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.state.WebSocketInterceptRule
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * [WebSocketInterceptRules.evaluate]: what the rules do to one frame, text or binary, in the order
 * they are listed.
 */
class WebSocketInterceptRulesTest {

    private val url = "wss://chat.test/ws"

    private fun rule(
        id: String,
        action: String,
        matchMessage: String? = null,
        modifyRegex: String? = null,
        replacement: String? = null,
        direction: String = "both",
        matchUrl: String? = null,
        messageType: String? = null,
        enabled: Boolean = true,
    ) = WebSocketInterceptRule(
        ruleId = id, matchUrl = matchUrl, matchMessage = matchMessage, direction = direction, action = action,
        modifyRegex = modifyRegex, modifyReplacement = replacement, enabled = enabled, messageType = messageType,
    )

    private fun evaluate(
        rules: List<WebSocketInterceptRule>,
        content: String,
        binary: Boolean = false,
        direction: String = "client_to_server",
        url: String? = this.url,
        tagged: MutableList<String> = ArrayList(),
    ) = WebSocketInterceptRules.evaluate(rules, url, direction, binary, { content }, { tagged += it.ruleId })

    @Test
    fun `modify rules apply in order, each on the result of the previous one`() {
        val rules = listOf(
            rule("a", "modify", modifyRegex = "user", replacement = "admin"),
            rule("b", "modify", matchMessage = "admin", modifyRegex = "\"role\":\"\\w+\"", replacement = "\"role\":\"root\""),
        )

        val outcome = evaluate(rules, """{"name":"user","role":"guest"}""")

        assertEquals(WebSocketInterceptRules.Outcome.Modify("""{"name":"admin","role":"root"}"""), outcome)
    }

    @Test
    fun `the first matching drop wins, also after a modify made it match`() {
        val tagged = ArrayList<String>()
        val rules = listOf(
            rule("rewrite", "modify", modifyRegex = "ping", replacement = "pong"),
            rule("drop-pong", "drop", matchMessage = "pong"),
            rule("tag-after", "tag"),
        )

        assertEquals(WebSocketInterceptRules.Outcome.Drop, evaluate(rules, "ping", tagged = tagged))
        assertTrue(tagged.isEmpty(), "rules after the drop are not evaluated")
    }

    @Test
    fun `tag rules report the frame and let it through`() {
        val tagged = ArrayList<String>()
        val rules = listOf(rule("t1", "tag", matchMessage = "secret"), rule("t2", "tag", matchMessage = "nothing"))

        assertEquals(WebSocketInterceptRules.Outcome.Continue, evaluate(rules, "a secret", tagged = tagged))
        assertEquals(listOf("t1"), tagged)
    }

    @Test
    fun `direction, URL, frame kind and enabled state limit where a rule applies`() {
        val drop = listOf(rule("d", "drop", direction = "server_to_client"))
        assertEquals(WebSocketInterceptRules.Outcome.Continue, evaluate(drop, "x", direction = "client_to_server"))
        assertEquals(WebSocketInterceptRules.Outcome.Drop, evaluate(drop, "x", direction = "server_to_client"))

        val byUrl = listOf(rule("u", "drop", matchUrl = "chat\\.test"))
        assertEquals(WebSocketInterceptRules.Outcome.Drop, evaluate(byUrl, "x"))
        assertEquals(WebSocketInterceptRules.Outcome.Continue, evaluate(byUrl, "x", url = "wss://other.test/ws"))
        assertEquals(WebSocketInterceptRules.Outcome.Continue, evaluate(byUrl, "x", url = null))

        val binaryOnly = listOf(rule("b", "drop", messageType = "BINARY"))
        assertEquals(WebSocketInterceptRules.Outcome.Continue, evaluate(binaryOnly, "x", binary = false))
        assertEquals(WebSocketInterceptRules.Outcome.Drop, evaluate(binaryOnly, "x", binary = true))
        val textOnly = listOf(rule("t", "drop", messageType = "TEXT"))
        assertEquals(WebSocketInterceptRules.Outcome.Continue, evaluate(textOnly, "x", binary = true))

        assertEquals(WebSocketInterceptRules.Outcome.Continue, evaluate(listOf(rule("off", "drop", enabled = false)), "x"))
    }

    @Test
    fun `a binary frame is matched and rewritten as its bytes, and maps back to bytes exactly`() {
        val original = byteArrayOf(0x00, 0x01, 0xFF.toByte(), 0x41, 0x7F)
        val rules = listOf(rule("bin", "modify", matchMessage = "^\\x00", modifyRegex = "\\x01\\xFF", replacement = "\u00AB\u00CD"))

        val outcome = evaluate(rules, WebSocketFrames.latin1(original), binary = true)

        val modified = (outcome as WebSocketInterceptRules.Outcome.Modify).content
        assertContentEquals(byteArrayOf(0x00, 0xAB.toByte(), 0xCD.toByte(), 0x41, 0x7F), WebSocketFrames.latin1Bytes(modified))
    }

    @Test
    fun `a rule whose regex cannot run counts as no match`() {
        val rules = listOf(rule("bad", "drop", matchMessage = "(unclosed"), rule("bad-modify", "modify", modifyRegex = "(", replacement = "x"))
        assertEquals(WebSocketInterceptRules.Outcome.Continue, evaluate(rules, "(unclosed"))
    }

    @Test
    fun `the content is read once, and only when a rule looks at it`() {
        var reads = 0
        val content = { reads++; "payload" }
        WebSocketInterceptRules.evaluate(listOf(rule("t", "tag"), rule("d", "drop", direction = "server_to_client")), url, "client_to_server", false, content) {}
        assertEquals(0, reads)

        val rules = listOf(rule("m1", "tag", matchMessage = "pay"), rule("m2", "modify", modifyRegex = "load", replacement = "LOAD"), rule("m3", "tag", matchMessage = "LOAD"))
        val outcome = WebSocketInterceptRules.evaluate(rules, url, "client_to_server", false, content) {}
        assertEquals(1, reads)
        assertEquals(WebSocketInterceptRules.Outcome.Modify("payLOAD"), outcome)
    }

    @Test
    fun `a listed rule shows its criteria, and only the ones it has`() {
        val listed = WebSocketInterceptRules.toJson(rule("r", "modify", modifyRegex = "a", replacement = "b", messageType = "BINARY"))

        assertEquals("r", listed["rule_id"]!!.jsonPrimitive.content)
        assertEquals("modify", listed["action"]!!.jsonPrimitive.content)
        assertEquals("both", listed["direction"]!!.jsonPrimitive.content)
        assertTrue(listed["enabled"]!!.jsonPrimitive.boolean)
        assertEquals("BINARY", listed["message_type"]!!.jsonPrimitive.content)
        assertEquals("b", listed["modify_replacement"]!!.jsonPrimitive.content)
        assertNull(listed["match_url"])
        assertNull(listed["tag_comment"])
    }
}
