package io.bitbytelab.raijin.injection

import io.bitbytelab.raijin.injection.XssOracle.Fate
import io.bitbytelab.raijin.injection.XssOracle.Kind
import io.bitbytelab.raijin.injection.XssOracle.Reflection
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class XssOracleTest {

    private val token = "rjntok"

    /** Every probed character with the same [fate], except those in [others]. */
    private fun fates(fate: Fate, vararg others: Pair<Char, Fate>): Map<Char, Fate> =
        XssOracle.PROBE_CHARS.associateWith { fate } + others

    private fun kinds(html: String): List<Kind> = XssOracle.reflections(html, "CAN1").map { it.kind }

    /** True when [html], the response to a proof payload, shows the escape [breakout] expects. */
    private fun confirmed(breakout: XssOracle.Breakout, html: String): Boolean =
        XssOracle.reflections(html, token).any(breakout.confirms)

    // ---------------------------------------------------------------
    // Where a value is reflected
    // ---------------------------------------------------------------

    @Test
    fun `reflections are placed in their syntactic position`() {
        val html = "<html><head><title>T CAN1</title></head><body>" +
            "<p>hi CAN1</p>" +
            "<input value=\"CAN1\">" +
            "<a href='/x?CAN1'>l</a>" +
            "<div class=CAN1>d</div>" +
            "<!-- CAN1 -->" +
            "<script>var a = 'CAN1'; var b = \"x CAN1\"; var c = `CAN1`; var d = CAN1; // CAN1\n/* CAN1 */</script>" +
            "<textarea>CAN1</textarea>" +
            "<style>.CAN1{}</style>" +
            "</body></html>"
        assertEquals(
            listOf(
                Kind.RCDATA, Kind.HTML_TEXT, Kind.ATTR_DOUBLE, Kind.ATTR_SINGLE, Kind.ATTR_UNQUOTED, Kind.COMMENT,
                Kind.SCRIPT_SINGLE, Kind.SCRIPT_DOUBLE, Kind.SCRIPT_TEMPLATE, Kind.SCRIPT_CODE, Kind.SCRIPT_COMMENT, Kind.SCRIPT_COMMENT,
                Kind.RCDATA, Kind.STYLE,
            ),
            kinds(html),
        )
    }

    @Test
    fun `an attribute reflection knows its tag, attribute and what precedes it`() {
        val reflections = XssOracle.reflections("<form><a class=\"b\" href=\"/go?next=CAN1\">x</a><div CAN1></div><CAN1x></form>", "CAN1")
        assertEquals(Reflection(Kind.ATTR_DOUBLE, reflections[0].offset, "a", "href", "/go?next="), reflections[0])
        assertEquals(Kind.TAG, reflections[1].kind)
        assertEquals("can1", reflections[1].attribute)
        assertEquals(Kind.TAG, reflections[2].kind)
        assertEquals("can1x", reflections[2].tag)
        assertEquals("", reflections[2].attribute)
    }

    @Test
    fun `a script block that is data is not script code`() {
        assertEquals(listOf(Kind.SCRIPT_DATA), kinds("<script type=\"application/json\">{\"q\":\"CAN1\"}</script>"))
        assertEquals(listOf(Kind.SCRIPT_DOUBLE), kinds("<script type=\"text/javascript\">var q = \"CAN1\";</script>"))
        assertEquals(listOf(Kind.SCRIPT_CODE), kinds("<script type=module>go(CAN1)</script>"))
    }

    @Test
    fun `an escaped quote does not end a script string and text after the script is text again`() {
        assertEquals(listOf(Kind.SCRIPT_SINGLE), kinds("<script>var a = 'it\\'s CAN1';</script>"))
        assertEquals(listOf(Kind.HTML_TEXT), kinds("<script>var a = 'x';</script><p>CAN1</p>"))
        assertEquals(listOf(Kind.HTML_TEXT), kinds("<p>1 < 2 and CAN1</p>"))
    }

    @Test
    fun `only document content types render markup`() {
        assertTrue(XssOracle.rendersAsHtml("text/html; charset=utf-8", ""))
        assertTrue(XssOracle.rendersAsHtml("application/xhtml+xml", ""))
        assertFalse(XssOracle.rendersAsHtml("application/json", "<html>"))
        assertFalse(XssOracle.rendersAsHtml("text/plain", "<html>"))
        assertTrue(XssOracle.rendersAsHtml(null, "<!DOCTYPE html><html><body>x</body></html>"))
        assertFalse(XssOracle.rendersAsHtml(null, "{\"q\":\"x\"}"))
    }

    // ---------------------------------------------------------------
    // What happens to each character
    // ---------------------------------------------------------------

    @Test
    fun `the survival probe is read back character by character`() {
        assertEquals("H<->-\"-'-`-\\-/-(-)- -=T", XssOracle.survivalProbe("H", "T", "-"))

        val pieces = listOf("&lt;", "&gt;", "&quot;", "&#39;", "`", "\\\\", "/", "%28", "\\u0029", "", "=")
        val body = "<p>q: hEaD" + pieces.joinToString("sEp") + "tAiL</p>"
        val survival = XssOracle.survival(body, "head", "tail", "sep").single()
        assertEquals(body.indexOf("hEaD"), survival.offset)
        assertEquals(
            mapOf(
                '<' to Fate.HTML_ENTITY, '>' to Fate.HTML_ENTITY, '"' to Fate.HTML_ENTITY, '\'' to Fate.HTML_ENTITY,
                '`' to Fate.RAW, '\\' to Fate.BACKSLASH_ESCAPED, '/' to Fate.RAW, '(' to Fate.URL_ENCODED,
                ')' to Fate.JS_ESCAPED, ' ' to Fate.STRIPPED, '=' to Fate.RAW,
            ),
            survival.fates,
        )
    }

    @Test
    fun `an escaped quote and an unrecognised rewrite are told apart`() {
        val pieces = listOf("<", ">", "\\\"", "\\'", "`", "\\", "/", "(", ")", "+", "[eq]")
        val survival = XssOracle.survival("x" + "h1" + pieces.joinToString("|") + "t1", "h1", "t1", "|").single()
        assertEquals(Fate.BACKSLASH_ESCAPED, survival.fates['"'])
        assertEquals(Fate.BACKSLASH_ESCAPED, survival.fates['\''])
        assertEquals(Fate.RAW, survival.fates['\\'])
        assertEquals(Fate.URL_ENCODED, survival.fates[' '])
        assertEquals(Fate.OTHER, survival.fates['='])
    }

    @Test
    fun `a reflection that lost its tail or a separator is not assessed`() {
        assertTrue(XssOracle.survival("<p>head<sep>sep", "head", "tail", "sep").isEmpty())
        assertTrue(XssOracle.survival("<p>head<sep>tail</p>", "head", "tail", "sep").isEmpty())
        assertTrue(XssOracle.survival("<p>nothing here</p>", "head", "tail", "sep").isEmpty())
    }

    // ---------------------------------------------------------------
    // Whether the position can be left
    // ---------------------------------------------------------------

    @Test
    fun `HTML text is left by opening a tag, which the proof must show`() {
        val text = Reflection(Kind.HTML_TEXT, 0)
        val breakout = assertNotNull(XssOracle.breakout(text, fates(Fate.RAW), token))
        assertEquals("<rjntok x=1>", breakout.proof)
        assertTrue(confirmed(breakout, "<p>Results for <rjntok x=1></p>"))
        assertFalse(confirmed(breakout, "<p>Results for &lt;rjntok x=1&gt;</p>"), "encoded on the way back")
        assertFalse(confirmed(breakout, "<p>Results for rjntok x=1</p>"), "angle brackets stripped")

        assertNull(XssOracle.breakout(text, fates(Fate.RAW, '<' to Fate.HTML_ENTITY), token))
    }

    @Test
    fun `a quoted attribute is left through its quote`() {
        val value = Reflection(Kind.ATTR_DOUBLE, 0, "input", "value", "")
        val breakout = assertNotNull(XssOracle.breakout(value, fates(Fate.HTML_ENTITY, '"' to Fate.RAW), token))
        assertEquals("\"rjntok=\"", breakout.proof)
        assertTrue(confirmed(breakout, "<input value=\"\"rjntok=\"\">"))
        assertFalse(confirmed(breakout, "<input value=\"&quot;rjntok=&quot;\">"))

        val single = Reflection(Kind.ATTR_SINGLE, 0, "input", "value", "")
        assertEquals("'rjntok='", XssOracle.breakout(single, fates(Fate.HTML_ENTITY, '\'' to Fate.RAW), token)?.proof)
        assertNull(XssOracle.breakout(value, fates(Fate.HTML_ENTITY), token), "every special character encoded")
        assertNull(XssOracle.breakout(value, fates(Fate.RAW, '"' to Fate.HTML_ENTITY), token), "the wrong quote does not help")
    }

    @Test
    fun `an unquoted attribute is left with a space`() {
        val value = Reflection(Kind.ATTR_UNQUOTED, 0, "div", "class", "")
        val breakout = assertNotNull(XssOracle.breakout(value, fates(Fate.HTML_ENTITY, ' ' to Fate.RAW), token))
        assertTrue(confirmed(breakout, "<div class=x rjntok=1>d</div>"))
        assertFalse(confirmed(breakout, "<div class=x&#32;rjntok=1>d</div>"))
        assertNull(XssOracle.breakout(value, fates(Fate.HTML_ENTITY), token))
    }

    @Test
    fun `a link target the value starts can take a script scheme`() {
        val href = Reflection(Kind.ATTR_DOUBLE, 0, "a", "href", "")
        val breakout = assertNotNull(XssOracle.breakout(href, fates(Fate.HTML_ENTITY), token))
        assertEquals("javascript:rjntok", breakout.proof)
        assertTrue(confirmed(breakout, "<a href=\"javascript:rjntok\">x</a>"))
        assertFalse(confirmed(breakout, "<a href=\"/redirect?to=javascript:rjntok\">x</a>"))

        assertNull(XssOracle.breakout(href.copy(valuePrefix = "/go?next="), fates(Fate.HTML_ENTITY), token), "the value does not start the URL")
        assertNull(XssOracle.breakout(href.copy(tag = "img", attribute = "src"), fates(Fate.HTML_ENTITY), token), "an image source runs no script")
    }

    @Test
    fun `an event handler is script, where an entity-encoded quote still ends a string`() {
        val handler = Reflection(Kind.ATTR_DOUBLE, 0, "button", "onclick", "go('")
        val breakout = assertNotNull(XssOracle.breakout(handler, fates(Fate.HTML_ENTITY), token))
        assertEquals("'-rjntok-'", breakout.proof)
        assertTrue(confirmed(breakout, "<button onclick=\"go('&#39;-rjntok-&#39;')\">b</button>"))
        assertFalse(confirmed(breakout, "<button onclick=\"go('\\'-rjntok-\\'')\">b</button>"), "backslash-escaped instead")

        assertNull(XssOracle.breakout(handler, fates(Fate.STRIPPED), token))
        val code = handler.copy(valuePrefix = "track(")
        assertNull(XssOracle.breakout(code, fates(Fate.STRIPPED), token))
        assertNotNull(XssOracle.breakout(code, fates(Fate.HTML_ENTITY), token), "script code inside the handler")
    }

    @Test
    fun `a script string is left through its quote, a lone backslash, or the end of the script block`() {
        val string = Reflection(Kind.SCRIPT_SINGLE, 0, "script")
        val quote = assertNotNull(XssOracle.breakout(string, fates(Fate.HTML_ENTITY, '\'' to Fate.RAW), token))
        assertEquals("'-rjntok-'", quote.proof)
        assertTrue(confirmed(quote, "<script>var a = ''-rjntok-'';</script>"))
        assertFalse(confirmed(quote, "<script>var a = '\\'-rjntok-\\'';</script>"))

        val escaped = fates(Fate.HTML_ENTITY, '\'' to Fate.BACKSLASH_ESCAPED, '\\' to Fate.RAW, '/' to Fate.RAW)
        val backslash = assertNotNull(XssOracle.breakout(string, escaped, token))
        assertEquals("\\'-rjntok//", backslash.proof)
        assertTrue(confirmed(backslash, "<script>var a = '\\\\'-rjntok//';</script>"))

        val bothEscaped = fates(Fate.RAW, '\'' to Fate.BACKSLASH_ESCAPED, '\\' to Fate.BACKSLASH_ESCAPED)
        val close = assertNotNull(XssOracle.breakout(string, bothEscaped, token))
        assertEquals("</script><rjntok x=1>", close.proof)
        assertTrue(confirmed(close, "<script>var a = '</script><rjntok x=1>';</script>"))

        assertNull(XssOracle.breakout(string, fates(Fate.HTML_ENTITY, '\'' to Fate.BACKSLASH_ESCAPED, '\\' to Fate.BACKSLASH_ESCAPED), token))
    }

    @Test
    fun `comments, raw-text elements and data blocks are left by closing them`() {
        val comment = assertNotNull(XssOracle.breakout(Reflection(Kind.COMMENT, 0), fates(Fate.RAW), token))
        assertTrue(confirmed(comment, "<!-- note: --><rjntok x=1> -->"))

        val textarea = assertNotNull(XssOracle.breakout(Reflection(Kind.RCDATA, 0, "textarea"), fates(Fate.RAW), token))
        assertEquals("</textarea><rjntok x=1>", textarea.proof)
        assertTrue(confirmed(textarea, "<textarea></textarea><rjntok x=1></textarea>"))
        assertFalse(confirmed(textarea, "<textarea>&lt;/textarea&gt;&lt;rjntok x=1&gt;</textarea>"))

        assertNotNull(XssOracle.breakout(Reflection(Kind.SCRIPT_DATA, 0, "script"), fates(Fate.RAW), token))
        assertNull(XssOracle.breakout(Reflection(Kind.SCRIPT_DATA, 0, "script"), fates(Fate.RAW, '/' to Fate.BACKSLASH_ESCAPED), token))
        assertNull(XssOracle.breakout(Reflection(Kind.STYLE, 0, "style"), fates(Fate.RAW, '<' to Fate.HTML_ENTITY), token))
    }

    @Test
    fun `a value inside a tag or in script code needs no further proof`() {
        val inTag = assertNotNull(XssOracle.breakout(Reflection(Kind.TAG, 0, "div", "rjntok"), fates(Fate.RAW), token))
        assertNull(inTag.proof)
        assertNull(XssOracle.breakout(Reflection(Kind.TAG, 0, "div", "rjntok"), fates(Fate.RAW, '=' to Fate.HTML_ENTITY), token))

        val code = assertNotNull(XssOracle.breakout(Reflection(Kind.SCRIPT_CODE, 0, "script"), fates(Fate.HTML_ENTITY, '(' to Fate.RAW, ')' to Fate.RAW), token))
        assertNull(code.proof)
        assertNull(XssOracle.breakout(Reflection(Kind.SCRIPT_CODE, 0, "script"), fates(Fate.HTML_ENTITY), token))
    }
}
