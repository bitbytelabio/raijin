package io.bitbytelab.raijin.core

import io.bitbytelab.raijin.core.ParamMinerWordlists.Entry
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ParamMinerWordlistsTest {

    @Test
    fun `explicit candidates are used as-is regardless of wordlistName`() {
        val resolved = ParamMinerWordlists.resolve(listOf("a", "b"), "does-not-matter")
        assertTrue(resolved is ParamMinerWordlists.Resolved.Ok)
        assertEquals(listOf("a", "b"), resolved.candidates)
    }

    @Test
    fun `an unknown wordlist name is an error, not a silent empty scan`() {
        // Exactly the reported bug shape: a typo like "param-miner-param" (missing the trailing
        // 's') must not resolve to an empty candidate list that looks like a clean scan.
        val resolved = ParamMinerWordlists.resolve(null, "param-miner-param")
        assertTrue(resolved is ParamMinerWordlists.Resolved.Error)
        assertTrue(resolved.message.contains("Unknown wordlist"))
    }

    @Test
    fun `the default bundled wordlist resolves to a non-empty candidate list`() {
        val resolved = ParamMinerWordlists.resolve(null, ParamMinerWordlists.DEFAULT)
        assertTrue(resolved is ParamMinerWordlists.Resolved.Ok)
        assertTrue(resolved.candidates.isNotEmpty())
    }

    @Test
    fun `the header wordlist also resolves to a non-empty candidate list`() {
        val resolved = ParamMinerWordlists.resolve(null, "param-miner-headers")
        assertTrue(resolved is ParamMinerWordlists.Resolved.Ok)
        assertTrue(resolved.candidates.isNotEmpty())
    }

    @Test
    fun `a line with a value template is split into name and template`() {
        assertEquals(Entry("host", "%h:%s"), ParamMinerWordlists.parseLine("host~%h:%s"))
        assertEquals(Entry("origin", "https://%s.%h"), ParamMinerWordlists.parseLine("  origin~https://%s.%h  "))
        assertEquals(Entry("x-original-url", "/%s"), ParamMinerWordlists.parseLine("x-original-url~/%s"))
        assertEquals(Entry("x-forwarded-proto", "http"), ParamMinerWordlists.parseLine("x-forwarded-proto~http"))
        assertEquals(Entry("accept"), ParamMinerWordlists.parseLine("accept"))
        // No name before the tilde, or nothing after it: the line is a name as written.
        assertEquals(Entry("~x"), ParamMinerWordlists.parseLine("~x"))
        assertEquals(Entry("x~"), ParamMinerWordlists.parseLine("x~"))
    }

    @Test
    fun `comments and blank lines are not entries`() {
        assertNull(ParamMinerWordlists.parseLine(""))
        assertNull(ParamMinerWordlists.parseLine("   "))
        assertNull(ParamMinerWordlists.parseLine("# Vendored from somewhere"))
        assertEquals(
            listOf(Entry("a"), Entry("host", "%h:%s"), Entry("b")),
            ParamMinerWordlists.parse("# comment\na\n\nhost~%h:%s\r\nb\na\n"),
        )
    }

    @Test
    fun `a template is filled with the canary and the target host`() {
        assertEquals("t.example:CANARY", Entry("host", "%h:%s").value("CANARY", "t.example"))
        assertEquals("https://CANARY.t.example", Entry("origin", "https://%s.%h").value("CANARY", "t.example"))
        assertEquals("/CANARY", Entry("x-original-url", "/%s").value("CANARY", "t.example"))
        assertEquals("http", Entry("x-forwarded-proto", "http").value("CANARY", "t.example"))
        assertEquals("CANARY", Entry("accept").value("CANARY", "t.example"))
    }

    @Test
    fun `the bundled header list carries its templates as values, never in a header name`() {
        val entries = ParamMinerWordlists.entries(ParamMinerWordlists.HEADERS)
        assertTrue(entries.none { '~' in it.name }, "a header name still carries its template")
        assertTrue(Entry("host", "%h:%s") in entries)
        assertTrue(Entry("origin", "https://%s.%h") in entries)
        assertTrue(Entry("x-forwarded-host", "%s.%h") in entries)
        assertTrue(Entry("x-original-url", "/%s") in entries)
        // The same header is also listed bare: both ways of sending it are candidates.
        assertTrue(Entry("host") in entries)
        assertEquals(entries.size, entries.toSet().size)

        val names = ParamMinerWordlists.load(ParamMinerWordlists.HEADERS)
        assertTrue(names.none { '~' in it })
        assertEquals(names.size, names.toSet().size)
        assertEquals(1, names.count { it == "host" })
    }

    @Test
    fun `the bundled parameter list is served whole`() {
        val entries = ParamMinerWordlists.entries(ParamMinerWordlists.DEFAULT)
        assertTrue(entries.size > 6000, "only ${entries.size} entries")
        assertTrue(entries.all { it.valueTemplate == null && it.name.isNotBlank() && !it.name.startsWith("#") })
        assertEquals(entries.map { it.name }, (ParamMinerWordlists.resolve(null, ParamMinerWordlists.DEFAULT) as ParamMinerWordlists.Resolved.Ok).candidates)
    }

    @Test
    fun `explicit candidates may carry their own value template`() {
        val resolved = ParamMinerWordlists.resolve(listOf("x-forwarded-host~%s.%h", "plain", "", "plain"), "ignored")
        assertTrue(resolved is ParamMinerWordlists.Resolved.Ok)
        assertEquals(listOf(Entry("x-forwarded-host", "%s.%h"), Entry("plain")), resolved.entries)
        assertEquals(listOf("x-forwarded-host", "plain"), resolved.candidates)
    }

    @Test
    fun `an unknown list has no entries and a known one is read once`() {
        assertTrue(ParamMinerWordlists.entries("no-such-list").isEmpty())
        assertSame(ParamMinerWordlists.entries(ParamMinerWordlists.DEFAULT), ParamMinerWordlists.entries(ParamMinerWordlists.DEFAULT))
    }

    @Test
    fun `lists can be loaded from many threads at once`() {
        val pool = Executors.newFixedThreadPool(16)
        try {
            val tasks = List(64) { i ->
                Callable { ParamMinerWordlists.entries(if (i % 2 == 0) ParamMinerWordlists.DEFAULT else ParamMinerWordlists.HEADERS).size }
            }
            val sizes = pool.invokeAll(tasks).map { it.get() }
            assertEquals(setOf(ParamMinerWordlists.entries(ParamMinerWordlists.DEFAULT).size, ParamMinerWordlists.entries(ParamMinerWordlists.HEADERS).size), sizes.toSet())
        } finally {
            pool.shutdownNow()
        }
    }
}
