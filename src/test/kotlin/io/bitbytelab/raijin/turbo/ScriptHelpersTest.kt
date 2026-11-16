package io.bitbytelab.raijin.turbo

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ScriptHelpersTest {

    @Test
    fun `endpoint brackets IPv6 hosts only`() {
        assertEquals("https://example.com:443", turboEndpoint("https", "example.com", 443))
        assertEquals("http://10.0.0.1:8080", turboEndpoint("http", "10.0.0.1", 8080))
        assertEquals("https://[::1]:8443", turboEndpoint("https", "::1", 8443))
    }

    @Test
    fun `script newlines become CRLF whatever the editor produced`() {
        assertEquals("a\r\nb\r\n", normalizeScriptNewlines("a\nb\n"))
        assertEquals("a\r\nb\r\n", normalizeScriptNewlines("a\r\nb\r\n"))
        assertEquals("a\r\nb\r\nc", normalizeScriptNewlines("a\r\nb\nc"))
        assertEquals("plain", normalizeScriptNewlines("plain"))
    }

    @Test
    fun `example list drops directories, hidden files and __init__ and sorts`() {
        val entries = listOf(
            "examples/", "examples/zeta.py", "examples/__init__.py", "examples/.hidden.py",
            "examples/basic.py", "examples/request.txt", "examples/sub/",
        )
        assertEquals(
            listOf("examples/basic.py", "examples/request.txt", "examples/zeta.py"),
            exampleScriptNames(entries),
        )
    }

    @Test
    fun `user scripts are sorted, hidden files skipped, missing dir is empty`() {
        val dir = Files.createTempDirectory("turbo-scripts").toFile()
        try {
            File(dir, "b.py").writeText("b")
            File(dir, "a.py").writeText("a")
            File(dir, ".secret.py").writeText("x")
            val items = userScriptItems(dir)
            assertEquals(listOf("a.py", "b.py"), items.map { it.name })
            assertEquals(File(dir, "a.py").absolutePath, items[0].fullPath)
            assertEquals("a.py", items[0].toString())
        } finally {
            dir.deleteRecursively()
        }
        assertTrue(userScriptItems(File(dir, "gone")).isEmpty())
    }

    @Test
    fun `table model returns null for rows outside the model`() {
        val model = RequestTableModel()
        assertNull(model.getRequest(-1))
        assertNull(model.getRequest(0))
        val first = Request("GET / HTTP/1.1\r\n\r\n", emptyList(), 0)
        val second = Request("GET /b HTTP/1.1\r\n\r\n", emptyList(), 0)
        model.addRows(listOf(first, second))
        assertEquals(2, model.rowCount)
        assertEquals(second, model.getRequest(1))
        assertNull(model.getRequest(2))
    }

    @Test
    fun `connection id column sorts as text`() {
        // The value is a String (or ""), so an Integer column class made the row sorter throw.
        assertEquals(String::class.java, RequestTableModel().getColumnClass(11))
    }
}
