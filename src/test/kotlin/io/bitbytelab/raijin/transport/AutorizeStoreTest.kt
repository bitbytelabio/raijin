package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.state.AutorizeMatch
import io.bitbytelab.raijin.state.AutorizeReplay
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Per-project persistence of the Autorize matches: what a reload restores, and how the file stays bounded. */
class AutorizeStoreTest {

    private val dir: File = Files.createTempDirectory("raijin-autorize-store").toFile()

    @AfterTest
    fun cleanUp() {
        dir.deleteRecursively()
    }

    private fun match(id: Long, softDenial: Boolean = false, response: String = "HTTP/1.1 200 OK\r\n\r\n{\"id\":$id}") = AutorizeMatch(
        id = id,
        ruleId = "arule-001",
        timestamp = "2026-11-17T10:00:0${id % 10}Z",
        method = "GET",
        url = "https://shop.test/api/orders?id=$id",
        originalStatus = 200,
        findings = listOf(buildJsonObject { put("severity", "critical"); put("id", "cross_identity_match"); put("detail", "d") }),
        request = "GET /api/orders?id=$id HTTP/1.1\r\nCookie: session=admin\r\n\r\n",
        response = response,
        replays = listOf(
            AutorizeReplay("low", 200, "GET /api/orders?id=$id HTTP/1.1\r\nCookie: session=low\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n{}"),
            AutorizeReplay("none", 401, "GET /api/orders?id=$id HTTP/1.1\r\n\r\n", "HTTP/1.1 401 Unauthorized\r\n\r\n"),
        ),
        softDenial = softDenial,
    )

    @Test
    fun `a match round-trips with its replays and soft-denial flag`() {
        val original = match(3, softDenial = true)
        val (back, project) = AutorizeStore.parseEntry(AutorizeStore.buildEntry(original, "shop"))!!
        assertEquals(original, back)
        assertEquals("shop", project)
    }

    @Test
    fun `text that cannot be encoded is written with a replacement character instead of failing the write`() {
        val broken = match(1, response = "HTTP/1.1 200 OK\r\n\r\nbad\uD800half")
        val (back, _) = AutorizeStore.parseEntry(AutorizeStore.buildEntry(broken, "shop"))!!
        assertEquals("HTTP/1.1 200 OK\r\n\r\nbad\uFFFDhalf", back.response)
    }

    @Test
    fun `malformed lines are skipped`() {
        assertNull(AutorizeStore.parseEntry("not json {"))
        assertNull(AutorizeStore.parseEntry(""))
    }

    @Test
    fun `a project's newest matches come back newest first`() {
        val parsed = listOf(match(1) to "shop", match(2) to "other", match(3) to "shop", match(4) to "shop")
        assertEquals(listOf(4L, 3L), AutorizeStore.selectForProject(parsed, "shop", 2).map { it.id })
        assertEquals(listOf(2L), AutorizeStore.selectForProject(parsed, "other", 10).map { it.id })
        assertEquals(listOf(1L, 1L), AutorizeStore.dedupe(listOf(match(1) to "shop", match(1) to "shop", match(1) to "other")).map { it.first.id })
    }

    @Test
    fun `the file store appends, loads per project and rewrites one project on clear`() {
        val file = File(dir, "autorize.jsonl")
        val store = AutorizeFileStore(file)
        store.append(match(1), "shop")
        store.append(match(2), "other")
        store.append(match(3, softDenial = true), "shop")

        val restored = store.load("shop", 10)
        assertEquals(listOf(3L, 1L), restored.map { it.id })
        assertTrue(restored.first().softDenial)
        assertEquals(listOf("low", "none"), restored.first().replays.map { it.identity })

        store.replaceProject("shop") { listOf(match(3)) }
        assertEquals(listOf(3L), store.load("shop", 10).map { it.id })
        assertEquals(listOf(2L), store.load("other", 10).map { it.id }, "other projects' matches are kept")

        store.replaceProject("shop") { emptyList() }
        store.replaceProject("other") { emptyList() }
        assertFalse(file.exists(), "an empty store leaves no file behind")
        assertNull(store.lastError)
    }

    @Test
    fun `a store past its size keeps its newest lines`() {
        val file = File(dir, "autorize.jsonl")
        val store = AutorizeFileStore(file, maxBytes = 6_000)
        (1L..20L).forEach { store.append(match(it), "shop") }

        assertTrue(file.length() <= 6_000, "trimmed to its budget (${file.length()} bytes)")
        val kept = store.load("shop", 100).map { it.id }
        assertEquals(20L, kept.first(), "the newest match is always kept")
        assertEquals(kept.sortedDescending(), kept)
        assertTrue(kept.size < 20)
    }

    @Test
    fun `trimming keeps the newest lines that fit, and always the newest one`() {
        assertEquals(listOf("bbbbbbbbbb", "cccccccccc"), AutorizeStore.newestWithin(listOf("aaaaaaaaaa", "bbbbbbbbbb", "cccccccccc"), 25))
        assertEquals(listOf("xxxxx"), AutorizeStore.newestWithin(listOf("xxxxx"), 1))
        assertEquals(emptyList(), AutorizeStore.newestWithin(emptyList(), 100))
    }
}
