package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.bridge.HttpBridge
import io.bitbytelab.raijin.events.EventBus
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class P1RegressionTest {

    @Test
    fun `SecurityConfig formats bracketed IPv6 allowlists and lowercases hosts`() {
        val (hosts, origins) = SecurityConfig.buildAllowlists(listOf("::1", "LOCALHOST"), listOf(9876))
        assertEquals(setOf("[::1]:9876", "localhost:9876"), hosts)
        assertEquals(setOf("http://[::1]:9876", "http://localhost:9876"), origins)
    }

    @Test
    fun `PortPolicy duplicatePortMessages flags shared ports cleanly`() {
        assertTrue(PortPolicy.duplicatePortMessages(9876, 9877, 9878).isEmpty())
        val conflicts = PortPolicy.duplicatePortMessages(9876, 9876, 9878)
        assertEquals(1, conflicts.size)
        assertTrue("9876" in conflicts.first())
    }

    @Test
    fun `EventBus subscribeInternal survives clear and size stays O(1) accurate`() {
        val bus = EventBus(maxBufferSize = 3)
        val internalEvents = mutableListOf<Long>()
        val clientEvents = mutableListOf<Long>()
        bus.subscribeInternal(emptyList()) { internalEvents += it.id }
        bus.subscribe(emptyList()) { clientEvents += it.id }

        repeat(5) { bus.emit("test.event", kotlinx.serialization.json.buildJsonObject {}) }
        assertEquals(3, bus.size())
        assertEquals(listOf(3L, 4L, 5L), bus.getRecentEvents(5).map { it.id })
        assertEquals(5, internalEvents.size)
        assertEquals(5, clientEvents.size)

        bus.clear()
        assertEquals(0, bus.size())

        bus.emit("test.event", kotlinx.serialization.json.buildJsonObject {})
        assertEquals(6, internalEvents.size, "internal subscriber must survive EventBus.clear()")
        assertEquals(5, clientEvents.size, "client subscriber should be removed by EventBus.clear()")

        bus.clearAll()
        bus.emit("test.event", kotlinx.serialization.json.buildJsonObject {})
        assertEquals(6, internalEvents.size, "clearAll() removes internal subscribers too")
    }

    @Test
    fun `AuditFileStore locks concurrent writes and rotates beyond maxLines`() {
        val tempFile = File.createTempFile("raijin-audit-test", ".jsonl")
        try {
            tempFile.delete()
            val store = AuditFileStore(tempFile, maxLines = 10, retainLines = 6)
            val pool = Executors.newFixedThreadPool(4)
            val latch = CountDownLatch(12)
            repeat(12) { idx ->
                pool.submit {
                    try {
                        store.record(
                            "turbo_run", "2026-01-01T00:00:00Z", idx.toLong(), false,
                            mapOf("arr" to buildJsonArray { add("x") }), "", "", "", 0
                        )
                    } finally {
                        latch.countDown()
                    }
                }
            }
            latch.await()
            pool.shutdownNow()

            store.compactIfNeeded()
            val lines = tempFile.readLines()
            assertTrue(lines.size <= 10, "expected rotation to keep <= 10 lines, got ${lines.size}")
            lines.forEach { line ->
                val obj = Json.parseToJsonElement(line).jsonObject
                assertEquals("turbo_run", obj["tool"]?.jsonPrimitive?.content)
            }
        } finally {
            tempFile.delete()
        }
    }

    @Test
    fun `ToolCallTracker shouldAudit covers mutating tools cleanly`() {
        assertTrue(ToolCallTracker.shouldAudit("turbo_run", "", "", false))
        assertTrue(ToolCallTracker.shouldAudit("http_race", "", "", false))
        assertTrue(ToolCallTracker.shouldAudit("config_set", "", "", false))
        assertFalse(ToolCallTracker.shouldAudit("util_base64_decode", "", "", false))
    }

    @Test
    fun `HttpBridge parseHostHeader handles IPv6 and never crosses CRLF`() {
        assertEquals("[::1]".let { "::1" to 8443 }, HttpBridge.parseHostHeader("GET / HTTP/1.1\r\nHost: [::1]:8443\r\nX-Port: 9999\r\n\r\n"))
        assertEquals("example.com" to null, HttpBridge.parseHostHeader("GET / HTTP/1.1\r\nHost: example.com\r\nX-Port: 9999\r\n\r\n"))
        assertEquals("example.com" to 8080, HttpBridge.parseHostHeader("GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"))
    }
}
