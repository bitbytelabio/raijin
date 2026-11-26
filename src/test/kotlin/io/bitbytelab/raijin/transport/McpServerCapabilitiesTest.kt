package io.bitbytelab.raijin.transport

import io.github.oshai.kotlinlogging.DirectLoggerFactory
import io.github.oshai.kotlinlogging.KotlinLoggingConfiguration
import io.github.oshai.kotlinlogging.Level
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Guards what the server tells a client on initialize. The playbooks ship with the raijin CLI, not here. */
class McpServerCapabilitiesTest {

    @Test
    fun `server declares tools and resources, no prompts`() {
        val caps = McpServerManager.serverCapabilities()
        assertNotNull(caps.tools, "tools capability")
        assertNotNull(caps.resources, "resources capability")
        assertNull(caps.prompts, "the extension serves no prompts")
    }

    @Test fun `server declares no resource subscriptions or list notifications it does not send`() {
        val caps = McpServerManager.serverCapabilities()
        assertEquals(false, caps.resources?.subscribe, "resources are read on demand; no updates are pushed")
        assertEquals(false, caps.resources?.listChanged, "the resource list never changes while a session is open")
    }

    @Test
    fun `instructions are short and name no skill transport`() {
        val text = McpServerManager.SERVER_INSTRUCTIONS
        // omp keeps only the first 4000 characters of server instructions.
        assertTrue(text.length < 4000, "instructions are ${text.length} characters")
        assertFalse(text.contains("skill://"), "instructions name a skill resource")
        assertFalse(text.contains("load_skill"), "instructions name load_skill")
    }

    @Test
    fun `sdk logging is silenced to errors without slf4j startup noise`() {
        McpServerManager.silenceSdkLogging()
        assertEquals("false", System.getProperty("kotlin-logging.logStartupMessage"))
        assertEquals(false, KotlinLoggingConfiguration.logStartupMessage)
        assertSame(DirectLoggerFactory, KotlinLoggingConfiguration.loggerFactory)
        assertEquals(Level.ERROR, KotlinLoggingConfiguration.direct.logLevel)
    }
}
