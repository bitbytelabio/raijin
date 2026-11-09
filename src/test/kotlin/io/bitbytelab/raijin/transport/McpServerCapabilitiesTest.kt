package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.skills.SkillCatalog
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Guards what the server tells a client on initialize. Skills only reach Claude Code and omp as
 * slash commands if `prompts` is declared; without it they never call `prompts/list`.
 */
class McpServerCapabilitiesTest {

    @Test
    fun `server declares tools, resources and prompts`() {
        val caps = McpServerManager.serverCapabilities()
        assertNotNull(caps.tools, "tools capability")
        assertNotNull(caps.resources, "resources capability")
        assertNotNull(caps.prompts, "prompts capability: clients skip prompts/list without it, so no skill is listed")
    }

    @Test
    fun `instructions are short and point at the skills`() {
        val text = McpServerManager.SERVER_INSTRUCTIONS
        // omp keeps only the first 4000 characters of server instructions.
        assertTrue(text.length < 4000, "instructions are ${text.length} characters")
        assertTrue(text.contains(SkillCatalog.uri(SkillCatalog.ENTRY_SKILL)), "instructions must name the entry skill resource")
        SkillCatalog.NAMES.forEach {
            assertTrue(text.contains(it), "instructions lack skill '$it'")
            assertTrue(text.contains(SkillCatalog.promptName(it)), "instructions lack prompt '${SkillCatalog.promptName(it)}'")
        }
    }
}
