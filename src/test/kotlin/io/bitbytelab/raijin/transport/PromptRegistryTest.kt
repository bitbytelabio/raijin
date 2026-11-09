package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.skills.SkillCatalog
import io.bitbytelab.raijin.testClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.GetPromptRequest
import io.modelcontextprotocol.kotlin.sdk.types.GetPromptRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.Role
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PromptRegistryTest {

    /** A server with the same capabilities the real one advertises (the SDK needs `prompts` to accept a prompt). */
    private fun registered(): Server {
        val server = Server(Implementation("t", "0"), ServerOptions(McpServerManager.serverCapabilities()))
        PromptRegistry.registerAll(server)
        return server
    }

    @Test
    fun `every skill is a prompt named by promptName with the skill's description`() {
        val server = registered()
        assertEquals(SkillCatalog.NAMES.map { SkillCatalog.promptName(it) }.toSet(), server.prompts.keys)
        SkillCatalog.list().forEach { skill ->
            val prompt = server.prompts.getValue(SkillCatalog.promptName(skill.name)).prompt
            assertEquals(SkillCatalog.promptName(skill.name), prompt.name)
            assertEquals(skill.description, prompt.description)
            assertTrue(prompt.arguments.isNullOrEmpty(), "${skill.name} is a static guide and takes no arguments")
        }
    }

    @Test
    fun `getting a prompt returns the skill body as one user message`() {
        val server = registered()
        runBlocking {
            SkillCatalog.list().forEach { skill ->
                val name = SkillCatalog.promptName(skill.name)
                val result = server.prompts.getValue(name)
                    .messageProvider(testClientConnection, GetPromptRequest(GetPromptRequestParams(name)))
                val message = result.messages.single()
                assertEquals(Role.User, message.role, name)
                assertEquals(skill.body, (message.content as TextContent).text, name)
            }
        }
    }

    @Test
    fun `prompt names are unique, snake case and end in _skill`() {
        // Clients turn the name into a slash command (/mcp__burpsuite__<name>, burpsuite:<name>) and
        // their pickers filter on it: only names containing "skill" are found by typing `skill`.
        val valid = Regex("[a-z0-9]+(_[a-z0-9]+)*_skill")
        val names = SkillCatalog.NAMES.map { SkillCatalog.promptName(it) }
        names.forEach { assertTrue(valid.matches(it), "'$it' is not snake_case ending in _skill") }
        assertEquals(names.size, names.toSet().size, "two skills map to the same prompt name")
    }
}
