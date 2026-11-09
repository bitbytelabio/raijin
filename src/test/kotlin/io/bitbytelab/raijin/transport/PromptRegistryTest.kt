package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.skills.SkillCatalog
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
    fun `every skill is a prompt with the skill's name and description`() {
        val server = registered()
        assertEquals(SkillCatalog.NAMES.toSet(), server.prompts.keys)
        SkillCatalog.list().forEach { skill ->
            val prompt = server.prompts.getValue(skill.name).prompt
            assertEquals(skill.name, prompt.name)
            assertEquals(skill.description, prompt.description)
            assertTrue(prompt.arguments.isNullOrEmpty(), "${skill.name} is a static guide and takes no arguments")
        }
    }

    @Test
    fun `getting a prompt returns the skill body as one user message`() {
        val server = registered()
        runBlocking {
            SkillCatalog.list().forEach { skill ->
                val request = GetPromptRequest(GetPromptRequestParams(skill.name))
                val result = server.prompts.getValue(skill.name).messageProvider(request)
                val message = result.messages.single()
                assertEquals(Role.User, message.role, skill.name)
                assertEquals(skill.body, (message.content as TextContent).text, skill.name)
            }
        }
    }

    @Test
    fun `skill names are valid prompt names`() {
        // Clients turn the name into a slash command (/mcp__burpsuite__<name>, burpsuite:<name>).
        val valid = Regex("[a-z0-9]+(-[a-z0-9]+)*")
        SkillCatalog.NAMES.forEach { assertTrue(valid.matches(it), "'$it' is not a lowercase hyphenated name") }
    }
}
