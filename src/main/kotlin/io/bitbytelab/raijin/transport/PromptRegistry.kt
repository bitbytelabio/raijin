package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.skills.SkillCatalog
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.GetPromptResult
import io.modelcontextprotocol.kotlin.sdk.types.PromptMessage
import io.modelcontextprotocol.kotlin.sdk.types.Role
import io.modelcontextprotocol.kotlin.sdk.types.TextContent

/**
 * Serves every skill as an MCP prompt, named after the skill (`http-testing`, ...).
 *
 * This is what makes skills show up in clients: Claude Code lists a server's prompts as slash
 * commands (`/mcp__burpsuite__http-testing`) and omp as `burpsuite:http-testing`. Both only ask a
 * server for prompts when it advertises the `prompts` capability, so [McpServerManager.serverCapabilities]
 * must keep declaring it (the SDK also refuses [Server.addPrompt] without it).
 *
 * The same text is served as `skill://burpsuite/<name>` resources by [ResourceRegistry], which is how
 * a model reads a skill on its own. Skills are static guides, so prompts take no arguments.
 */
object PromptRegistry {

    /** Registers one prompt per [SkillCatalog] skill on [server]. Called once per server instance. */
    fun registerAll(server: Server) {
        SkillCatalog.list().forEach { skill ->
            server.addPrompt(name = skill.name, description = skill.description) {
                GetPromptResult(
                    messages = listOf(PromptMessage(Role.User, TextContent(skill.body))),
                    description = skill.description
                )
            }
        }
    }
}
