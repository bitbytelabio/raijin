package io.bitbytelab.raijin.transport

import io.bitbytelab.raijin.skills.SkillCatalog
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.GetPromptResult
import io.modelcontextprotocol.kotlin.sdk.types.PromptMessage
import io.modelcontextprotocol.kotlin.sdk.types.Role
import io.modelcontextprotocol.kotlin.sdk.types.TextContent

/**
 * Serves every skill as an MCP prompt named [SkillCatalog.promptName] (`http-testing` becomes
 * `http_testing_skill`).
 *
 * This is what makes skills show up in clients: Claude Code lists a server's prompts as slash
 * commands (`/mcp__burpsuite__http_testing_skill`) and omp as `burpsuite:http_testing_skill`. Both only
 * ask a server for prompts when it advertises the `prompts` capability, so
 * [McpServerManager.serverCapabilities] must keep declaring it (the SDK also refuses [Server.addPrompt]
 * without it). Both pickers filter on the command name, hence the `_skill` suffix: typing `skill`
 * finds every skill prompt, from every server.
 *
 * The same text is served as `skill://<name>/SKILL.md` resources by [ResourceRegistry], which is how
 * a model reads a skill on its own. Skills are static guides, so prompts take no arguments.
 */
object PromptRegistry {

    /** Registers one prompt per [SkillCatalog] skill on [server]. Called once per server instance. */
    fun registerAll(server: Server) {
        SkillCatalog.list().forEach { skill ->
            server.addPrompt(name = SkillCatalog.promptName(skill.name), description = skill.description) {
                GetPromptResult(
                    messages = listOf(PromptMessage(Role.User, TextContent(skill.body))),
                    description = skill.description
                )
            }
        }
    }
}
