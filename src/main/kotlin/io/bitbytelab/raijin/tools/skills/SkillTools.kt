package io.bitbytelab.raijin.tools.skills

import io.bitbytelab.raijin.skills.SkillCatalog
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.*

/**
 * Skill tools: let a client discover and load the usage guides in [SkillCatalog].
 * Start with `skill_list`, then `skill_get("raijin-overview")`.
 */
object SkillTools {

    private fun text(json: JsonElement, isError: Boolean = false) =
        CallToolResult(content = listOf(TextContent(json.toString())), isError = isError)

    fun register(server: Server) {

        server.addTool(
            name = "skill_list",
            description = "List the Raijin usage skills (guides for tool groups and workflows). " +
                "Call this first when you are new to this server, then load what you need with action get. " +
                "Start with '${SkillCatalog.ENTRY_SKILL}'.",
            inputSchema = ToolSchema(properties = buildJsonObject {}, required = emptyList())
        ) {
            text(buildJsonObject {
                put("entry", SkillCatalog.ENTRY_SKILL)
                putJsonArray("skills") {
                    SkillCatalog.list().forEach { s ->
                        addJsonObject {
                            put("name", s.name)
                            put("description", s.description)
                            put("uri", SkillCatalog.uri(s.name))
                        }
                    }
                }
            })
        }

        server.addTool(
            name = "skill_get",
            description = "Load one Raijin usage skill by name (see action list). Returns markdown with the " +
                "relevant tools, workflow steps and scope rules.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("name") {
                        put("type", "string")
                        put("description", "Skill name from the list action, e.g. raijin-overview")
                    }
                },
                required = listOf("name")
            )
        ) { req ->
            val name = req.params.arguments?.get("name")?.jsonPrimitive?.contentOrNull?.trim()
            val skill = name?.let { SkillCatalog.get(it) }
            if (skill == null) {
                text(buildJsonObject {
                    put("error", "unknown_skill")
                    putJsonArray("available") { SkillCatalog.list().forEach { add(it.name) } }
                }, isError = true)
            } else {
                text(buildJsonObject {
                    put("name", skill.name)
                    put("description", skill.description)
                    put("content", skill.body)
                })
            }
        }
    }
}
