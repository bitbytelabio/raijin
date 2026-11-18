package io.bitbytelab.raijin.tools.skills

import io.bitbytelab.raijin.skills.SkillCatalog
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.*

/**
 * Tool-based access to [SkillCatalog] for MCP clients/models that discover capabilities through
 * `tools/call` instead of reading `skill://<name>/SKILL.md` resources (`ResourceRegistry`) or
 * invoking MCP prompts (`PromptRegistry`).
 */
object SkillTools {

    fun register(server: Server) {
        server.addTool(
            name = "search_skills",
            description = "List or search Raijin's built-in Burp Suite guides by name or description. " +
                "Returns name, description, and skill:// URI; use load_skill for the full guide.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("query") {
                        put("type", "string")
                        put("description", "Case-insensitive substring match against name/description; omit to list every skill")
                    }
                    putJsonObject("limit") {
                        put("type", "integer")
                        put("description", "Maximum results, default 20")
                    }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val query = args["query"]?.jsonPrimitive?.contentOrNull?.trim()?.lowercase()
                val limit = (args["limit"]?.jsonPrimitive?.intOrNull ?: 20).coerceAtLeast(0)

                val matches = SkillCatalog.list().filter { skill ->
                    query.isNullOrEmpty() ||
                        skill.name.lowercase().contains(query) ||
                        skill.description.lowercase().contains(query)
                }

                val result = buildJsonObject {
                    put("total_matched", matches.size)
                    put("skills", buildJsonArray {
                        matches.take(limit).forEach { skill ->
                            add(buildJsonObject {
                                put("uri", SkillCatalog.uri(skill.name))
                                put("name", skill.name)
                                put("description", skill.description)
                            })
                        }
                    })
                }
                toolJsonResult(result)
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "load_skill",
            description = "Load a Raijin skill's full markdown guide by skill name (e.g. 'overview') or " +
                "skill://<name>/SKILL.md URI.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("name") {
                        put("type", "string")
                        put("description", "Skill name, e.g. 'overview' or 'http-testing'")
                    }
                    putJsonObject("uri") {
                        put("type", "string")
                        put("description", "Skill URI, e.g. 'skill://overview/SKILL.md'")
                    }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val nameArg = args["name"]?.jsonPrimitive?.contentOrNull?.trim()?.takeIf { it.isNotEmpty() }
                val uriArg = args["uri"]?.jsonPrimitive?.contentOrNull?.trim()?.takeIf { it.isNotEmpty() }
                if (nameArg == null && uriArg == null) {
                    return@addTool toolError("Provide 'name' or 'uri'")
                }

                val uriName = if (uriArg != null) {
                    if ("://" in uriArg) {
                        SkillCatalog.nameFromUri(uriArg) ?: return@addTool toolJsonResult(buildJsonObject {
                            put("error", "Malformed skill URI '$uriArg'; expected skill://<name>/SKILL.md")
                            put("error_code", "malformed_uri")
                        })
                    } else {
                        uriArg
                    }
                } else {
                    null
                }

                if (nameArg != null && uriName != null && nameArg != uriName) {
                    return@addTool toolError("Conflicting 'name' ('$nameArg') and 'uri' ('$uriArg')")
                }

                val skillName = nameArg ?: uriName!!
                val content = SkillCatalog.raw(skillName) ?: return@addTool toolJsonResult(buildJsonObject {
                    put("error", "Unknown skill '$skillName'")
                    put("error_code", "unknown_skill")
                    put("available", buildJsonArray { SkillCatalog.NAMES.forEach { add(it) } })
                })

                val result = buildJsonObject {
                    put("uri", SkillCatalog.uri(skillName))
                    put("name", skillName)
                    put("origin", "burpsuite")
                    put("content", content)
                    put("sha256", SkillCatalog.sha256(skillName) ?: "")
                    put("byte_size", SkillCatalog.byteSize(skillName) ?: 0)
                    put("resource_uris", buildJsonArray { })
                }
                toolJsonResult(result)
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
