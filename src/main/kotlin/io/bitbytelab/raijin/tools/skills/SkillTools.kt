package io.bitbytelab.raijin.tools.skills

import io.bitbytelab.raijin.skills.SkillCatalog
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.*

/**
 * Compatibility layer over [SkillCatalog] for MCP clients that discover capabilities through
 * ordinary `tools/call` rather than the experimental native Skills Extension (`skills/list`,
 * `skills/get` — not implementable against the pinned Kotlin MCP SDK 0.16 without forking it;
 * see `burp://skills/manifest` and [io.bitbytelab.raijin.transport.ResourceRegistry] for the
 * resource-based route a client CAN use today).
 *
 * All three tools read the exact same [SkillCatalog] the resources/prompts use — there is no
 * separate catalog to drift out of sync.
 *
 * **Loading a skill's markdown through one of these tools is a compatibility mechanism.** It
 * does not activate a native Agent Skill inside a host the way a real Skills Extension
 * `skills/get` (or this project's own `*_skill` MCP prompts, see `PromptRegistry`) would — the
 * content just becomes ordinary tool-result text the model may or may not act on.
 */
object SkillTools {

    fun register(server: Server) {

        server.addTool(
            name = "search_skills",
            description = "Search the skill catalog by name/description. Returns URI, name, description per match — " +
                "never full skill content (use load_skill for that). This is a tools/call compatibility route; see " +
                "the object's kdoc for how it relates to the native Skills Extension and to the *_skill MCP prompts.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("query") { put("type", "string"); put("description", "Case-insensitive substring match against name/description; omit to list every skill") }
                    putJsonObject("limit") { put("type", "integer"); put("description", "Maximum results, default 20") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val query = args["query"]?.jsonPrimitive?.contentOrNull?.trim()?.lowercase()
                val limit = (args["limit"]?.jsonPrimitive?.intOrNull ?: 20).coerceAtLeast(0)

                val matches = SkillCatalog.list().filter { skill ->
                    query.isNullOrEmpty() || skill.name.lowercase().contains(query) || skill.description.lowercase().contains(query)
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
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(content = listOf(TextContent(buildJsonObject { put("error", e.message ?: "Unknown error") }.toString())), isError = true)
            }
        }

        server.addTool(
            name = "load_skill",
            description = "Load a skill's full SKILL.md content by its skill:// URI (from search_skills or burp://skills/manifest), " +
                "with integrity metadata. This is a tools/call compatibility route — loading the markdown this way does NOT by " +
                "itself activate a native Agent Skill in a host; the content becomes ordinary tool-result text.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("uri") { put("type", "string"); put("description", "skill://<name>/SKILL.md, e.g. from search_skills") }
                },
                required = listOf("uri")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val uri = args["uri"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(content = listOf(TextContent("""{"error":"Parameter 'uri' is required"}""")), isError = true)

                val name = SkillCatalog.nameFromUri(uri)
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject { put("error", "Malformed skill URI '$uri'; expected skill://<name>/SKILL.md") }.toString())),
                        isError = true
                    )
                val content = SkillCatalog.raw(name)
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject { put("error", "Unknown skill '$name'"); put("error_code", "unknown_skill") }.toString())),
                        isError = true
                    )

                val result = buildJsonObject {
                    put("uri", uri)
                    put("name", name)
                    put("origin", "burpsuite")
                    put("content", content)
                    put("sha256", SkillCatalog.sha256(name) ?: "")
                    put("byte_size", SkillCatalog.byteSize(name) ?: 0)
                    // No skill ships supporting files today (each is one markdown file); this
                    // stays an empty array, not omitted, so a client's shape expectations hold.
                    put("resource_uris", buildJsonArray { })
                }
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(content = listOf(TextContent(buildJsonObject { put("error", e.message ?: "Unknown error") }.toString())), isError = true)
            }
        }

        server.addTool(
            name = "read_skill_file",
            description = "Read one authorized skill resource by URI. Today every skill is a single SKILL.md with no " +
                "supporting files, so this only resolves a skill's own skill://<name>/SKILL.md URI (same content as " +
                "load_skill) — kept as a separate tool so a client written against the general form keeps working once " +
                "supporting resource files are added.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("uri") { put("type", "string"); put("description", "skill://<name>/SKILL.md") }
                },
                required = listOf("uri")
            )
        ) { request ->
            try {
                val args = request.params.arguments ?: emptyMap()
                val uri = args["uri"]?.jsonPrimitive?.contentOrNull
                    ?: return@addTool CallToolResult(content = listOf(TextContent("""{"error":"Parameter 'uri' is required"}""")), isError = true)

                val name = SkillCatalog.nameFromUri(uri)
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject {
                            put("error", "No such resource '$uri'. Only a skill's own skill://<name>/SKILL.md is readable today — no supporting files exist yet.")
                            put("error_code", "unknown_resource")
                        }.toString())),
                        isError = true
                    )
                val content = SkillCatalog.raw(name)
                    ?: return@addTool CallToolResult(
                        content = listOf(TextContent(buildJsonObject { put("error", "Unknown skill '$name'"); put("error_code", "unknown_skill") }.toString())),
                        isError = true
                    )

                val result = buildJsonObject {
                    put("uri", uri)
                    put("content", content)
                    put("sha256", SkillCatalog.sha256(name) ?: "")
                    put("byte_size", SkillCatalog.byteSize(name) ?: 0)
                }
                CallToolResult(content = listOf(TextContent(result.toString())))
            } catch (e: Exception) {
                CallToolResult(content = listOf(TextContent(buildJsonObject { put("error", e.message ?: "Unknown error") }.toString())), isError = true)
            }
        }
    }
}
