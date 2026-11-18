package io.bitbytelab.raijin.tools.skills

import io.bitbytelab.raijin.skills.SkillCatalog
import io.bitbytelab.raijin.testClientConnection
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequest
import io.modelcontextprotocol.kotlin.sdk.types.CallToolRequestParams
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SkillToolsTest {

    private fun server(): Server {
        val server = Server(
            Implementation("burpsuite", "test"),
            ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = false)))
        )
        SkillTools.register(server)
        return server
    }

    private fun call(server: Server, tool: String, args: JsonObject): Pair<Boolean, JsonObject> {
        val res = runBlocking {
            server.tools.getValue(tool).handler(testClientConnection, CallToolRequest(CallToolRequestParams(tool, args)))
        }
        val text = (res.content.single() as TextContent).text
        return (res.isError == true) to Json.parseToJsonElement(text).jsonObject
    }

    @Test
    fun `registers only search_skills and load_skill`() {
        val server = server()
        assertEquals(setOf("search_skills", "load_skill"), server.tools.keys)
    }

    @Test
    fun `search_skills lists all skills and filters by query and limit`() {
        val server = server()

        val (errAll, all) = call(server, "search_skills", buildJsonObject { })
        assertFalse(errAll)
        assertEquals(SkillCatalog.NAMES.size, all.getValue("total_matched").jsonPrimitive.int)
        assertEquals(
            SkillCatalog.NAMES,
            all.getValue("skills").jsonArray.map { it.jsonObject.getValue("name").jsonPrimitive.content }
        )

        val (errMatch, match) = call(server, "search_skills", buildJsonObject { put("query", "graphql") })
        assertFalse(errMatch)
        assertEquals(listOf("recon-probes"), match.getValue("skills").jsonArray.map { it.jsonObject.getValue("name").jsonPrimitive.content })

        val (errLim, lim) = call(server, "search_skills", buildJsonObject { put("limit", 2) })
        assertFalse(errLim)
        assertEquals(SkillCatalog.NAMES.size, lim.getValue("total_matched").jsonPrimitive.int)
        assertEquals(2, lim.getValue("skills").jsonArray.size)
    }

    @Test
    fun `load_skill accepts name, uri, or bare name in uri`() {
        val server = server()
        val expected = SkillCatalog.raw("overview")!!

        for (args in listOf(
            buildJsonObject { put("name", "overview") },
            buildJsonObject { put("uri", "skill://overview/SKILL.md") },
            buildJsonObject { put("uri", "overview") },
            buildJsonObject { put("name", "overview"); put("uri", "skill://overview/SKILL.md") },
        )) {
            val (isErr, json) = call(server, "load_skill", args)
            assertFalse(isErr, "$args failed: $json")
            assertEquals("overview", json.getValue("name").jsonPrimitive.content)
            assertEquals("skill://overview/SKILL.md", json.getValue("uri").jsonPrimitive.content)
            assertEquals(expected, json.getValue("content").jsonPrimitive.content)
        }
    }

    @Test
    fun `load_skill rejects missing, conflicting, malformed, and unknown inputs`() {
        val server = server()

        assertTrue(call(server, "load_skill", buildJsonObject { }).first)
        assertTrue(call(server, "load_skill", buildJsonObject { put("name", "overview"); put("uri", "skill://http-testing/SKILL.md") }).first)

        val (badUriErr, badUri) = call(server, "load_skill", buildJsonObject { put("uri", "skill://overview") })
        assertTrue(badUriErr)
        assertEquals("malformed_uri", badUri.getValue("error_code").jsonPrimitive.content)

        val (unknownErr, unknown) = call(server, "load_skill", buildJsonObject { put("name", "nope") })
        assertTrue(unknownErr)
        assertEquals("unknown_skill", unknown.getValue("error_code").jsonPrimitive.content)
        assertEquals(SkillCatalog.NAMES, unknown.getValue("available").jsonArray.map { it.jsonPrimitive.content })
    }
}
