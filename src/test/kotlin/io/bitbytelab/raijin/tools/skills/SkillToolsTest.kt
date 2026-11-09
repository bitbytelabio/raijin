package io.bitbytelab.raijin.tools.skills

import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import kotlin.test.Test
import kotlin.test.assertTrue

class SkillToolsTest {

    @Test
    fun `register adds skill_list and skill_get`() {
        val server = Server(
            Implementation("test", "0"),
            ServerOptions(ServerCapabilities(tools = ServerCapabilities.Tools(listChanged = true)))
        )
        SkillTools.register(server)
        assertTrue(server.tools.containsKey("skill_list"))
        assertTrue(server.tools.containsKey("skill_get"))
    }
}
