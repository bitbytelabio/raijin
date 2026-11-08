package io.bitbytelab.raijin.turbo.mcp

import io.bitbytelab.raijin.turbo.ResultStore
import io.bitbytelab.raijin.turbo.RunHandler
import java.util.UUID

class ActiveRun(
    val sequenceNumber: Long = 0,
    val handler: RunHandler = RunHandler(),
    val store: ResultStore = ResultStore(),
    /** Where the run came from: "MCP" (agent) or "GUI" (script dialog). */
    val source: String = "MCP",
) {
    val id: String = UUID.randomUUID().toString()
    val createdAt: Long = System.currentTimeMillis()
    @Volatile
    var responsesStripped: Boolean = false
}
