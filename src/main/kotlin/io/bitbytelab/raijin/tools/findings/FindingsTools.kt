package io.bitbytelab.raijin.tools.findings

import io.bitbytelab.raijin.bridge.FindingsBridge
import io.bitbytelab.raijin.bridge.Owasp2021
import io.bitbytelab.raijin.core.EnumValidation
import io.bitbytelab.raijin.tools.toolError
import io.bitbytelab.raijin.tools.toolJsonResult
import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.*

/**
 * Registers the findings-memory tools: `findings_add` (deduplicated) and
 * `findings_list`. Gives the agent persistent recall of confirmed/suspected
 * issues across a session for triage and reporting.
 */
object FindingsTools {

    private val SEVERITIES = listOf("critical", "high", "medium", "low", "info")

    fun register(server: Server, bridge: FindingsBridge) {
        server.addTool(
            name = "findings_add",
            description = "Record a confirmed or suspected finding in the agent's deduplicated findings store " +
                "(working memory, separate from Burp's scanner). Re-adding the same type+url+location is deduped. " +
                "Use to remember bugs you've confirmed so you can triage/report them later. " +
                "Fills the Findings tab in Burp (survives reloads).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("type") { put("type", "string"); put("description", "Vulnerability type, e.g. xss, sqli, idor, ssrf, info_leak") }
                    putJsonObject("severity") {
                        put("type", "string")
                        putJsonArray("enum") { SEVERITIES.forEach { add(it) } }
                        put("description", "Severity (default info)")
                    }
                    putJsonObject("url") { put("type", "string"); put("description", "Affected URL") }
                    putJsonObject("location") { put("type", "string"); put("description", "Where it lives: param:name, header:name, body, path") }
                    putJsonObject("detail") { put("type", "string"); put("description", "Description of the issue") }
                    putJsonObject("evidence") { put("type", "string"); put("description", "Evidence (payload, response excerpt)") }
                    putJsonObject("cvss_score") { put("type", "string"); put("description", "CVSS base score, 0.0-10.0 (e.g. 8.1). Optional.") }
                    putJsonObject("cvss_vector") { put("type", "string"); put("description", "CVSS vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H). Optional.") }
                    putJsonObject("owasp_category") {
                        put("type", "string")
                        put("description", "OWASP Top 10 2021 category. Accepts the code (A03), code+year (A03:2021), or the name (Injection, SSRF, broken access control) - normalized to canonical form. Optional. Valid: ${Owasp2021.validValues()}")
                    }
                    putJsonObject("steps_to_reproduce") { put("type", "string"); put("description", "Numbered steps to reproduce the issue. Optional.") }
                    putJsonObject("request") { put("type", "string"); put("description", "Raw HTTP request evidence (the triggering request). Optional.") }
                    putJsonObject("response") { put("type", "string"); put("description", "Raw HTTP response evidence (the proof response). Optional.") }
                },
                required = listOf("type", "url")
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val type = a["type"]?.jsonPrimitive?.contentOrNull ?: return@addTool toolError("Parameter 'type' is required")
                val url = a["url"]?.jsonPrimitive?.contentOrNull ?: return@addTool toolError("Parameter 'url' is required")
                val severity = a["severity"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() } ?: "info"
                EnumValidation.error(severity, SEVERITIES.toSet(), "severity")?.let { return@addTool toolJsonResult(it) }
                val result = bridge.add(
                    type,
                    severity.trim().lowercase(),
                    url,
                    a["location"]?.jsonPrimitive?.contentOrNull ?: "",
                    a["detail"]?.jsonPrimitive?.contentOrNull ?: "",
                    a["evidence"]?.jsonPrimitive?.contentOrNull ?: "",
                    a["cvss_score"]?.jsonPrimitive?.contentOrNull ?: "",
                    a["cvss_vector"]?.jsonPrimitive?.contentOrNull ?: "",
                    a["owasp_category"]?.jsonPrimitive?.contentOrNull ?: "",
                    a["steps_to_reproduce"]?.jsonPrimitive?.contentOrNull ?: "",
                    a["request"]?.jsonPrimitive?.contentOrNull ?: "",
                    a["response"]?.jsonPrimitive?.contentOrNull ?: ""
                )
                toolJsonResult(result)
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "findings_list",
            description = "List the recorded findings, optionally filtered by severity and/or type.",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("severity") {
                        put("type", "string")
                        putJsonArray("enum") { SEVERITIES.forEach { add(it) } }
                        put("description", "Filter by severity")
                    }
                    putJsonObject("type") { put("type", "string"); put("description", "Filter by type") }
                },
                required = emptyList()
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val severity = a["severity"]?.jsonPrimitive?.contentOrNull?.trim()?.takeIf { it.isNotEmpty() }
                EnumValidation.error(severity, SEVERITIES.toSet(), "severity")?.let { return@addTool toolJsonResult(it) }
                toolJsonResult(bridge.list(severity, a["type"]?.jsonPrimitive?.contentOrNull))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }

        server.addTool(
            name = "findings_remove",
            description = "Remove a recorded finding by id (from findings_add's response or findings_list).",
            inputSchema = ToolSchema(
                properties = buildJsonObject {
                    putJsonObject("id") { put("type", "string"); put("description", "Finding id to remove") }
                },
                required = listOf("id")
            )
        ) { request ->
            try {
                val a = request.params.arguments ?: emptyMap()
                val id = a["id"]?.jsonPrimitive?.contentOrNull ?: return@addTool toolError("Parameter 'id' is required")
                toolJsonResult(bridge.remove(id))
            } catch (e: Exception) {
                toolError(e.message ?: "Unknown error")
            }
        }
    }
}
