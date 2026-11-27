package io.bitbytelab.raijin.tools

import io.modelcontextprotocol.kotlin.sdk.types.Tool
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * Resolves the tool names agents send to a published call: exact names, legacy member names
 * (`scope_list`), dotted `group.action` names, names differing only in case or separators
 * (`Burp.Version`), and a few names that mean an action with fixed arguments (`sha256`). A
 * destructive call is never run from an inexact name; it comes back as a suggestion.
 */
internal object ToolNames {

    sealed interface Resolution

    /**
     * Call [tool] with [action] (null: as given) and [extra] arguments under the caller's; [note]
     * says what was changed.
     */
    data class Found(
        val tool: String,
        val action: String?,
        val extra: JsonObject,
        val note: String?,
    ) : Resolution

    /**
     * No single safe match: up to three [didYouMean] call names, and [retry] when one is certain.
     */
    data class NotFound(val didYouMean: List<String>, val retry: String?) : Resolution

    private val EMPTY = JsonObject(emptyMap())

    /** Name normal form: trimmed, lowercase, `-`, `.`, `/` and spaces as `_`. */
    fun norm(s: String): String =
        s.trim()
            .lowercase()
            .map { if (it == '-' || it == '.' || it == '/' || it == ' ') '_' else it }
            .joinToString("")

    /**
     * Prefixes clients put before a tool name (`mcp__raijin__proxy_history`,
     * `raijin.proxy_history`).
     */
    private val SERVER_PREFIXES =
        listOf("mcp__raijin__", "raijin.", "raijin:", "raijin/", "functions.")

    /**
     * [raw] without a server prefix ([SERVER_PREFIXES], any case) when it has one and something
     * follows it, else null. Same list as the CLI's `strip_server_prefix`.
     */
    fun stripServerPrefix(raw: String): String? = SERVER_PREFIXES.firstNotNullOfOrNull { prefix ->
        raw.takeIf { it.startsWith(prefix, ignoreCase = true) }
            ?.substring(prefix.length)
            ?.takeIf { it.isNotBlank() }
    }

    private val DESTRUCTIVE_ACTION =
        Regex(
            "(^|_)(delete|remove|clear|shutdown|stop|kill|reset|drop|purge|import|unregister)(_|$)",
        )

    private val groups = ToolConsolidation.GROUPS.associateBy { it.tool }

    /**
     * Whether calling [tool] with [action] may remove or stop something; [published] is the tool as
     * published.
     */
    fun destructive(tool: String, action: String?, published: Tool?): Boolean =
        if (action != null && tool in groups) DESTRUCTIVE_ACTION.containsMatchIn(action)
        else published?.annotations?.destructiveHint == true

    private val HASHES =
        mapOf(
            "md5" to "MD5",
            "sha1" to "SHA_1",
            "sha256" to "SHA_256",
            "sha384" to "SHA_384",
            "sha512" to "SHA_512",
        )

    /**
     * The action and fixed arguments a name that is not an action of [tool] stands for (`sha256` ->
     * hash).
     */
    fun semanticAction(tool: String, raw: String): Pair<String, JsonObject>? {
        if (tool != "util") return null
        val key =
            raw.lowercase()
                .filter { it != '-' && it != '_' && it != '.' && it != ' ' }
                .removePrefix("util")
        val algorithm = HASHES[key] ?: return null
        return "hash" to buildJsonObject { put("algorithm", algorithm) }
    }

    /**
     * What [raw] names among the published [tools], read without a server prefix
     * ([stripServerPrefix], noted); first rule that matches wins.
     */
    fun resolve(raw: String, tools: Map<String, Tool>): Resolution {
        val stripped = stripServerPrefix(raw.trim()) ?: return resolveName(raw, tools)
        return when (val r = resolveName(stripped, tools)) {
            is Found -> {
                val call = ToolArgs.callName(r.tool, r.action)
                r.copy(
                    note =
                        listOfNotNull("read '${raw.trim()}' as $call", r.note).joinToString("; "),
                )
            }
            is NotFound -> r
        }
    }

    private fun resolveName(raw: String, tools: Map<String, Tool>): Resolution {
        val n = raw.trim()
        if (n in tools) return Found(n, null, EMPTY, null)

        for (g in ToolConsolidation.GROUPS) {
            if (g.tool !in tools) continue
            val action = g.actions.entries.firstOrNull { it.value == n }?.key ?: continue
            return Found(g.tool, action, EMPTY, "'$n' is now ${g.tool}.$action")
        }

        if ('.' in n) {
            val group = n.substringBefore('.')
            val rest = n.substringAfter('.')
            if (group in tools && group in groups) {
                // `burp.Shutdown` would run burp.shutdown: an inexact spelling of a destructive
                // action only suggests it.
                val action = ToolConsolidation.resolveAction(group, rest)
                if (action != null && action != rest && destructive(group, action, tools[group])) {
                    return NotFound(listOf("$group.$action"), "$group.$action")
                }
                return Found(group, rest, EMPTY, null)
            }
        }

        val calls = LinkedHashMap<String, Pair<String, String?>>()
        tools.keys.forEach { calls[it] = it to null }
        val published = ToolConsolidation.GROUPS.filter { it.tool in tools }
        for (g in published) {
            for ((action, member) in g.actions) {
                calls["${g.tool}.$action"] = g.tool to action
                calls.putIfAbsent(member, g.tool to action)
            }
        }
        val wanted = norm(n)
        val hits = calls.filterKeys { norm(it) == wanted }.values.distinct()
        if (hits.size == 1) {
            val (tool, action) = hits.single()
            val callName = if (action == null) tool else "$tool.$action"
            return if (destructive(tool, action, tools[tool])) NotFound(listOf(callName), callName)
            else Found(tool, action, EMPTY, "ran '$n' as $callName")
        }

        if ("util" in tools) {
            semanticAction("util", n)?.let { (action, extra) ->
                val algorithm = extra.getValue("algorithm").jsonPrimitive.content
                return Found(
                    "util",
                    action,
                    extra,
                    "ran '$n' as util.$action with algorithm $algorithm",
                )
            }
        }

        // A grouped tool is never suggested without its action.
        val callNames =
            tools.keys.filter { it !in groups } +
                published.flatMap { g -> g.actions.keys.map { "${g.tool}.$it" } }
        val found = ToolArgs.closestCalls(n, callNames, 3)
        val hints = found.map { it.name }
        // Only a sure call: a single hint within 2 edits, or the one hint with the same words;
        // an action named for a grouped tool, nothing removed.
        val sure =
            found.singleOrNull()?.name?.takeIf { ToolArgs.levenshtein(wanted, norm(it)) <= 2 }
                ?: found
                    .firstOrNull()
                    ?.takeIf { first ->
                        first.sameWords && found.count { it.sameWords } == 1
                    }
                    ?.name
        val retry = sure?.takeIf { name ->
            val tool = name.substringBefore('.')
            (tool !in groups || '.' in name) &&
                !destructive(tool, name.substringAfter('.', "").ifEmpty { null }, tools[tool])
        }
        return NotFound(hints, retry)
    }
}
