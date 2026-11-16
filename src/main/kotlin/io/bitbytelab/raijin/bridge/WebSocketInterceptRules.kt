package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.safety.SafeRegex
import io.bitbytelab.raijin.state.WebSocketInterceptRule
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Evaluation of WebSocket intercept rules against one frame, free of Burp types.
 *
 * A text frame is evaluated on its payload and a binary frame on its bytes read as ISO-8859-1
 * ([WebSocketFrames.latin1]), so the same rules match, drop and rewrite both kinds, and a rewritten
 * binary frame maps back to bytes exactly.
 */
internal object WebSocketInterceptRules {

    /** What to do with the frame. */
    sealed class Outcome {
        /** Forward it unchanged. */
        object Continue : Outcome()

        /** Discard it. */
        object Drop : Outcome()

        /** Forward [content] instead; for a binary frame it is the ISO-8859-1 text of the new bytes. */
        data class Modify(val content: String) : Outcome()
    }

    /**
     * Applies the enabled [rules] in order. The first matching "drop" wins; "modify" rules rewrite
     * the content one after the other, each seeing the result of the previous one; "tag" rules call
     * [onTag]. An invalid or slow regex counts as no match, so a bad rule never breaks a socket.
     *
     * @param url the connection URL, or null if unknown (a rule with a URL pattern then never matches).
     * @param direction "client_to_server" or "server_to_client".
     * @param binary whether the frame is binary.
     * @param content the frame as text; read at most once, and only when a rule looks at the content.
     */
    fun evaluate(
        rules: Iterable<WebSocketInterceptRule>,
        url: String?,
        direction: String,
        binary: Boolean,
        content: () -> String,
        onTag: (WebSocketInterceptRule) -> Unit,
    ): Outcome {
        var current: String? = null
        var modified = false
        val text = { current ?: content().also { current = it } }

        for (rule in rules) {
            if (!rule.enabled) continue
            if (!matches(rule, url, direction, binary, text)) continue
            when (rule.action) {
                "drop" -> return Outcome.Drop
                "modify" -> {
                    val regex = rule.modifyRegex
                    if (regex != null) {
                        val before = text()
                        val updated = SafeRegex.replace(regex, before, rule.modifyReplacement ?: "")
                        if (updated != before) {
                            current = updated
                            modified = true
                        }
                    }
                }
                "tag" -> onTag(rule)
            }
        }
        return if (modified) Outcome.Modify(text()) else Outcome.Continue
    }

    /**
     * True when [rule] applies to a frame: its direction ("both" matches either), its frame kind, its
     * URL pattern and its content pattern all agree. A null pattern matches anything.
     */
    private fun matches(
        rule: WebSocketInterceptRule,
        url: String?,
        direction: String,
        binary: Boolean,
        text: () -> String,
    ): Boolean {
        if (rule.direction != "both" && rule.direction != direction) return false
        val kind = rule.messageType
        if (kind != null && (kind == "BINARY") != binary) return false
        val urlPattern = rule.matchUrl
        if (urlPattern != null && (url == null || !SafeRegex.containsMatchIn(urlPattern, url))) return false
        val contentPattern = rule.matchMessage
        if (contentPattern != null && !SafeRegex.containsMatchIn(contentPattern, text())) return false
        return true
    }

    /** [rule] as an entry of the rule list. */
    fun toJson(rule: WebSocketInterceptRule): JsonObject = buildJsonObject {
        put("rule_id", rule.ruleId)
        put("action", rule.action)
        put("direction", rule.direction)
        put("enabled", rule.enabled)
        rule.messageType?.let { put("message_type", it) }
        rule.matchUrl?.let { put("match_url", it) }
        rule.matchMessage?.let { put("match_message", it) }
        rule.modifyRegex?.let { put("modify_regex", it) }
        rule.modifyReplacement?.let { put("modify_replacement", it) }
        rule.tagComment?.let { put("tag_comment", it) }
    }
}
