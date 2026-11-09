package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scope.ScopeChangeHandler
import io.bitbytelab.raijin.events.EventBus
import kotlinx.serialization.json.*
import java.time.Instant

class ScopeBridge(private val api: MontoyaApi, private val eventBus: EventBus) {

    fun check(url: String): JsonObject {
        val inScope = api.scope().isInScope(url)

        return buildJsonObject {
            put("url", url)
            put("in_scope", inScope)
        }
    }

    fun include(url: String): JsonObject {
        api.scope().includeInScope(url)

        return buildJsonObject {
            put("status", "included")
            put("url", url)
            put("in_scope", true)
        }
    }

    fun exclude(url: String): JsonObject {
        api.scope().excludeFromScope(url)

        return buildJsonObject {
            put("status", "excluded")
            put("url", url)
            put("in_scope", false)
        }
    }

    fun getConfig(): JsonObject {
        return try {
            val scopeJson = api.burpSuite().exportProjectOptionsAsJson("target.scope")

            return buildJsonObject {
                put("status", "success")
                put("scope_config", scopeJson)
            }
        } catch (e: Exception) {
            buildJsonObject {
                put("status", "error")
                put("message", e.message ?: "Failed to export scope configuration")
            }
        }
    }

    /** Lists the include/exclude rules in Burp's target scope, with their index for [remove]. */
    fun list(): JsonObject {
        return try {
            buildJsonObject {
                put("include", buildJsonArray {
                    currentScopeList("include").forEachIndexed { idx, rule ->
                        addJsonObject { put("index", idx); rule.jsonObject.forEach { (k, v) -> put(k, v) } }
                    }
                })
                put("exclude", buildJsonArray {
                    currentScopeList("exclude").forEachIndexed { idx, rule ->
                        addJsonObject { put("index", idx); rule.jsonObject.forEach { (k, v) -> put(k, v) } }
                    }
                })
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Failed to list scope rules: ${e.message}") }
        }
    }

    /**
     * Removes a single scope rule by its index in the include or exclude list (see [list]).
     * [include]/[exclude] in Montoya's [burp.api.montoya.scope.Scope] can only ever ADD rules
     * (`includeInScope`/`excludeFromScope`); there is no per-rule removal API, so this follows
     * the same export -> mutate JSON -> import -> read-back-confirm pattern
     * [ConfigBridge.removeMatchReplaceRule] already uses for `proxy.match_replace_rules`,
     * targeting `target.scope` instead.
     *
     * The exact `target.scope` JSON field names used here (`include`/`exclude` arrays of
     * objects with `enabled`/`host`/`port`/`protocol`/`file`) are Raijin's best-documented
     * understanding of Burp's project-options export, not runtime-verified against a live
     * Burp in this change. The read-back-confirm step is the safety net for that: if the
     * shape is wrong, Burp silently ignores the unrecognized keys, the rule count does not
     * drop, and this returns a clean `status: failed` instead of a false success.
     */
    fun remove(list: String, index: Int): JsonObject {
        val key = list.trim().lowercase()
        if (key != "include" && key != "exclude") {
            return buildJsonObject { put("error", "Parameter 'list' must be 'include' or 'exclude'") }
        }
        return try {
            val configJson = api.burpSuite().exportProjectOptionsAsJson("target.scope")
            val config = Json.parseToJsonElement(configJson).jsonObject.toMutableMap()
            val targetObj = config["target"]?.jsonObject?.toMutableMap()
                ?: return buildJsonObject { put("error", "No target.scope configuration found (unexpected export shape)") }
            val scopeObj = targetObj["scope"]?.jsonObject?.toMutableMap()
                ?: return buildJsonObject { put("error", "No target.scope configuration found (unexpected export shape)") }
            val rules = scopeObj[key]?.jsonArray?.toMutableList() ?: mutableListOf()

            if (index < 0 || index >= rules.size) {
                return buildJsonObject {
                    put("error", "Invalid $key index: $index. Valid range: 0..${rules.size - 1}. Use scope(action=list) first.")
                }
            }

            val expectedCount = rules.size - 1
            val removed = rules.removeAt(index)
            scopeObj[key] = JsonArray(rules)
            targetObj["scope"] = JsonObject(scopeObj)
            config["target"] = JsonObject(targetObj)

            api.burpSuite().importProjectOptionsFromJson(JsonObject(config).toString())

            val after = currentScopeList(key)
            if (after.size > expectedCount) {
                return buildJsonObject {
                    put("status", "failed")
                    put("error", "Burp did not accept the config change (unrecognized schema?) — the rule was not removed.")
                }
            }

            buildJsonObject {
                put("status", "removed")
                put("list", key)
                put("index", index)
                put("removed", removed)
                put("total_rules", after.size)
            }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Failed to remove scope rule: ${e.message}") }
        }
    }

    private fun currentScopeList(key: String): List<JsonElement> {
        val configJson = api.burpSuite().exportProjectOptionsAsJson("target.scope")
        val config = Json.parseToJsonElement(configJson)
        return config.jsonObject["target"]?.jsonObject?.get("scope")?.jsonObject?.get(key)?.jsonArray ?: JsonArray(emptyList())
    }

    fun createScopeChangeHandler(): ScopeChangeHandler {
        return ScopeChangeHandler { _ ->
            val eventData = buildJsonObject {
                put("event", "scope_changed")
                put("timestamp", Instant.now().toString())
            }
            eventBus.emit("scope.changed", eventData)
        }
    }
}
