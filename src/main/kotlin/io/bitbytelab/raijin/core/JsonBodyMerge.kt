package io.bitbytelab.raijin.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Merges one key into a JSON object body — pulled out of [io.bitbytelab.raijin.bridge.ReconBridge]'s
 * `injectJsonBody` so the actual merge logic is unit-testable without a Montoya `HttpRequest`.
 *
 * A missing, empty, or non-JSON-object body is treated as `{}` rather than left untouched: the
 * base request `recon(action=param_mine)` builds for `inject_in=json_body` has no body at all
 * (it's constructed from a bare URL), so "starts as `{}`" is the common case, not an edge case —
 * leaving an empty body untouched would mean every candidate silently sends the same unmodified,
 * bodyless request and never actually tests anything.
 */
object JsonBodyMerge {
    fun mergeKey(bodyText: String, name: String, value: String): String {
        val trimmed = bodyText.trim()
        val base: JsonObject = if (trimmed.startsWith("{")) {
            try {
                (Json.parseToJsonElement(trimmed) as? JsonObject) ?: buildJsonObject {}
            } catch (_: Exception) {
                buildJsonObject {}
            }
        } else {
            buildJsonObject {}
        }
        return buildJsonObject {
            base.forEach { (k, v) -> put(k, v) }
            put(name, value)
        }.toString()
    }
}
