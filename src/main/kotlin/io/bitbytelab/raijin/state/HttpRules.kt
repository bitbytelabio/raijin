package io.bitbytelab.raijin.state

import burp.api.montoya.core.ToolType
import kotlinx.serialization.json.JsonObject

/**
 * A global HTTP traffic modification rule. Applied by the HttpBridge's
 * global HTTP handler to all outgoing requests or incoming responses.
 *
 * @property ruleId Unique identifier (e.g. "trule-001").
 * @property direction Whether this rule applies to "request" or "response".
 * @property matchUrl Optional URL regex to match.
 * @property matchHost Optional hostname glob to match.
 * @property matchHeader Optional header pattern to match.
 * @property modifyAddHeader Header line to add ("Name: Value"), written as given: no CR/LF or
 *   syntax check, so a rule can also inject a second line or a line without a colon.
 * @property modifyRemoveHeader Header name to remove.
 * @property modifyReplaceHeader Map of header names to replacement values, written as given.
 * @property enabled Whether this rule is currently active.
 */
data class TrafficRule(
    val ruleId: String,
    val direction: String,
    val matchUrl: String? = null,
    val matchHost: String? = null,
    val matchHeader: String? = null,
    val modifyAddHeader: String? = null,
    val modifyRemoveHeader: String? = null,
    val modifyReplaceHeader: Map<String, String>? = null,
    @Volatile var enabled: Boolean = true,
    /**
     * "modify" (default, header add/remove/replace above), "drop", or "spoof_response".
     * drop/spoof_response only apply to direction="request" — they short-circuit before
     * the request is ever sent, via Montoya's RequestToBeSentAction.drop()/.spoof() (Burp
     * 2026.7+; falls back to sending the real request on an older Burp, see HttpBridge).
     */
    val action: String = "modify",
    /** Raw HTTP response text to spoof when [action] is "spoof_response". */
    val spoofResponse: String? = null,
    /** Optional set of Montoya ToolType names (e.g. "SCANNER") restricting which Burp tools trigger this rule. */
    val toolFilter: Set<String>? = null,
    /**
     * Cookies (name -> value) merged into the request's Cookie header by name: these pairs take
     * these values while every other pair the request sends is kept (direction="request" only).
     * Set by Raijin's own rules (audit authentication), not by a tool parameter.
     */
    val modifySetCookies: Map<String, String>? = null,
)

/**
 * A session handling rule that extracts a value from one response and
 * injects it into subsequent requests. Used for CSRF tokens, session
 * tokens, and other dynamic values.
 *
 * @property ruleName Human-readable name for this rule.
 * @property scope Where to apply: "all", "suite", or "custom".
 * @property scopePattern URL regex when scope is "custom".
 * @property extractFrom Where to extract from: "header" or "body".
 * @property extractHeaderName Header name when extracting from headers; every header line of that
 *   name is read (each `Set-Cookie` separately) and the first one that yields a value wins.
 * @property extractRegex Regex for extraction (first capture group, else the whole match); empty
 *   when [extractJsonPath] or [extractXPath] alone selects the value. With a path, the regex cuts a
 *   part out of what the path selected.
 * @property injectInto Where to inject: "header", "cookie", "body" (form parameter), "query"
 *   (URL parameter) or "json" (a value in a JSON body).
 * @property injectName Name of the header/cookie/parameter to inject into; for "json" a JSONPath
 *   naming exactly one value (`$.auth.token`, or just `token`).
 * @property injectValueTemplate Template string: `{value}` is replaced with the extracted value,
 *   `{value|url}` with the value run through the named encoder(s), chained left to right.
 * @property enabled Whether this rule is currently active.
 * @property lastExtractedValue The most recently extracted value (mutable for runtime updates).
 * @property extractJsonPath JSONPath selecting the value in a JSON body (or header value).
 * @property extractXPath XPath selecting the value in an XML body (or header value).
 * @property injectIfMissing When true (default) the header/cookie/parameter/JSON member is added to
 *   a request that lacks it; when false only one the request already has gets the value.
 */
data class SessionRule(
    val ruleName: String,
    val scope: String,
    val scopePattern: String?,
    val extractFrom: String,
    val extractHeaderName: String?,
    val extractRegex: String,
    val injectInto: String,
    val injectName: String,
    val injectValueTemplate: String,
    @Volatile var enabled: Boolean = true,
    @Volatile var lastExtractedValue: String? = null,
    val extractJsonPath: String? = null,
    val extractXPath: String? = null,
    val injectIfMissing: Boolean = true,
)

/**
 * A login macro: a stored request sequence that re-establishes an expired session. It runs when a
 * response it covers shows that the session expired (its status is in [triggerStatus] or it matches
 * [triggerRegex]); the request that got that response is then sent once more with the refreshed
 * session, and the new response replaces the expired one.
 *
 * @property name Unique name; also the value of the `X-Raijin-Reauthenticated` marker.
 * @property steps The requests to replay, in order: `http_send_request_chain` step objects
 *   (`raw_request` or `url`/`method`/`headers`/`body`, optional `extract`, `{{variable}}` placeholders).
 * @property scope Which responses may trigger it and which requests get its cookies: "all", "suite"
 *   or "custom".
 * @property scopePattern URL regex when scope is "custom".
 * @property triggerStatus Response status codes that mean "session expired".
 * @property triggerRegex Regex over the response's status line, headers and body that means the same.
 * @property toolFilter Montoya ToolType names whose traffic it covers; by default every tool except
 *   PROXY, so the browser's own traffic is left alone (Burp's session handling default).
 * @property requireCredentials Only a request that carried credentials (an Authorization or Cookie
 *   header, or a value a session rule injects) can trigger it, so a deliberately unauthenticated
 *   request stays unauthenticated.
 * @property updateCookies Cookies set by the macro's responses replace the same-named cookies of
 *   requests it covers; they are never added to a request that does not send them.
 * @property minIntervalMs Shortest time between the end of one automatic run and the next.
 * @property maxFailures Runs in a row that did not help before the macro suspends itself; 0 = never.
 * @property stepTimeoutMs Hard timeout of each step and of the retry.
 * @property httpMode HTTP mode of the steps (`HTTP_1`, `HTTP_2`, ...); null for AUTO.
 * @property enabled When false the macro is kept but inactive: no automatic runs, no cookie updates.
 */
data class SessionMacro(
    val name: String,
    val steps: List<JsonObject>,
    val scope: String,
    val scopePattern: String? = null,
    val triggerStatus: Set<Int> = DEFAULT_TRIGGER_STATUS,
    val triggerRegex: String? = null,
    val toolFilter: Set<String> = DEFAULT_TOOL_FILTER,
    val requireCredentials: Boolean = true,
    val updateCookies: Boolean = true,
    val minIntervalMs: Long = DEFAULT_MIN_INTERVAL_MS,
    val maxFailures: Int = DEFAULT_MAX_FAILURES,
    val stepTimeoutMs: Long = DEFAULT_STEP_TIMEOUT_MS,
    val httpMode: String? = null,
    val enabled: Boolean = true,
) {
    companion object {
        val DEFAULT_TRIGGER_STATUS: Set<Int> = setOf(401)

        /** Every Burp tool except PROXY. */
        val DEFAULT_TOOL_FILTER: Set<String> =
            ToolType.entries.filter { it != ToolType.PROXY }.mapTo(LinkedHashSet()) { it.name }

        const val DEFAULT_MIN_INTERVAL_MS = 5_000L
        const val DEFAULT_MAX_FAILURES = 3
        const val DEFAULT_STEP_TIMEOUT_MS = 15_000L
    }
}

