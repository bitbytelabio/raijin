package io.bitbytelab.raijin.state

/**
 * A global HTTP traffic modification rule. Applied by the HttpBridge's
 * global HTTP handler to all outgoing requests or incoming responses.
 *
 * @property ruleId Unique identifier (e.g. "trule-001").
 * @property direction Whether this rule applies to "request" or "response".
 * @property matchUrl Optional URL regex to match.
 * @property matchHost Optional hostname glob to match.
 * @property matchHeader Optional header pattern to match.
 * @property modifyAddHeader Header to add (format "Name: Value").
 * @property modifyRemoveHeader Header name to remove.
 * @property modifyReplaceHeader Map of header names to replacement values.
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
    val toolFilter: Set<String>? = null
)

/**
 * A session handling rule that extracts a value from one response and
 * injects it into subsequent requests. Used for CSRF tokens, session
 * tokens, and other dynamic values.
 *
 * @property ruleName Human-readable name for this rule.
 * @property scope Where to apply: "all", "suite", or "custom".
 * @property scopePattern URL pattern when scope is "custom".
 * @property extractFrom Where to extract from: "header" or "body".
 * @property extractHeaderName Header name when extracting from headers.
 * @property extractRegex Regex with a capture group for extraction.
 * @property injectInto Where to inject: "header", "body", or "cookie".
 * @property injectName Name of the header/cookie/parameter to inject into.
 * @property injectValueTemplate Template string; "{value}" is replaced with the extracted value.
 * @property enabled Whether this rule is currently active.
 * @property lastExtractedValue The most recently extracted value (mutable for runtime updates).
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
    @Volatile var lastExtractedValue: String? = null
)

