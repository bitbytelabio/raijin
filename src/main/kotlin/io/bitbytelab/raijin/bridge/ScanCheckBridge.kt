package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.*

/**
 * The `scancheck_*` tools: custom scan checks described as JSON (conditions for a passive check,
 * payload steps for an active one) that Burp's scanner then runs.
 *
 * Script mode is the programmatic complement to BCheck (DSL-based): multi-step payload chains,
 * condition lists joined by AND or OR, negation, and comparison with the baseline response.
 * Parsing and evaluation live in [ScanCheckLogic], registration in [CustomScanCheckManager],
 * which `scanner_register_check` shares.
 */
class ScanCheckBridge(
    private val api: MontoyaApi,
    stateManager: StateManager
) {
    private val checks = CustomScanCheckManager(api, stateManager)

    /**
     * Create a PASSIVE scan check (Script mode).
     *
     * Runs on every message Burp audits passively. Conditions can look at the response body,
     * headers, status code and length and at the request, each optionally negated.
     *
     * @param name Name of the check and of the issue it reports. An existing check of that name is replaced.
     * @param description What this check detects.
     * @param conditions Condition objects: {location, pattern, condition_type, negate}.
     * @param severity Issue severity: high, medium, low, information.
     * @param confidence Issue confidence: certain, firm, tentative.
     * @param issueDetail Detailed description included in reported issues.
     * @param issueRemediation Remediation guidance (optional).
     * @param matchMode "all" (default): every condition must hold. "any": one is enough.
     * @return JSON object with deployment status or error.
     */
    fun createPassive(
        name: String,
        description: String,
        conditions: List<JsonObject>,
        severity: String,
        confidence: String,
        issueDetail: String,
        issueRemediation: String?,
        matchMode: String? = null
    ): JsonObject = deploy("passive") {
        passiveDefinition(name, description, conditions, severity, confidence, issueDetail, issueRemediation, matchMode)
    }

    /**
     * Create an ACTIVE scan check (Script mode).
     *
     * Sends each step's payload at the insertion point, in order, and judges the response. The
     * check reports only when a step matches and the response to the unmodified request would not
     * have: see [ScanCheckLogic.runActive].
     *
     * @param name Name of the check and of the issue it reports. An existing check of that name is replaced.
     * @param description What this check detects.
     * @param steps Step objects: {payload, response_conditions[], match_mode, stop_if_no_match}.
     * @param severity Issue severity: high, medium, low, information.
     * @param confidence Issue confidence: certain, firm, tentative.
     * @param issueDetail Detailed description included in reported issues.
     * @param issueRemediation Remediation guidance (optional).
     * @param matchMode How a step's conditions combine unless the step says otherwise: "all" (default) or "any".
     * @return JSON object with deployment status or error.
     */
    fun createActive(
        name: String,
        description: String,
        steps: List<JsonObject>,
        severity: String,
        confidence: String,
        issueDetail: String,
        issueRemediation: String?,
        matchMode: String? = null
    ): JsonObject = deploy("active") {
        activeDefinition(name, description, steps, severity, confidence, issueDetail, issueRemediation, matchMode)
    }

    private fun deploy(kind: String, define: () -> CheckDefinition): JsonObject = try {
        val definition = define()
        val (check, replaced) = checks.register(definition)
        buildJsonObject {
            put("id", check.id)
            put("name", definition.name)
            put("mode", definition.mode)
            put("status", "deployed")
            put("description", definition.description)
            definition.passive?.let {
                put("conditions_count", it.conditions.size)
                put("match_mode", it.mode.name.lowercase())
            }
            definition.active?.let { put("steps_count", it.size) }
            if (replaced != null) put("replaced", replaced.id)
            put(
                "note",
                if (definition.active != null) {
                    "Active scan check deployed. During active audits it sends its payloads at each insertion " +
                        "point and reports only what a payload changes compared with the unmodified response."
                } else {
                    "Passive scan check deployed. It runs on every message Burp audits passively from now on. " +
                        "scancheck_dry_run shows what it matches in the proxy history already recorded."
                }
            )
        }
    } catch (e: InvalidCheckException) {
        errorJson(e.message ?: "Invalid scan check")
    } catch (e: UnsupportedOperationException) {
        errorJson("Scanner API is not available in Burp Suite Community Edition")
    } catch (e: Exception) {
        errorJson("Failed to create $kind scan check: ${e.message}")
    }

    /**
     * Evaluates a check definition against the proxy history Burp has already recorded, without
     * registering it and without sending anything.
     *
     * With [conditions], it reports which recorded messages the passive check would flag. With
     * [steps], it reports how many recorded responses already satisfy each step with no payload
     * sent: there the step cannot count as evidence, and a step that matches much of the baseline
     * is too broad to be useful.
     *
     * @param conditions Passive check conditions; exclusive with [steps].
     * @param steps Active check steps; exclusive with [conditions].
     * @param matchMode "all" (default) or "any".
     * @param urlPattern Regex a history item's URL must match to be read (optional).
     * @param inScopeOnly Read only in-scope items.
     * @param maxItems How many of the newest matching items to read (default 200).
     * @param maxMatches How many matches to list in full (default 20).
     */
    fun dryRun(
        conditions: List<JsonObject>?,
        steps: List<JsonObject>?,
        matchMode: String?,
        urlPattern: String?,
        inScopeOnly: Boolean,
        maxItems: Int?,
        maxMatches: Int?
    ): JsonObject = try {
        if ((conditions == null) == (steps == null)) {
            throw InvalidCheckException("Give either 'conditions' (a passive check) or 'steps' (an active check)")
        }
        val mode = ScanCheckLogic.matchMode(matchMode)
        val filter = HistoryFilter.of(urlPattern, inScopeOnly, maxItems)
        val listed = HistoryFilter.matchLimit(maxMatches)
        val sampler = HistorySampler(api)
        if (conditions != null) {
            requireNonEmpty(conditions, "conditions", "condition")
            val run = PassiveDryRun(ScanCheckLogic.conditions(conditions, "conditions"), mode, listed)
            val historySize = sampler.forEach(filter, run.parts, run::visit)
            dryRunReport(
                "passive", historySize, filter, run.toJson(),
                "would_report counts the recorded messages the check flags; Burp consolidates them to one issue per path."
            )
        } else {
            requireNonEmpty(steps.orEmpty(), "steps", "step")
            val run = BaselineDryRun(ScanCheckLogic.steps(steps.orEmpty(), mode), listed)
            val historySize = sampler.forEach(filter, run.parts, run::visit)
            dryRunReport(
                "active", historySize, filter, run.toJson(),
                "No payload was sent. baseline_matches counts recorded responses that satisfy a step's response " +
                    "conditions as they are: on those requests the step is not evidence, and cannot_report_on counts " +
                    "the requests where no step can be. A high baseline_matches means the conditions are too broad."
            )
        }
    } catch (e: InvalidCheckException) {
        errorJson(e.message ?: "Invalid scan check")
    } catch (e: Exception) {
        errorJson("Dry run failed: ${e.message}")
    }

    /**
     * Lists every custom scan check Burp is running for this extension, including the ones
     * registered with `scanner_register_check`.
     *
     * @return JSON object with count and array of deployed checks.
     */
    fun list(): JsonObject {
        val deployed = checks.list()
        return buildJsonObject {
            put("count", deployed.size)
            put("checks", buildJsonArray {
                deployed.forEach { check ->
                    add(buildJsonObject {
                        put("id", check.id)
                        put("name", check.definition.name)
                        put("mode", check.definition.mode)
                        put("issue_name", check.definition.issueName)
                        put("severity", check.definition.severity)
                        put("confidence", check.definition.confidence)
                        put("deployed_at", check.deployedAt.toString())
                    })
                }
            })
        }
    }

    /**
     * Deregisters a custom scan check from Burp's scanner.
     *
     * @param id The scan check ID (e.g. "scheck-001") or the name it was created under.
     * @return JSON object confirming removal or reporting an error.
     */
    fun remove(id: String): JsonObject {
        val check = checks.find(id) ?: return errorJson("Scan check not found: $id")
        return try {
            checks.remove(check)
            buildJsonObject {
                put("id", check.id)
                put("name", check.definition.name)
                put("mode", check.definition.mode)
                put("removed", true)
            }
        } catch (e: Exception) {
            errorJson("Failed to remove scan check ${check.id}: ${e.message}")
        }
    }

    /** Deregisters all live MCP scan checks on extension unload. */
    fun shutdown() {
        checks.shutdown()
    }

    /**
     * Returns Script-mode templates, examples, and a condition reference.
     *
     * Teaches the AI agent the full capabilities of Script mode: passive
     * and active check patterns, condition types, locations, and multi-step
     * payload chain examples.
     *
     * @return JSON object with templates and reference documentation.
     */
    fun getTemplates(): JsonObject {
        return buildJsonObject {
            put("mode", "script")
            put("description", "Script mode creates scan checks via the Montoya Java API at runtime. " +
                "More powerful than BCheck -- supports multi-step active checks, condition lists joined " +
                "by AND or OR with negation, and comparison with the baseline response.")
            put("when_to_use", "Use Script mode when you need: multi-step verification (inject A, " +
                "check, inject B, confirm), conditions on several parts of a message, or evidence that " +
                "must differ from the unmodified response. Use BCheck mode for simpler pattern matching.")

            put("passive_check_templates", buildJsonArray {
                add(buildJsonObject {
                    put("name", "Sensitive Data Exposure")
                    put("description", "Detect sensitive patterns in responses")
                    put("conditions_example", buildJsonArray {
                        add(buildJsonObject {
                            put("location", "response_body")
                            put("pattern", "(?i)(api[_-]?key|secret[_-]?key|private[_-]?key|access[_-]?token)\\s*[=:]\\s*['\"]?[a-zA-Z0-9]{20,}")
                            put("condition_type", "matches")
                            put("negate", false)
                        })
                    })
                })
                add(buildJsonObject {
                    put("name", "Security Header Missing")
                    put("description", "Check for missing security headers")
                    put("conditions_example", buildJsonArray {
                        add(buildJsonObject {
                            put("location", "response_headers")
                            put("pattern", "(?i)strict-transport-security")
                            put("condition_type", "matches")
                            put("negate", true)
                        })
                        add(buildJsonObject {
                            put("location", "status_code")
                            put("pattern", "200")
                            put("condition_type", "equals")
                            put("negate", false)
                        })
                    })
                })
                add(buildJsonObject {
                    put("name", "Error Message Disclosure")
                    put("description", "Detect stack traces and error details")
                    put("conditions_example", buildJsonArray {
                        add(buildJsonObject {
                            put("location", "response_body")
                            put("pattern", "(?i)(stack.?trace|exception|traceback|error.*line\\s*\\d+|at\\s+[a-z]+\\.[a-z]+\\.[a-z]+)")
                            put("condition_type", "matches")
                            put("negate", false)
                        })
                    })
                })
            })

            put("active_check_templates", buildJsonArray {
                add(buildJsonObject {
                    put("name", "SQL Injection (Error-based)")
                    put("description", "Multi-step: inject quote, check for SQL error, confirm with different payload")
                    put("steps_example", buildJsonArray {
                        add(buildJsonObject {
                            put("payload", "'")
                            put("stop_if_no_match", true)
                            put("response_conditions", buildJsonArray {
                                add(buildJsonObject {
                                    put("location", "response_body")
                                    put("pattern", "(?i)(sql|syntax|mysql|postgresql|oracle|sqlite|database|query)")
                                    put("condition_type", "matches")
                                    put("negate", false)
                                })
                            })
                        })
                        add(buildJsonObject {
                            put("payload", "' OR '1'='1")
                            put("stop_if_no_match", false)
                            put("response_conditions", buildJsonArray {
                                add(buildJsonObject {
                                    put("location", "response_body")
                                    put("pattern", "(?i)(sql|syntax|mysql|postgresql|oracle|sqlite|database|query)")
                                    put("condition_type", "matches")
                                    put("negate", false)
                                })
                            })
                        })
                    })
                })
                add(buildJsonObject {
                    put("name", "SSTI Detection (Multi-step)")
                    put("description", "Inject math expression, verify evaluation, confirm with different expression")
                    put("steps_example", buildJsonArray {
                        add(buildJsonObject {
                            put("payload", "{{7*7}}")
                            put("stop_if_no_match", true)
                            put("response_conditions", buildJsonArray {
                                add(buildJsonObject {
                                    put("location", "response_body")
                                    put("pattern", "49")
                                    put("condition_type", "contains")
                                    put("negate", false)
                                })
                            })
                        })
                        add(buildJsonObject {
                            put("payload", "{{7*6}}")
                            put("stop_if_no_match", true)
                            put("response_conditions", buildJsonArray {
                                add(buildJsonObject {
                                    put("location", "response_body")
                                    put("pattern", "42")
                                    put("condition_type", "contains")
                                    put("negate", false)
                                })
                            })
                        })
                    })
                })
                add(buildJsonObject {
                    put("name", "Reflected XSS (Multi-step)")
                    put("description", "Inject canary, check reflection, inject XSS payload, verify unencoded reflection")
                    put("steps_example", buildJsonArray {
                        add(buildJsonObject {
                            put("payload", "raijin7x7canary")
                            put("stop_if_no_match", true)
                            put("response_conditions", buildJsonArray {
                                add(buildJsonObject {
                                    put("location", "response_body")
                                    put("pattern", "raijin7x7canary")
                                    put("condition_type", "contains")
                                    put("negate", false)
                                })
                            })
                        })
                        add(buildJsonObject {
                            put("payload", "<raijin>xss</raijin>")
                            put("stop_if_no_match", true)
                            put("response_conditions", buildJsonArray {
                                add(buildJsonObject {
                                    put("location", "response_body")
                                    put("pattern", "<raijin>xss</raijin>")
                                    put("condition_type", "contains")
                                    put("negate", false)
                                })
                            })
                        })
                    })
                })
            })

            put("condition_reference", buildJsonObject {
                put("locations", buildJsonArray {
                    add("response_body - HTTP response body text")
                    add("response_headers - All response headers as text")
                    add("status_code - HTTP status code as string")
                    add("response_length - Response body length as string")
                    add("request_body - HTTP request body text")
                    add("request_headers - All request headers as text")
                    add("request_url - Full request URL")
                })
                put("condition_types", buildJsonArray {
                    add("matches - Regex found anywhere in the text (case-insensitive)")
                    add("contains - Substring containment check (case-insensitive)")
                    add("equals - The whole text equals the pattern (case-insensitive)")
                })
                put("negate", "Set to true to invert the condition (NOT matches). A condition on the response " +
                    "never holds for a message without a response, negated or not.")
                put("match_mode", "all (default): every condition in the list must hold. any: one is enough. " +
                    "Given on the tool call, or per step for an active check.")
                put("active_step_fields", buildJsonArray {
                    add("payload - String to inject at the insertion point")
                    add("response_conditions - Array of conditions to check on the response to that payload")
                    add("match_mode - all | any for this step's conditions (default: the tool call's match_mode)")
                    add("stop_if_no_match - true (default): a required step; the check ends without reporting when " +
                        "it does not match or gets no response. false: an optional step; the chain goes on")
                })
                put("baseline_comparison", "An active check reports only when some step matches and the response " +
                    "to the unmodified request would not have matched the same conditions. A pattern the page " +
                    "shows anyway, or a failed request, never raises an issue. At least one step needs a " +
                    "condition on the response.")
                put("consolidation", "One issue per name and URL path for a passive check; for an active check " +
                    "one per name, URL path and insertion point, so two vulnerable parameters stay two issues.")
                put("dry_run", "scancheck_dry_run evaluates conditions or steps against the recorded proxy history " +
                    "before you deploy: what a passive check would flag, how much of the baseline an active step matches.")
            })
        }
    }

    private fun errorJson(message: String): JsonObject = buildJsonObject { put("error", message) }

    internal companion object {
        private const val DEFAULT_REMEDIATION = "Review and address the identified issue."

        /** The `scancheck_create_passive` parameters as a [CheckDefinition]. @throws InvalidCheckException */
        fun passiveDefinition(
            name: String,
            description: String,
            conditions: List<JsonObject>,
            severity: String,
            confidence: String,
            issueDetail: String,
            issueRemediation: String?,
            matchMode: String?,
        ): CheckDefinition {
            if (name.isBlank()) throw InvalidCheckException("name must not be blank")
            val issueSeverity = ScanCheckLogic.severity(severity)
            val issueConfidence = ScanCheckLogic.confidence(confidence)
            requireNonEmpty(conditions, "conditions", "condition")
            return CheckDefinition(
                name = name,
                issueName = name,
                description = description,
                detail = issueDetail,
                remediation = issueRemediation ?: DEFAULT_REMEDIATION,
                severity = issueSeverity,
                confidence = issueConfidence,
                passive = PassiveRule(
                    ScanCheckLogic.conditions(conditions, "conditions"),
                    ScanCheckLogic.matchMode(matchMode),
                ),
            )
        }

        /** The `scancheck_create_active` parameters as a [CheckDefinition]. @throws InvalidCheckException */
        fun activeDefinition(
            name: String,
            description: String,
            steps: List<JsonObject>,
            severity: String,
            confidence: String,
            issueDetail: String,
            issueRemediation: String?,
            matchMode: String?,
        ): CheckDefinition {
            if (name.isBlank()) throw InvalidCheckException("name must not be blank")
            val issueSeverity = ScanCheckLogic.severity(severity)
            val issueConfidence = ScanCheckLogic.confidence(confidence)
            requireNonEmpty(steps, "steps", "step")
            return CheckDefinition(
                name = name,
                issueName = name,
                description = description,
                detail = issueDetail,
                remediation = issueRemediation ?: DEFAULT_REMEDIATION,
                severity = issueSeverity,
                confidence = issueConfidence,
                active = ScanCheckLogic.steps(steps, ScanCheckLogic.matchMode(matchMode)),
            )
        }

        private fun requireNonEmpty(items: List<JsonObject>, paramName: String, elementNoun: String) {
            ScanCheckValidation.nonEmptyError(items, paramName, elementNoun)?.let {
                throw InvalidCheckException(it.getValue("error").jsonPrimitive.content)
            }
        }
    }
}

/**
 * Pure, Burp-free validation helpers for scan-check registration.
 *
 * Extracted so the emptiness guards can be unit-tested without a live
 * [MontoyaApi]/[StateManager]. Rejecting an empty rule set at registration
 * time keeps the failure consistent with the per-condition
 * [ScanCheckBridge]-level enum validation, instead of deploying a check that
 * can never fire (empty AND-chain) or, worse, a negated one that fires on
 * everything.
 */
internal object ScanCheckValidation {
    /**
     * Returns an `{"error": ...}` object when [items] is empty, else null.
     *
     * @param items The parsed rule objects (conditions or steps).
     * @param paramName The parameter name as surfaced to the agent (e.g. "steps").
     * @param elementNoun Singular noun for the element (e.g. "step", "condition").
     */
    fun nonEmptyError(
        items: List<JsonObject>,
        paramName: String,
        elementNoun: String
    ): JsonObject? {
        if (items.isNotEmpty()) return null
        return buildJsonObject {
            put("error", "Parameter '$paramName' must contain at least one $elementNoun object")
        }
    }
}
