package io.bitbytelab.raijin.graphql.bruteforcer

import io.bitbytelab.raijin.graphql.TargetUnreachableException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put

/**
 * Reconstructs a GraphQL schema's shape — without introspection — by sending field/argument-name
 * guesses from a wordlist and parsing "did you mean"/type-mismatch error messages, the Clairvoyance
 * technique InQL's `Bruteforcer` implements. Ported as a simplified, self-contained v1: it tracks
 * its own lightweight (typeName -> fields) map instead of InQL's `graphql-java` `GraphQLSchema`
 * (so there's no SDL/`GQLQueryPrinter` round-trip yet — see note on [Result.typesAsJson]), runs
 * strictly sequentially (InQL bucket-parallelizes with coroutines; not done here, matching the rest
 * of `GraphQlBridge`, which has no concurrent-send path), and discovers argument *names* only, not
 * their precise types (InQL's `probeArgumentType` systematically probes value types too).
 *
 * A known limitation from not modeling real argument requirements: a path field that itself
 * requires a non-null argument will error oddly when probed bare (no arguments supplied), which
 * can make probing stall below that point — same class of limitation InQL's own `convertPathToQuery`
 * exists specifically to paper over by supplying placeholder argument values, which this simplified
 * port does not attempt.
 *
 * Every document it sends carries a fake field or a fake argument, so a server that validates
 * documents before running them (as the specification requires) rejects each one: reconstructing
 * a schema executes no query and, above all, no mutation.
 *
 * The run is bounded: it stops after [maxRequests] requests, or as soon as [sendQuery] throws
 * [TargetUnreachableException], and returns what it has learnt so far (see [Result.stopped]).
 */
class SchemaBruteforcer(
    private val sendQuery: (String) -> String,
    private val bucketSize: Int = 64,
    private val depthLimit: Int = 2,
    private val bruteforceArguments: Boolean = true,
    private val wordlist: List<String> = Wordlists.fields,
    private val argumentWordlist: List<String> = Wordlists.args,
    private val maxRequests: Int = DEFAULT_MAX_REQUESTS,
) {
    data class DiscoveredField(val name: String, val typeHint: String?, val args: List<String>)
    data class DiscoveredType(val name: String, val kind: String, val fields: List<DiscoveredField>)

    /** Why a run ended before it had explored everything. */
    enum class StopReason { REQUEST_BUDGET, UNREACHABLE }

    /** [stopped] is null for a complete run; otherwise [types] is what was learnt up to that point. */
    class Result(val requestsSent: Int, val types: List<DiscoveredType>, val stopped: StopReason? = null) {
        fun typesAsJson(): JsonObject = buildJsonObject {
            types.forEach { t ->
                put(t.name, buildJsonObject {
                    put("kind", t.kind)
                    put("fields", buildJsonArray {
                        t.fields.forEach { f ->
                            add(buildJsonObject {
                                put("name", f.name)
                                f.typeHint?.let { put("type_hint", it) }
                                if (f.args.isNotEmpty()) put("args", buildJsonArray { f.args.forEach { a -> add(a) } })
                            })
                        }
                    })
                })
            }
        }
    }

    private data class ScanTarget(val operation: String, val fieldPath: List<String>, val typeName: String)

    /** Ends the run from wherever a request was about to be sent. */
    private class Halt(val reason: StopReason) : RuntimeException(null, null, false, false)

    companion object {
        const val DEFAULT_MAX_REQUESTS = 2_000

        private val BUILT_IN_SCALARS = setOf("String", "Int", "Float", "Boolean", "ID")
    }

    init {
        require(bucketSize > 0) { "bucketSize must be positive (got $bucketSize)" }
        require(maxRequests > 0) { "maxRequests must be positive (got $maxRequests)" }
    }

    private var requestsSent = 0

    /**
     * Sends [query] and returns the messages of the errors it drew. A body that is not a GraphQL
     * error reply (an HTML error page, an empty body) has none, so it confirms nothing.
     */
    private fun ask(query: String): List<String> {
        if (requestsSent >= maxRequests) throw Halt(StopReason.REQUEST_BUDGET)
        requestsSent++
        val body = try {
            sendQuery(query)
        } catch (_: TargetUnreachableException) {
            throw Halt(StopReason.UNREACHABLE)
        }
        val json = try { Json.parseToJsonElement(body) as? JsonObject } catch (_: Exception) { null } ?: return emptyList()
        return (json["errors"] as? JsonArray).orEmpty()
            .mapNotNull { ((it as? JsonObject)?.get("message") as? JsonPrimitive)?.contentOrNull }
    }

    private fun buildQuery(operation: String, fieldPath: List<String>, leaf: String): String {
        var body = leaf
        for (field in fieldPath.asReversed()) body = "$field { $body }"
        return "$operation { $body }"
    }

    /** The errors of selecting a fake subfield at [fieldPath]: they name the container's type, and any argument the last path field requires. */
    private fun probeContainer(operation: String, fieldPath: List<String>): List<String> =
        ask(buildQuery(operation, fieldPath, RegexStore.PROBE_FIELD))

    /** Resolves a container type name from the type-name-leaking errors of [probeContainer]. */
    private fun typenameFrom(messages: List<String>): String? {
        for (message in messages) {
            if (message.contains("Schema is not configured for")) return null
            RegexStore.SELECTION_ON_SCALAR.find(message)?.groups?.get("type")?.value?.let { return it }
            RegexStore.MISSING_SUBFIELDS.find(message)?.groups?.get("type")?.value?.let { return it }
            RegexStore.NO_SUBFIELDS.find(message)?.groups?.get("type")?.value?.let { return it }
            for (regex in RegexStore.WRONG_TYPENAME) {
                regex.find(message)?.groups?.get("typename")?.value?.let { return it }
            }
        }
        return null
    }

    private fun reportsInvalidField(message: String, fieldName: String): Boolean =
        RegexStore.WRONG_TYPENAME.any { it.find(message)?.groups?.get("field")?.value == fieldName }

    private fun unknownArguments(message: String): List<String> =
        RegexStore.UNKNOWN_ARGUMENT.flatMap { regex -> regex.findAll(message).mapNotNull { it.groups["argument"]?.value } }

    /**
     * Null return is the "this container is actually a scalar" signal (mirrors InQL's `probeValidFields`).
     * Each bucket is sent with the fake field appended: the names the server does not reject are
     * fields, and a bucket made of real fields only still cannot execute.
     */
    private fun probeValidFields(operation: String, fieldPath: List<String>): Set<String>? {
        val allValid = mutableSetOf<String>()
        for (bucket in wordlist.chunked(bucketSize)) {
            val messages = ask(buildQuery(operation, fieldPath, (bucket + RegexStore.PROBE_FIELD).joinToString(" ")))
            // Servers wrap these texts ("Validation error: ..."), so a match anywhere in the message counts.
            if (messages.any { RegexStore.NO_SUBFIELDS.containsMatchIn(it) || RegexStore.SELECTION_ON_SCALAR.containsMatchIn(it) }) {
                return null
            }

            // "Did you mean to use an inline fragment on X?" suggests types, not fields of this container.
            val suggestions = messages.filterNot { "inline fragment" in it }
                .flatMap { RegexStore.getSuggestions(it, RegexStore.FIELD_SUGGESTIONS) }.toSet()
            val invalid = mutableSetOf<String>()
            var hasRecognized = false
            for (message in messages) {
                for (regex in RegexStore.WRONG_TYPENAME) {
                    regex.find(message)?.groups?.get("field")?.value?.let { invalid.add(it); hasRecognized = true }
                }
            }
            if (suggestions.isNotEmpty() || hasRecognized) {
                allValid.addAll(bucket.toSet() - invalid + suggestions)
            }
        }
        return allValid
    }

    /**
     * Argument names of [fieldName]: the required ones named by [containerErrors] (the field's
     * [probeContainer] reply, sent without arguments), then the "did you mean" suggestions a fake
     * argument draws, and only when both find nothing a wordlist brute force.
     */
    private fun probeValidArguments(
        operation: String,
        fieldPath: List<String>,
        fieldName: String,
        containerErrors: List<String>,
    ): List<String> {
        val validArgs = linkedSetOf<String>()

        // 1. No arguments supplied: a required-argument error names the argument directly.
        for (message in containerErrors) {
            if (reportsInvalidField(message, fieldName)) return emptyList()
            RegexStore.MISSING_ARGUMENT.find(message)?.let { m ->
                if (m.groups["field"]?.value == fieldName) m.groups["argument"]?.value?.let { validArgs.add(it) }
            }
        }

        // 2. A fake argument name: "Unknown argument ... did you mean X?" leaks real ones.
        var foundViaSuggestions = false
        var rejectsUnknownArguments = false
        val fakeArgumentErrors = ask(buildQuery(operation, fieldPath, "$fieldName(${RegexStore.PROBE_ARG}: null) { __typename }"))
        for (message in fakeArgumentErrors) {
            if (reportsInvalidField(message, fieldName)) return emptyList()
            val suggestions = RegexStore.ARGUMENT_SUGGESTIONS.flatMap { regex ->
                regex.findAll(message).mapNotNull { m -> if (m.groups["field"]?.value == fieldName) m.groups["suggestion"]?.value else null }
            }.toMutableSet()
            if (RegexStore.PROBE_ARG in unknownArguments(message)) {
                rejectsUnknownArguments = true
                // The message is about our fake argument, so every name it suggests is an argument of this
                // field, however the server spells the field ("Query.user") or however many it lists.
                suggestions += RegexStore.getSuggestions(message, RegexStore.FIELD_SUGGESTIONS)
            }
            if (suggestions.isNotEmpty()) {
                foundViaSuggestions = true
                validArgs.addAll(suggestions)
            }
        }

        // 3. Wordlist brute force, only if the cheap probes above found nothing — and only against a
        // server that was just seen to name an unknown argument, since that error is all it reads.
        if (!foundViaSuggestions && validArgs.isEmpty() && bruteforceArguments && rejectsUnknownArguments) {
            for (bucket in argumentWordlist.chunked(bucketSize)) {
                validArgs.addAll(probeArgumentBucket(operation, fieldPath, fieldName, bucket) ?: break)
            }
        }
        return validArgs.toList()
    }

    /**
     * Tests one bucket of argument names in a single request, `field(a: null, b: null, ..., <fake>: null)`.
     * The trailing fake argument shows whether the server listed every unknown argument: once it
     * is reported, whatever the reply did not reject exists. A reply that stops short of it (a
     * server that reports only its first errors) just takes the names it did reject out, and the
     * rest is asked again. Null means the reply was unusable — the field is gone, or no unknown
     * argument was named at all — and the brute force should stop.
     */
    private fun probeArgumentBucket(
        operation: String,
        fieldPath: List<String>,
        fieldName: String,
        bucket: List<String>,
    ): Set<String>? {
        var remaining = bucket
        while (remaining.isNotEmpty()) {
            val arguments = (remaining + RegexStore.PROBE_ARG).joinToString(", ") { "$it: null" }
            val messages = ask(buildQuery(operation, fieldPath, "$fieldName($arguments) { __typename }"))
            if (messages.any { reportsInvalidField(it, fieldName) }) return null
            val unknown = messages.flatMapTo(mutableSetOf()) { unknownArguments(it) }
            if (RegexStore.PROBE_ARG in unknown) return remaining.filterNot { it in unknown }.toSet()
            val rejected = remaining.filter { it in unknown }
            if (rejected.isEmpty()) return null
            remaining = remaining - rejected.toSet()
        }
        return emptySet()
    }

    fun run(): Result {
        val discovered = LinkedHashMap<String, DiscoveredType>()
        val stopped = try {
            explore(discovered)
            null
        } catch (halt: Halt) {
            halt.reason
        }
        return Result(requestsSent, discovered.values.toList(), stopped)
    }

    private fun explore(discovered: MutableMap<String, DiscoveredType>) {
        val queryType = typenameFrom(probeContainer("query", emptyList())) ?: "Query"
        val mutationType = typenameFrom(probeContainer("mutation", emptyList()))
        val subscriptionType = typenameFrom(probeContainer("subscription", emptyList()))

        val scanned = mutableSetOf<String>()
        val worklist = ArrayDeque<ScanTarget>()
        listOfNotNull(
            "query" to queryType,
            mutationType?.let { "mutation" to it },
            subscriptionType?.let { "subscription" to it },
        ).forEach { (op, typeName) -> worklist.add(ScanTarget(op, emptyList(), typeName)) }

        while (worklist.isNotEmpty()) {
            val target = worklist.removeFirst()
            if (target.typeName in scanned || target.typeName in BUILT_IN_SCALARS) continue
            scanned.add(target.typeName)
            if (target.fieldPath.size > depthLimit) continue

            val validFields = probeValidFields(target.operation, target.fieldPath)
            if (validFields == null) {
                discovered[target.typeName] = DiscoveredType(target.typeName, "scalar", emptyList())
                continue
            }

            val fields = mutableListOf<DiscoveredField>()
            try {
                for (fieldName in validFields.sorted()) {
                    val childPath = target.fieldPath + fieldName
                    val containerErrors = probeContainer(target.operation, childPath)
                    val returnTypeName = typenameFrom(containerErrors)
                    val args = probeValidArguments(target.operation, target.fieldPath, fieldName, containerErrors)
                    fields.add(DiscoveredField(fieldName, returnTypeName, args))
                    if (returnTypeName != null && returnTypeName !in scanned && returnTypeName !in BUILT_IN_SCALARS) {
                        worklist.add(ScanTarget(target.operation, childPath, returnTypeName))
                    }
                }
            } finally {
                // Also on a halt: the fields worked out before it are part of the partial result.
                discovered[target.typeName] = DiscoveredType(target.typeName, "object", fields)
            }
        }
    }
}
