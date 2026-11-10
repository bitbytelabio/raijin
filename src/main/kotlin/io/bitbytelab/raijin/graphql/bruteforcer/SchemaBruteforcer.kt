package io.bitbytelab.raijin.graphql.bruteforcer

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
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
 */
class SchemaBruteforcer(
    private val sendQuery: (String) -> String,
    private val bucketSize: Int = 64,
    private val depthLimit: Int = 2,
    private val bruteforceArguments: Boolean = true,
    private val wordlist: List<String> = Wordlists.fields,
    private val argumentWordlist: List<String> = Wordlists.args,
) {
    data class DiscoveredField(val name: String, val typeHint: String?, val args: List<String>)
    data class DiscoveredType(val name: String, val kind: String, val fields: List<DiscoveredField>)
    class Result(val requestsSent: Int, val types: List<DiscoveredType>) {
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

    companion object {
        private val BUILT_IN_SCALARS = setOf("String", "Int", "Float", "Boolean", "ID")
    }

    private var requestsSent = 0

    private fun send(query: String): String {
        requestsSent++
        return sendQuery(query)
    }

    private fun buildQuery(operation: String, fieldPath: List<String>, leaf: String): String {
        var body = leaf
        for (field in fieldPath.asReversed()) body = "$field { $body }"
        return "$operation { $body }"
    }

    private fun errorMessages(body: String): List<String> {
        val obj = try { Json.parseToJsonElement(body).jsonObject } catch (_: Exception) { return emptyList() }
        val errors = obj["errors"] as? JsonArray ?: return emptyList()
        return errors.mapNotNull { (it as? JsonObject)?.get("message")?.jsonPrimitive?.contentOrNull }
    }

    /** Resolves the container type name at [fieldPath] by forcing a type-name-leaking error. */
    private fun probeTypename(operation: String, fieldPath: List<String>): String? {
        val body = send(buildQuery(operation, fieldPath, RegexStore.PROBE_FIELD))
        for (message in errorMessages(body)) {
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

    /** Null return is the "this container is actually a scalar" signal (mirrors InQL's `probeValidFields`). */
    private fun probeValidFields(operation: String, fieldPath: List<String>): Set<String>? {
        val allValid = mutableSetOf<String>()
        for (bucket in wordlist.chunked(bucketSize)) {
            val body = send(buildQuery(operation, fieldPath, bucket.joinToString(" ")))
            val messages = errorMessages(body)
            if (messages.isEmpty()) {
                allValid.addAll(bucket)
                continue
            }
            if (messages.any { RegexStore.NO_SUBFIELDS.matches(it) || RegexStore.SELECTION_ON_SCALAR.matches(it) }) {
                return null
            }

            val suggestions = messages.flatMap { RegexStore.getSuggestions(it, RegexStore.FIELD_SUGGESTIONS) }.toSet()
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

    /** Discovers argument names on [fieldName]: a cheap no-args + fake-arg-name probe first, wordlist brute force only as a fallback. */
    private fun probeValidArguments(operation: String, fieldPath: List<String>, fieldName: String): List<String> {
        val validArgs = mutableSetOf<String>()
        val childPath = fieldPath + fieldName

        // 1. No arguments supplied: a required-argument error names the argument directly.
        run {
            val body = send(buildQuery(operation, childPath, "__typename"))
            for (message in errorMessages(body)) {
                for (regex in RegexStore.WRONG_TYPENAME) {
                    if (regex.find(message)?.groups?.get("field")?.value == fieldName) return emptyList()
                }
                RegexStore.MISSING_ARGUMENT.find(message)?.let { m ->
                    if (m.groups["field"]?.value == fieldName) m.groups["argument"]?.value?.let { validArgs.add(it) }
                }
            }
        }

        // 2. A fake argument name: "Unknown argument ... did you mean X?" leaks a real one.
        var foundViaSuggestions = false
        run {
            val query = buildQuery(operation, fieldPath, "$fieldName(${RegexStore.PROBE_ARG}: null) { __typename }")
            val body = send(query)
            for (message in errorMessages(body)) {
                for (regex in RegexStore.WRONG_TYPENAME) {
                    if (regex.find(message)?.groups?.get("field")?.value == fieldName) return emptyList()
                }
                val suggestions = RegexStore.ARGUMENT_SUGGESTIONS.flatMap { regex ->
                    regex.findAll(message).mapNotNull { m -> if (m.groups["field"]?.value == fieldName) m.groups["suggestion"]?.value else null }
                }.distinct()
                if (suggestions.isNotEmpty()) {
                    foundViaSuggestions = true
                    validArgs.addAll(suggestions)
                }
            }
        }

        // 3. Wordlist brute force, only if the cheap probes above found nothing.
        if (!foundViaSuggestions && validArgs.isEmpty() && bruteforceArguments) {
            outer@ for (bucket in argumentWordlist.chunked(bucketSize)) {
                for (candidate in bucket) {
                    val query = buildQuery(operation, fieldPath, "$fieldName($candidate: null) { __typename }")
                    val body = send(query)
                    val messages = errorMessages(body)
                    if (messages.isEmpty()) {
                        validArgs.add(candidate)
                        continue
                    }
                    var fieldInvalid = false
                    var candidateUnknown = false
                    for (message in messages) {
                        for (regex in RegexStore.WRONG_TYPENAME) {
                            if (regex.find(message)?.groups?.get("field")?.value == fieldName) { fieldInvalid = true; break }
                        }
                        if (fieldInvalid) break
                        for (regex in RegexStore.UNKNOWN_ARGUMENT) {
                            if (regex.find(message)?.groups?.get("argument")?.value == candidate) { candidateUnknown = true; break }
                        }
                    }
                    if (fieldInvalid) break@outer
                    if (!candidateUnknown) validArgs.add(candidate)
                }
            }
        }
        return validArgs.toList()
    }

    fun run(): Result {
        val queryType = probeTypename("query", emptyList()) ?: "Query"
        val mutationType = probeTypename("mutation", emptyList())
        val subscriptionType = probeTypename("subscription", emptyList())

        val discovered = LinkedHashMap<String, DiscoveredType>()
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
            for (fieldName in validFields.sorted()) {
                val childPath = target.fieldPath + fieldName
                val returnTypeName = probeTypename(target.operation, childPath)
                val args = probeValidArguments(target.operation, target.fieldPath, fieldName)
                fields.add(DiscoveredField(fieldName, returnTypeName, args))
                if (returnTypeName != null && returnTypeName !in scanned && returnTypeName !in BUILT_IN_SCALARS) {
                    worklist.add(ScanTarget(target.operation, childPath, returnTypeName))
                }
            }
            discovered[target.typeName] = DiscoveredType(target.typeName, "object", fields)
        }

        return Result(requestsSent, discovered.values.toList())
    }
}
