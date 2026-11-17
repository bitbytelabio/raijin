package io.bitbytelab.raijin.graphql.scanners

import graphql.schema.GraphQLFieldDefinition
import graphql.schema.GraphQLFieldsContainer
import graphql.schema.GraphQLInterfaceType
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLScalarType
import graphql.schema.GraphQLType
import graphql.schema.GraphQLTypeReference
import graphql.schema.GraphQLTypeUtil
import graphql.schema.GraphQLUnionType
import io.bitbytelab.raijin.graphql.GQLSchema
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Walks a schema's query/mutation/subscription tree flagging fields whose name suggests a
 * security-interesting concern (auth, privileged, pii, payment, database, debugging, files),
 * plus deprecated fields and custom (non-builtin) scalars — ported from InQL's `POIScanner`.
 * Categories are loaded from the bundled `keywords.json` (vendored from InQL; same content).
 * Unlike InQL's version, categories/custom keywords are plain constructor parameters instead of
 * reading through InQL's global `Config` hook system.
 *
 * Also unlike InQL's version, which follows every path through object types only, the walk here
 * expands each type once per operation and goes through interfaces and unions: a recursive schema
 * (`User.friends: [User]`) cannot multiply the work, and fields that are only reachable through
 * an abstract type are still seen.
 */
class POIScanner(
    private val schema: GQLSchema,
    categories: Set<String> = DEFAULT_CATEGORIES,
    customKeywords: List<String> = emptyList(),
    private val flagDeprecated: Boolean = true,
    private val flagCustomScalars: Boolean = true,
) {
    data class FieldResult(val type: String, val path: String, val queryType: String, val description: String?)

    companion object {
        val DEFAULT_CATEGORIES = setOf("auth", "privileged", "pii", "payment", "database", "debugging", "files")

        private data class KeywordCategory(val name: String, val id: String, val keywords: List<String>)

        /**
         * The bundled `keywords.json` (vendored verbatim from InQL) has a typo'd category id,
         * "priviliged". Every other place in Raijin's own API surface — [DEFAULT_CATEGORIES],
         * the `poi_scan` tool description, the skill docs — uses the correctly-spelled
         * "privileged", so a caller typing the obvious spelling matched nothing. Remapped at load
         * time so "privileged" is the one id that exists anywhere in the public API/output.
         */
        private val categoryIdAliases = mapOf("priviliged" to "privileged")

        private val allCategories: List<KeywordCategory> by lazy {
            val text = POIScanner::class.java.getResource("/graphql/keywords.json")?.readText() ?: "[]"
            Json.parseToJsonElement(text).jsonArray.map { el ->
                val o = el.jsonObject
                val rawId = o["id"]?.jsonPrimitive?.contentOrNull ?: ""
                KeywordCategory(
                    name = o["name"]?.jsonPrimitive?.contentOrNull ?: "",
                    id = categoryIdAliases[rawId] ?: rawId,
                    keywords = o["keywords"]?.jsonArray?.mapNotNull { it.jsonPrimitive.contentOrNull } ?: emptyList(),
                )
            }
        }

        /** The category ids available from the bundled keyword file (for a tool's schema/description). */
        fun availableCategories(): Set<String> = allCategories.map { it.id }.toSet()

        private val BUILTIN_SCALARS = setOf("Int", "Float", "String", "Boolean", "ID")

        /**
         * A field name matches when one of [alternatives] is the whole name or a whole
         * `_`-separated part of it. Each alternative is a regex fragment.
         */
        private fun keywordPattern(alternatives: List<String>): Regex =
            Regex("(\\W|^|_)(${alternatives.joinToString("|")})(\\W|\$|_)", RegexOption.IGNORE_CASE)

        /**
         * One compiled pattern per bundled category, shared by every scanner. The bundled keywords
         * are regex fragments (`access.?key`), so they go in as written.
         */
        private val categoryPatterns: Map<String, Regex> by lazy {
            allCategories.filter { it.keywords.isNotEmpty() }.associate { it.id to keywordPattern(it.keywords) }
        }
    }

    /**
     * (category, pattern) in match priority: the bundled categories that were asked for, then the
     * caller's keywords. Those are matched literally: they are escaped, so no caller input can
     * break the pattern or turn into a slow one.
     */
    private val patterns: List<Pair<String, Regex>> = buildList {
        for ((id, pattern) in categoryPatterns) {
            if (id in categories) add(id to pattern)
        }
        val literals = customKeywords.map { it.trim() }.filter { it.isNotEmpty() }
        if (literals.isNotEmpty()) add("custom" to keywordPattern(literals.map { Regex.escape(it) }))
    }

    /** One pending stop of the walk: the type reached at [path], with [depth] levels left to expand. */
    private class Step(val type: GraphQLType, val path: String, val depth: Int, val inherited: Set<String> = emptySet())

    /**
     * Scans and returns results grouped by concern type, each entry deduplicated by path. A field
     * is reported once per operation type, at the shortest path that reaches it; [depth] is how
     * many levels below a root field's type are expanded.
     */
    fun scan(depth: Int = 10): Map<String, List<FieldResult>> {
        val results = mutableListOf<FieldResult>()
        scanOperation(schema.queries, "Query", depth, results)
        scanOperation(schema.mutations, "Mutation", depth, results)
        scanOperation(schema.subscriptions, "Subscription", depth, results)

        val finalResults = linkedMapOf<String, MutableList<FieldResult>>()
        val seenPaths = mutableMapOf<Pair<String, String>, MutableSet<String>>()
        for (r in results.distinct()) {
            val bucket = finalResults.getOrPut(r.type) { mutableListOf() }
            val seen = seenPaths.getOrPut(r.type to r.queryType) { mutableSetOf() }
            if (seen.add(r.path)) bucket.add(r)
        }
        return finalResults
    }

    /**
     * Breadth-first walk from one operation's root fields. Root fields (e.g. "login",
     * "deleteUser") are checked themselves, not just the fields inside their return type. Every
     * composite type is expanded once ([visited]), which is what ends the walk on recursive types
     * and makes the first, shortest path the one a field is reported at.
     */
    private fun scanOperation(
        roots: Map<String, GraphQLFieldDefinition>,
        queryType: String,
        depth: Int,
        results: MutableList<FieldResult>,
    ) {
        val visited = mutableSetOf<String>()
        val queue = ArrayDeque<Step>()
        for ((name, field) in roots) {
            val path = "-> $name"
            results.addAll(checkField(field, path, queryType))
            queue.add(Step(field.type, path, depth))
        }

        while (queue.isNotEmpty()) {
            val step = queue.removeFirst()
            if (step.depth < 0) continue
            when (val type = resolve(GraphQLTypeUtil.unwrapAll(step.type))) {
                is GraphQLScalarType -> {
                    if (flagCustomScalars && type.name !in BUILTIN_SCALARS) {
                        results.add(FieldResult("custom scalar", step.path, queryType, type.description))
                    }
                }
                is GraphQLObjectType -> {
                    if (visited.add(type.name)) expandFields(type, step, queryType, queue, results)
                }
                is GraphQLInterfaceType -> {
                    if (visited.add(type.name)) {
                        expandFields(type, step, queryType, queue, results)
                        // The interface's own fields were just reported; an implementation adds the rest.
                        val declared = type.fieldDefinitions.mapTo(mutableSetOf()) { it.name }
                        for (implementation in schema.schema.getImplementations(type).orEmpty()) {
                            queue.add(Step(implementation, "${step.path} -> ... on ${implementation.name}", step.depth, declared))
                        }
                    }
                }
                is GraphQLUnionType -> {
                    if (visited.add(type.name)) {
                        for (member in type.types) {
                            queue.add(Step(member, "${step.path} -> ... on ${member.name}", step.depth))
                        }
                    }
                }
                else -> {}
            }
        }
    }

    private fun expandFields(
        container: GraphQLFieldsContainer,
        step: Step,
        queryType: String,
        queue: ArrayDeque<Step>,
        results: MutableList<FieldResult>,
    ) {
        for (field in container.fieldDefinitions) {
            if (field.name in step.inherited) continue
            val fieldPath = "${step.path} -> ${field.name}"
            results.addAll(checkField(field, fieldPath, queryType))
            queue.add(Step(field.type, fieldPath, step.depth - 1))
        }
    }

    /** A schema built by graphql-java has no unresolved references left; this only guards a hand-built one. */
    private fun resolve(type: GraphQLType): GraphQLType =
        if (type is GraphQLTypeReference) schema.schema.getType(type.name) ?: type else type

    private fun checkField(field: GraphQLFieldDefinition, path: String, queryType: String): List<FieldResult> {
        val results = mutableListOf<FieldResult>()
        if (flagDeprecated && field.isDeprecated) {
            results.add(FieldResult("deprecated", path, queryType, field.description))
        }
        val category = patterns.firstOrNull { (_, pattern) -> pattern.containsMatchIn(field.name) }?.first
        if (category != null) results.add(FieldResult(category, path, queryType, field.description))
        return results
    }
}
