package io.bitbytelab.raijin.graphql.scanners

import graphql.schema.GraphQLFieldDefinition
import graphql.schema.GraphQLList
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLScalarType
import graphql.schema.GraphQLType
import graphql.schema.GraphQLTypeReference
import graphql.schema.GraphQLTypeUtil
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
        val DEFAULT_CATEGORIES = setOf("auth", "priviliged", "pii", "payment", "database", "debugging", "files")

        private data class KeywordCategory(val name: String, val id: String, val keywords: List<String>)

        private val allCategories: List<KeywordCategory> by lazy {
            val text = POIScanner::class.java.getResource("/graphql/keywords.json")?.readText() ?: "[]"
            Json.parseToJsonElement(text).jsonArray.map { el ->
                val o = el.jsonObject
                KeywordCategory(
                    name = o["name"]?.jsonPrimitive?.contentOrNull ?: "",
                    id = o["id"]?.jsonPrimitive?.contentOrNull ?: "",
                    keywords = o["keywords"]?.jsonArray?.mapNotNull { it.jsonPrimitive.contentOrNull } ?: emptyList(),
                )
            }
        }

        /** The category ids available from the bundled keyword file (for a tool's schema/description). */
        fun availableCategories(): Set<String> = allCategories.map { it.id }.toSet()

        private val BUILTIN_SCALARS = setOf("Int", "Float", "String", "Boolean", "ID")
    }

    private val regexKeywords: Map<String, String> = buildMap {
        for (cat in allCategories) {
            if (cat.id in categories) put(cat.id, cat.keywords.joinToString("|"))
        }
        if (customKeywords.isNotEmpty()) put("custom", customKeywords.joinToString("|"))
    }

    /** Scans and returns results grouped by concern type, each entry deduplicated by path. */
    fun scan(depth: Int = 10): Map<String, List<FieldResult>> {
        val results = mutableListOf<FieldResult>()
        for (q in schema.queries) results.addAll(scanField(q.value.type, "", "Query", depth))
        for (q in schema.mutations) results.addAll(scanField(q.value.type, "", "Mutation", depth))
        for (q in schema.subscriptions) results.addAll(scanField(q.value.type, "", "Subscription", depth))

        val finalResults = linkedMapOf<String, MutableList<FieldResult>>()
        val seenPaths = mutableMapOf<String, MutableSet<String>>()
        for (r in results.distinct()) {
            val bucket = finalResults.getOrPut(r.type) { mutableListOf() }
            val seen = seenPaths.getOrPut(r.type) { mutableSetOf() }
            if (seen.add(r.path)) bucket.add(r)
        }
        return finalResults
    }

    private fun scanField(type: GraphQLType, currentPath: String, queryType: String, depth: Int): List<FieldResult> {
        if (depth < 0) return emptyList()
        val results = mutableListOf<FieldResult>()
        val unwrapped = GraphQLTypeUtil.unwrapAll(type)

        when (unwrapped) {
            is GraphQLObjectType -> {
                unwrapped.fieldDefinitions.forEach { field ->
                    val fieldPath = "$currentPath -> ${field.name}"
                    results.addAll(checkField(field, fieldPath, queryType))
                    results.addAll(scanField(field.type, fieldPath, queryType, depth - 1))
                }
            }
            is GraphQLList -> results.addAll(scanField(unwrapped.wrappedType, currentPath, queryType, depth))
            is GraphQLScalarType -> {
                if (flagCustomScalars && unwrapped.name !in BUILTIN_SCALARS) {
                    results.add(FieldResult("custom scalar", currentPath, queryType, unwrapped.description))
                }
            }
            is GraphQLTypeReference -> {
                schema.schema.getType(unwrapped.name)?.let { resolved ->
                    results.addAll(scanField(resolved, currentPath, queryType, depth))
                }
            }
            else -> {}
        }
        return results
    }

    private fun checkField(field: GraphQLFieldDefinition, path: String, queryType: String): List<FieldResult> {
        val results = mutableListOf<FieldResult>()
        if (flagDeprecated && field.isDeprecated) {
            results.add(FieldResult("deprecated", path, queryType, field.description))
        }
        for ((keywordName, regexPattern) in regexKeywords) {
            if (regexPattern.isNotEmpty() && Regex("(\\W|^|_)($regexPattern)(\\W|\$|_)", RegexOption.IGNORE_CASE).containsMatchIn(field.name)) {
                results.add(FieldResult(keywordName, path, queryType, field.description))
                break
            }
        }
        return results
    }
}
