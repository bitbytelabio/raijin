package io.bitbytelab.raijin.graphql.scanners

import graphql.schema.GraphQLList
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLType
import graphql.schema.GraphQLTypeReference
import graphql.schema.GraphQLTypeUtil
import io.bitbytelab.raijin.graphql.GQLSchema

/**
 * DFS cycle detection over a schema's type graph (query/mutation/subscription roots) — flags
 * types that can recurse into themselves, a DoS/deeply-nested-query risk. Ported from InQL's
 * `CyclesScanner` (unchanged algorithm; drops its `Logger` dependency on a max-depth warning).
 */
class CyclesScanner(private val schema: GQLSchema, private val maxDepth: Int = 100) {
    private val visited = mutableSetOf<Pair<String, String?>>()
    private val visiting = mutableListOf<Pair<String, String?>>()
    private val foundCycles = mutableListOf<List<Pair<String, String?>>>()

    /** Runs the scan; call [cycles] afterward for the deduplicated result. */
    fun detect(): CyclesScanner {
        val all = schema.queries + schema.mutations + schema.subscriptions
        for (q in all) {
            detectCycle(q.key, q.value.type)
            visiting.clear()
            visited.clear()
        }
        return this
    }

    /** Each cycle as an ordered list of (fieldName, typeName) hops; deduplicated. */
    fun cycles(): List<List<Pair<String, String?>>> = foundCycles.distinct()

    fun cyclesAsStrings(): List<String> = cycles().map { cycle -> cycle.joinToString(" -> ") { (field, type) -> "$field ($type)" } }

    private fun detectCycle(fieldName: String, gqlType: GraphQLType, currentDepth: Int = 0): Boolean {
        if (currentDepth >= maxDepth) return false // might miss cycles beyond this depth

        val baseType = GraphQLTypeUtil.unwrapAll(gqlType)
        val typePair = fieldName to baseType.name

        if (typePair in visited) return false
        visited.add(typePair)
        visiting.add(typePair)

        when (baseType) {
            is GraphQLObjectType -> {
                baseType.fieldDefinitions.forEach { field ->
                    val fieldType = GraphQLTypeUtil.unwrapAll(field.type)
                    when {
                        fieldType is GraphQLList -> {
                            val wrapped = GraphQLTypeUtil.unwrapAll(fieldType.originalWrappedType)
                            if (detectCycle(field.name, wrapped, currentDepth + 1)) return true
                        }
                        fieldType is GraphQLObjectType -> {
                            val nextPair = field.name to fieldType.name
                            if (nextPair !in visited) {
                                if (detectCycle(field.name, fieldType, currentDepth + 1)) return true
                            } else if (nextPair in visiting) {
                                foundCycles.add(visiting.toList() + nextPair)
                                return true
                            }
                        }
                        fieldType is GraphQLTypeReference -> {
                            schema.schema.getType(fieldType.name)?.let { resolved ->
                                if (detectCycle(field.name, resolved, currentDepth + 1)) return true
                            }
                        }
                    }
                }
            }
            is GraphQLList -> {
                val wrapped = GraphQLTypeUtil.unwrapAll(baseType.originalWrappedType)
                return detectCycle(fieldName, wrapped, currentDepth)
            }
            else -> {}
        }

        visiting.removeLast()
        return false
    }
}
