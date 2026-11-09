package io.bitbytelab.raijin.graphql

import graphql.introspection.IntrospectionResultToSchema
import graphql.schema.GraphQLFieldDefinition
import graphql.schema.GraphQLSchema
import graphql.schema.idl.RuntimeWiring
import graphql.schema.idl.SchemaGenerator
import graphql.schema.idl.SchemaParser
import graphql.schema.idl.SchemaPrinter
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

/**
 * Wraps a graphql-java [GraphQLSchema] built from either a full-introspection-query JSON result
 * or raw SDL text — ported from InQL's `GQLSchema` (same library doing the actual schema
 * modeling in both). Needs the FULL official introspection query result
 * (`graphql.introspection.IntrospectionQuery.INTROSPECTION_QUERY`); Raijin's own lightweight
 * [GraphQl.INTROSPECTION_QUERY] (used by [io.bitbytelab.raijin.bridge.GraphQlBridge.probe]'s basic
 * verdict) omits the field/argument/enum detail this needs to build an executable schema.
 */
class GQLSchema(jsonOrSdlSchema: String) {
    enum class OperationType { QUERY, MUTATION, SUBSCRIPTION }

    val schema: GraphQLSchema
    private var sdlCache: String? = null

    init {
        val schemaParser = SchemaParser()
        val registry = try {
            var obj = Json.parseToJsonElement(jsonOrSdlSchema) as? JsonObject
                ?: throw IllegalArgumentException("not a JSON object")
            (obj["data"] as? JsonObject)?.let { obj = it }
            if (obj["__schema"] !is JsonObject) throw IllegalArgumentException("no __schema key")
            @Suppress("UNCHECKED_CAST")
            val rawMap = toRawTree(obj) as Map<String, Any?>
            val document = IntrospectionResultToSchema().createSchemaDefinition(rawMap)
            schemaParser.buildRegistry(document)
        } catch (_: Exception) {
            // Not (recognizable) introspection JSON — try it as raw SDL text instead.
            schemaParser.parse(jsonOrSdlSchema)
        }
        schema = SchemaGenerator().makeExecutableSchema(registry, RuntimeWiring.MOCKED_WIRING)
    }

    val queries: Map<String, GraphQLFieldDefinition> get() = schema.queryType.fields.associateBy { it.name }

    val mutations: Map<String, GraphQLFieldDefinition>
        get() = if (schema.isSupportingMutations) schema.mutationType.fields.associateBy { it.name } else emptyMap()

    val subscriptions: Map<String, GraphQLFieldDefinition>
        get() = if (schema.isSupportingSubscriptions) schema.subscriptionType.fields.associateBy { it.name } else emptyMap()

    /** The schema rendered as SDL text (cached after first access). */
    val sdlSchema: String
        get() {
            if (sdlCache == null) sdlCache = SchemaPrinter().print(schema)
            return sdlCache!!
        }

    /** Generates a runnable example query/mutation/subscription for [operationName]; null if it doesn't exist. */
    fun operationAsText(operationName: String, type: OperationType, maxDepth: Int = 6, padSize: Int = 2): String? {
        val field = when (type) {
            OperationType.QUERY -> queries[operationName]
            OperationType.MUTATION -> mutations[operationName]
            OperationType.SUBSCRIPTION -> subscriptions[operationName]
        } ?: return null
        return GQLQueryPrinter(field, type, maxDepth, padSize).printSDL()
    }
}

/** Converts a parsed [JsonElement] tree into the plain Map/List/primitive shape graphql-java's IntrospectionResultToSchema expects. */
private fun toRawTree(element: JsonElement): Any? = when (element) {
    is JsonNull -> null
    is JsonObject -> element.entries.associate { (k, v) -> k to toRawTree(v) }
    is JsonArray -> element.map { toRawTree(it) }
    is JsonPrimitive -> when {
        element.isString -> element.content
        else -> element.booleanOrNull ?: element.longOrNull ?: element.doubleOrNull ?: element.content
    }
}
