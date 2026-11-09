package io.bitbytelab.raijin.graphql

import graphql.language.ArrayValue
import graphql.language.BooleanValue
import graphql.language.EnumValue
import graphql.language.FloatValue
import graphql.language.IntValue
import graphql.language.NullValue
import graphql.language.ObjectValue
import graphql.language.StringValue
import graphql.language.Value
import graphql.schema.GraphQLArgument
import graphql.schema.GraphQLEnumType
import graphql.schema.GraphQLFieldDefinition
import graphql.schema.GraphQLFieldsContainer
import graphql.schema.GraphQLModifiedType
import graphql.schema.GraphQLNamedType
import graphql.schema.GraphQLScalarType
import graphql.schema.GraphQLType
import graphql.schema.GraphQLUnionType
import graphql.schema.InputValueWithState

/**
 * Generates a runnable example query/mutation/subscription SDL text from a schema field,
 * recursing through its type tree up to [maxDepth] — ported from InQL's `GQLQueryPrinter`
 * (unchanged algorithm; only the `inql.graphql.Utils.unwrapType`/`formatComment` helpers it used
 * are inlined here as private functions instead of pulled from InQL's own utility object).
 */
class GQLQueryPrinter(
    private val field: GraphQLFieldDefinition,
    private val operationType: GQLSchema.OperationType,
    private val maxDepth: Int = 6,
    private val padSize: Int = 2,
) {
    companion object {
        private val BUILTIN_SCALARS = setOf("Int", "Float", "String", "Boolean", "ID")
    }

    private var sdl: String? = null

    fun printSDL(): String {
        if (sdl == null) {
            val sb = StringBuilder()
            sb.appendLine("${operationType.name.lowercase()} ${field.name} {")
            printSingleField(field, sb, 1, maxDepth, padSize)
            sb.appendLine("}")
            sdl = sb.toString()
        }
        return sdl!!
    }

    private fun printSingleField(type: GraphQLFieldDefinition, sb: StringBuilder, depth: Int, maxDepth: Int, padSize: Int) {
        val padding = " ".repeat(padSize * depth)
        val descriptionLines = printFieldComment(type)
        val name = type.name
        val args = printArguments(type.arguments)
        val innerType = unwrapType(type.type)
        val isLeaf = innerType is GraphQLScalarType || innerType is GraphQLEnumType

        if (isLeaf) {
            if (descriptionLines.size == 1) {
                sb.appendLine("$padding$name$args ${descriptionLines[0]}")
                return
            }
            appendLinesWithPadding(sb, descriptionLines, padding)
            sb.appendLine("$padding$name$args")
            return
        }

        if (innerType !is GraphQLFieldsContainer && innerType !is GraphQLUnionType) {
            // Unresolved/unsupported type shape — emit it commented out rather than throwing, so
            // one unusual field doesn't fail the whole generated query.
            sb.appendLine("$padding$name$args # { Unsupported field type: $innerType }")
            return
        }

        appendLinesWithPadding(sb, descriptionLines, padding)

        if (depth > maxDepth) {
            sb.appendLine("$padding$name$args # { Truncated by depth limit }")
            return
        }

        sb.appendLine("$padding$name$args {")
        when (innerType) {
            is GraphQLFieldsContainer -> {
                for (innerField in innerType.fields.sortedBy { it.name }) {
                    printSingleField(innerField, sb, depth + 1, maxDepth, padSize)
                }
            }
            is GraphQLUnionType -> {
                for (unionInnerType in innerType.types.sortedBy { it.name }) {
                    if (unionInnerType is GraphQLFieldsContainer) {
                        printUnionType(unionInnerType, sb, depth + 1, maxDepth, padSize)
                    }
                }
            }
            else -> {}
        }
        sb.appendLine("$padding}")
    }

    private fun printUnionType(type: GraphQLFieldsContainer, sb: StringBuilder, depth: Int, maxDepth: Int, padSize: Int) {
        val padding = " ".repeat(padSize * depth)
        sb.appendLine("$padding... on ${type.name} {")
        sb.appendLine("${" ".repeat(padSize * (depth + 1))}__typename")
        for (field in type.fields.sortedBy { it.name }) {
            printSingleField(field, sb, depth + 1, maxDepth, padSize)
        }
        sb.appendLine("$padding}")
    }

    private fun printLiteralValue(value: Value<*>): String = when (value) {
        is StringValue -> "\"${value.value}\""
        is BooleanValue -> "${value.isValue}"
        is EnumValue -> value.name
        is FloatValue -> "${value.value}"
        is IntValue -> "${value.value}"
        is NullValue -> "null"
        is ObjectValue -> "{${value.objectFields.joinToString(", ") { "${it.name}: ${printLiteralValue(it.value)}" }}}"
        is ArrayValue -> "[${value.values.joinToString(", ") { printLiteralValue(it) }}]"
        else -> value.toString()
    }

    private fun printArgumentDefaultValue(valueObj: InputValueWithState): String? {
        if (valueObj.isNotSet) return null
        val value = valueObj.value
        return when {
            valueObj.isExternal -> if (value is String) "\"$value\"" else value.toString()
            valueObj.isLiteral && value is Value<*> -> printLiteralValue(value)
            else -> null
        }
    }

    private fun printArgument(argument: GraphQLArgument): String {
        val defaultValue = printArgumentDefaultValue(argument.argumentDefaultValue)
        val type = argument.type
        val typeString = if (type is GraphQLNamedType) type.name else type.toString()
        return if (defaultValue != null) "${argument.name}: $typeString = $defaultValue" else "${argument.name}: $typeString"
    }

    private fun printArguments(args: List<GraphQLArgument>): String =
        if (args.isEmpty()) "" else "(${args.joinToString(", ") { printArgument(it) }})"

    private fun printArgsDescription(args: List<GraphQLArgument>): List<String> =
        args.filter { it.description != null }.map { "${it.name}: ${it.description}" }

    private fun getFieldDescription(type: GraphQLFieldDefinition): String? {
        if (type.description != null) return type.description
        val innerType = unwrapType(type.type)
        if (innerType is GraphQLNamedType && innerType.description != null) return innerType.description
        return null
    }

    private fun printFieldComment(type: GraphQLFieldDefinition): List<String> {
        val innerType = unwrapType(type.type)

        val description: MutableList<String> = if (innerType is GraphQLScalarType && BUILTIN_SCALARS.contains(innerType.name)) {
            type.description?.lines()?.toMutableList() ?: mutableListOf()
        } else {
            getFieldDescription(type)?.lines()?.toMutableList() ?: mutableListOf()
        }

        if (innerType is GraphQLEnumType) {
            if (description.isEmpty() || description[0].isEmpty()) {
                description.add("(enum):")
            } else {
                description[0] = "(enum) ${description[0]}"
                if (!setOf('.', '!', '?', ':', ';').contains(description.last().last())) {
                    description.add("${description.removeLast()}:")
                }
            }
            description.addAll(innerType.values.map { " - ${it.name} (${it.description})" })
        }

        val argsDesc = printArgsDescription(type.arguments)
        if (argsDesc.isNotEmpty()) {
            if (description.isNotEmpty() && description.last().isNotEmpty() &&
                !setOf('.', '!', '?', ':', ';').contains(description.last().last())
            ) {
                description.add("${description.removeLast()}:")
            }
            description.addAll(argsDesc.map { " - $it" })
        }

        if (description.size == 1 && description[0].isEmpty()) return emptyList()
        return formatComment(description)
    }

    private fun appendLinesWithPadding(sb: StringBuilder, strings: List<String>, padding: String) {
        for (string in strings) {
            sb.append(padding)
            sb.appendLine(string)
        }
    }
}

/** Strips `GraphQLNonNull`/`GraphQLList` wrappers down to the named type underneath. */
private fun unwrapType(type: GraphQLType): GraphQLType {
    var outputType: GraphQLType = type
    while (outputType is GraphQLModifiedType) {
        outputType = outputType.wrappedType
    }
    return outputType
}

/** Word-wraps each line to [maxLength] and prefixes every resulting line with "# " (a GraphQL comment). */
private fun formatComment(strings: List<String>, maxLength: Int = 100): List<String> {
    val out = mutableListOf<String>()
    for (line in strings) {
        var currentLine = line
        while (currentLine.length > maxLength) {
            val splitOn = currentLine.lastIndexOf(' ', maxLength)
            if (splitOn == -1) break
            out.add("# ${currentLine.substring(0, splitOn)}")
            currentLine = currentLine.substring(splitOn + 1)
        }
        out.add("# $currentLine")
    }
    return out
}
