package io.bitbytelab.raijin.graphql

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Detects the GraphQL backend engine by sending a sequence of malformed/edge-case queries and
 * matching each engine's distinctive error text — ported from InQL's `Fingerprinter`
 * (inql/fingerprinter/Fingerprinter.kt). Each check is tried in the same priority order InQL
 * uses (more specific/rarer engines first, since several share overlapping error text), and the
 * first match wins.
 */
object EngineFingerprinter {

    data class Outcome(val engine: String?, val checked: Int)

    /** Runs every check via [sendQuery] (query text in, raw response body out) until one matches. */
    fun detect(sendQuery: (String) -> String): Outcome {
        val order: List<Pair<String, ((String) -> String) -> Boolean>> = listOf(
            "inigo" to { s: (String) -> String -> engineInigo(s) },
            "lighthouse" to { s: (String) -> String -> engineLighthouse(s) },
            "caliban" to { s: (String) -> String -> engineCaliban(s) },
            "lacinia" to { s: (String) -> String -> engineLacinia(s) },
            "morpheus-graphql" to { s: (String) -> String -> engineMorpheus(s) },
            "mercurius" to { s: (String) -> String -> engineMercurius(s) },
            "graphql_yoga" to { s: (String) -> String -> engineGraphqlYoga(s) },
            "agoo" to { s: (String) -> String -> engineAgoo(s) },
            "tailcall" to { s: (String) -> String -> engineTailcall(s) },
            "dgraph" to { s: (String) -> String -> engineDgraph(s) },
            "graphene" to { s: (String) -> String -> engineGraphene(s) },
            "ariadne" to { s: (String) -> String -> engineAriadne(s) },
            "apollo" to { s: (String) -> String -> engineApollo(s) },
            "aws-appsync" to { s: (String) -> String -> engineAwsAppSync(s) },
            "hasura" to { s: (String) -> String -> engineHasura(s) },
            "wpgraphql" to { s: (String) -> String -> engineWpGraphql(s) },
            "graphql-java" to { s: (String) -> String -> engineGraphqlJava(s) },
            "hypergraphql" to { s: (String) -> String -> engineHypergraphql(s) },
            "ruby-graphql" to { s: (String) -> String -> engineRuby(s) },
            "graphql-php" to { s: (String) -> String -> engineGraphqlPhp(s) },
            "gqlgen" to { s: (String) -> String -> engineGqlGen(s) },
            "graphql-go" to { s: (String) -> String -> engineGraphqlGo(s) },
            "juniper" to { s: (String) -> String -> engineJuniper(s) },
            "sangria" to { s: (String) -> String -> engineSangria(s) },
            "dianajl" to { s: (String) -> String -> engineDianaJl(s) },
            "strawberry" to { s: (String) -> String -> engineStrawberry(s) },
            "tartiflette" to { s: (String) -> String -> engineTartiflette(s) },
            "directus" to { s: (String) -> String -> engineDirectus(s) },
            "absinthe-graphql" to { s: (String) -> String -> engineAbsinthe(s) },
            "graphql-dotnet" to { s: (String) -> String -> engineGraphqlDotNet(s) },
            "pg_graphql" to { s: (String) -> String -> enginePgGraphql(s) },
            "hotchocolate" to { s: (String) -> String -> engineHotChocolate(s) },
            "ballerina" to { s: (String) -> String -> engineBallerina(s) },
            "flutter" to { s: (String) -> String -> engineFlutter(s) },
        )
        for ((i, pair) in order.withIndex()) {
            val (name, check) = pair
            val matched = try { check(sendQuery) } catch (_: Exception) { false }
            if (matched) return Outcome(name, i + 1)
        }
        return Outcome(null, order.size)
    }

    // -------------------------------------------------------------------
    // JSON helpers — mirrors InQL's `errorContains(resp: JSONObject, msg)`: if the response has
    // a top-level "errors" array, look for `msg` inside any one error entry's re-serialized JSON
    // text (this is deliberate: GraphQL servers that double-escape quotes in error messages need
    // the match string to carry the same `\"` escaping); otherwise fall back to a plain substring
    // search over the whole raw body.
    // -------------------------------------------------------------------

    private fun parseOrNull(body: String): JsonObject? =
        try { Json.parseToJsonElement(body).jsonObject } catch (_: Exception) { null }

    private fun errorContains(body: String, msg: String): Boolean {
        val errors = parseOrNull(body)?.get("errors") as? JsonArray
        return if (errors != null) errors.any { it.toString().contains(msg) } else body.contains(msg)
    }

    private fun typename(body: String): String? =
        (parseOrNull(body)?.get("data") as? JsonObject)?.get("__typename")?.jsonPrimitive?.contentOrNull

    private fun hasDataKey(body: String): Boolean = parseOrNull(body)?.containsKey("data") == true

    // -------------------------------------------------------------------
    // Per-engine checks — ported 1:1 from Fingerprinter.kt's engineXxx() functions.
    // -------------------------------------------------------------------

    private fun engineGraphqlYoga(send: (String) -> String): Boolean {
        val resp = send("subscription {\n   __typename\n}")
        return errorContains(resp, "asyncExecutionResult[Symbol.asyncIterator] is not a function") ||
            errorContains(resp, "Unexpected error.")
    }

    private fun engineApollo(send: (String) -> String): Boolean {
        var resp = send("query @skip {\n  __typename\n}")
        if (errorContains(resp, "Directive \\\"@skip\\\" argument \\\"if\\\" of type \\\"Boolean!\\\" is required, but it was not provided.")) {
            return true
        }
        resp = send("query @deprecated {\n  __typename\n}")
        return errorContains(resp, "Directive \\\"@deprecated\\\" may not be used on QUERY.")
    }

    private fun engineAwsAppSync(send: (String) -> String): Boolean {
        val resp = send("query @skip { __typename }")
        return errorContains(resp, "MisplacedDirective")
    }

    private fun engineGraphene(send: (String) -> String): Boolean {
        val resp = send("aaa")
        return errorContains(resp, "Syntax Error GraphQL (1:1)")
    }

    private fun engineHasura(send: (String) -> String): Boolean {
        var resp = send("query @cached {\n  __typename\n}")
        if (typename(resp) == "query_root") return true

        resp = send("query {\n aaa\n}")
        if (errorContains(resp, "field \"aaa\" not found in type: 'query_root'")) return true

        resp = send("query @skip {\n  __typename\n}")
        if (errorContains(resp, "directive \"skip\" is not allowed on a query")) return true

        resp = send("query {\n  __schema\n}")
        return errorContains(resp, "missing selection set for \"__Schema\"")
    }

    private fun engineGraphqlPhp(send: (String) -> String): Boolean {
        var resp = send("query ! {\n  __typename\n}")
        if (errorContains(resp, "Syntax Error: Cannot parse the unexpected character \\\"?\\\".")) return true

        resp = send("query @deprecated {\n  __typename\n}")
        return errorContains(resp, "Directive \\\"deprecated\\\" may not be used on \\\"QUERY\\\".")
    }

    private fun engineRuby(send: (String) -> String): Boolean {
        var resp = send("query @skip {\n __typename\n}")
        if (errorContains(resp, "'@skip' can't be applied to queries (allowed: fields, fragment spreads, inline fragments)")) {
            return true
        } else if (errorContains(resp, "Directive 'skip' is missing required arguments: if")) {
            return true
        }

        resp = send("query @deprecated {\n __typename\n}")
        if (errorContains(resp, "'@deprecated' can't be applied to queries")) return true

        resp = send("query {\n __typename {\n}")
        if (errorContains(resp, "Parse error on \\\"}\\\" (RCURLY)")) return true

        resp = send("query {\n  __typename @skip\n}")
        return errorContains(resp, "Directive 'skip' is missing required arguments: if")
    }

    private fun engineHypergraphql(send: (String) -> String): Boolean {
        var resp = send("zzz {\n __typename\n}")
        if (errorContains(resp, "Validation error of type InvalidSyntax: Invalid query syntax.")) return true

        resp = send("query {\n  alias1:__typename @deprecated\n}")
        return errorContains(resp, "Validation error of type UnknownDirective: Unknown directive deprecated @ '__typename'")
    }

    private fun engineGraphqlJava(send: (String) -> String): Boolean {
        var resp = send("queryy  {\n __typename\n}")
        if (errorContains(resp, "Invalid Syntax : offending token 'queryy'")) return true

        resp = send("query @aaa@aaa {\n __typename\n}")
        if (errorContains(resp, "Validation error of type DuplicateDirectiveName: Directives must be uniquely named within a location.")) {
            return true
        }

        resp = send("")
        return errorContains(resp, "Invalid Syntax : offending token '<EOF>'")
    }

    private fun engineAriadne(send: (String) -> String): Boolean {
        var resp = send("query {\n  __typename @abc\n}")
        if (errorContains(resp, "Unknown directive '@abc'.") && hasDataKey(resp)) return true

        resp = send("")
        return errorContains(resp, "The query must be a string.")
    }

    private fun engineWpGraphql(send: (String) -> String): Boolean {
        var resp = send("")
        if (errorContains(resp, "GraphQL Request must include at least one of those two parameters: \\\"query\\\" or \\\"queryId\\\"")) {
            return true
        }

        resp = send("query {\n alias1\$1:__typename\n}")
        if (!errorContains(resp, "Syntax Error: Expected Name, found \$")) return false

        val ext = parseOrNull(resp)?.get("extensions")?.jsonObject ?: return false
        val dbg = ext["debug"]?.jsonArray ?: return false
        if (dbg.isEmpty()) return false
        val debugMsg = dbg[0].jsonObject
        val dbgMsgType = debugMsg["type"]?.jsonPrimitive?.contentOrNull
        val dbgMsgMessage = debugMsg["message"]?.jsonPrimitive?.contentOrNull

        return dbgMsgType == "DEBUG_LOGS_INACTIVE" ||
            dbgMsgMessage == "GraphQL Debug logging is not active. To see debug logs, GRAPHQL_DEBUG must be enabled."
    }

    private fun engineGqlGen(send: (String) -> String): Boolean {
        var resp = send("query  {\n__typename {\n}")
        if (errorContains(resp, "expected at least one definition")) return true

        resp = send("query  {\nalias^_:__typename {\n}")
        return errorContains(resp, "Expected Name, found <Invalid>")
    }

    private fun engineGraphqlGo(send: (String) -> String): Boolean {
        var resp = send("query {\n__typename {\n}")
        if (errorContains(resp, "Unexpected empty IN")) return true

        resp = send("")
        if (errorContains(resp, "Must provide an operation.")) return true

        resp = send("query {\n  __typename\n}")
        return typename(resp) == "RootQuery"
    }

    private fun engineJuniper(send: (String) -> String): Boolean {
        var resp = send("queryy {\n  __typename\n}")
        if (errorContains(resp, "Unexpected \"queryy\"")) return true

        resp = send("")
        return errorContains(resp, "Unexpected end of input")
    }

    private fun engineSangria(send: (String) -> String): Boolean {
        val resp = send("queryy {\n  __typename\n}")
        val syntaxError = parseOrNull(resp)?.get("syntaxError")?.jsonPrimitive?.contentOrNull ?: ""
        val msg = "Syntax error while parsing GraphQL query. Invalid input \"queryy\", expected ExecutableDefinition or TypeSystemDefinition"
        return syntaxError.contains(msg)
    }

    private fun engineFlutter(send: (String) -> String): Boolean {
        val resp = send("query {\n  __typename @deprecated\n}")
        return errorContains(resp, "Directive \"deprecated\" may not be used on FIELD.")
    }

    private fun engineDianaJl(send: (String) -> String): Boolean {
        val resp = send("queryy { __typename }")
        return errorContains(resp, "Syntax Error GraphQL request (1:1) Unexpected Name \"queryy\"") ||
            errorContains(resp, "Syntax Error GraphQL request (1:1) Unexpected Name \\\"queryy\\\"")
    }

    private fun engineStrawberry(send: (String) -> String): Boolean {
        val resp = send("query @deprecated {\n  __typename\n}")
        return errorContains(resp, "Directive '@deprecated' may not be used on query.") && hasDataKey(resp)
    }

    private fun engineTartiflette(send: (String) -> String): Boolean {
        var resp = send("query @a { __typename }")
        if (errorContains(resp, "Unknow Directive < @a >.")) return true

        resp = send("query @skip { __typename }")
        if (errorContains(resp, "Missing mandatory argument < if > in directive < @skip >.")) return true

        resp = send("query { graphwoof }")
        if (errorContains(resp, "Field graphwoof doesn't exist on Query")) return true

        resp = send("query {\n  __typename @deprecated\n}")
        if (errorContains(resp, "Directive < @deprecated > is not used in a valid location.")) return true

        resp = send("queryy {\n  __typename\n}")
        return errorContains(resp, "syntax error, unexpected IDENTIFIER")
    }

    private fun engineTailcall(send: (String) -> String): Boolean {
        val resp = send("aa {\n  __typename\n}")
        return errorContains(resp, "expected executable_definition")
    }

    private fun engineDgraph(send: (String) -> String): Boolean {
        var resp = send("query {\n  __typename @cascade\n}")
        if (typename(resp) == "Query") return true

        resp = send("query {\n  __typename\n}")
        return errorContains(resp, "Not resolving __typename. There's no GraphQL schema in Dgraph. Use the /admin API to add a GraphQL schema")
    }

    private fun engineDirectus(send: (String) -> String): Boolean {
        val resp = send("")
        val errors = parseOrNull(resp)?.get("errors")?.jsonArray ?: return false
        if (errors.isEmpty()) return false
        val code = errors[0].jsonObject["extensions"]?.jsonObject?.get("code")?.jsonPrimitive?.contentOrNull
        return code == "INVALID_PAYLOAD"
    }

    private fun engineLighthouse(send: (String) -> String): Boolean {
        val resp = send("query {\n  __typename @include(if: falsee)\n}")
        return errorContains(resp, "Internal server error")
    }

    private fun engineAgoo(send: (String) -> String): Boolean {
        val resp = send("query {\n  zzz\n}")
        return errorContains(resp, "eval error")
    }

    private fun engineMercurius(send: (String) -> String): Boolean {
        val resp = send("")
        return errorContains(resp, "Unknown query") || errorContains(resp, "MER_ERR_GQL_VALIDATION")
    }

    private fun engineMorpheus(send: (String) -> String): Boolean {
        val resp = send("queryy {\n    __typename\n}")
        return errorContains(resp, "expecting white space") || errorContains(resp, "offset")
    }

    private fun engineLacinia(send: (String) -> String): Boolean {
        val resp = send("query {\n  inql\n}")
        return errorContains(resp, "Cannot query field `inql' on type `QueryRoot'.")
    }

    private fun engineCaliban(send: (String) -> String): Boolean {
        val resp = send(
            "query {\n    __typename\n}\n\nfragment woof on __Schema {\n    directives {\n        name\n    }\n}"
        )
        return errorContains(resp, "Fragment 'woof' is not used in any spread")
    }

    private fun engineAbsinthe(send: (String) -> String): Boolean {
        val resp = send("query {\n    inql\n}")
        return errorContains(resp, "Cannot query field \\\"inql\\\" on type \\\"RootQueryType\\\".")
    }

    private fun engineGraphqlDotNet(send: (String) -> String): Boolean {
        val resp = send("query @skip { __typename }")
        return errorContains(resp, "Directive 'skip' may not be used on Query.")
    }

    private fun enginePgGraphql(send: (String) -> String): Boolean {
        val resp = send("query { __typename @skip(aa:true) }")
        return errorContains(resp, "Unknown argument to @skip: aa")
    }

    private fun engineHotChocolate(send: (String) -> String): Boolean {
        var resp = send("queryy  {\n    __typename\n}")
        if (errorContains(resp, "Unexpected token: Name.")) return true

        resp = send("query @aaa@aaa {\n    __typename\n}")
        return errorContains(resp, "The specified directive `aaa` is not supported by the current schema.")
    }

    private fun engineInigo(send: (String) -> String): Boolean {
        val resp = send("query  {\n    __typename\n}")
        val extensions = parseOrNull(resp)?.get("extensions")?.jsonObject ?: return false
        return extensions.containsKey("inigo")
    }

    private fun engineBallerina(send: (String) -> String): Boolean {
        val resp = send(
            "query {\n    __typename\n    ...A\n}\n\nfragment A on Query {\n    ...B\n}\n\nfragment B on Query {\n    ...A\n}"
        )
        return errorContains(resp, "Cannot spread fragment \"A\" within itself via \"B\"")
    }
}
