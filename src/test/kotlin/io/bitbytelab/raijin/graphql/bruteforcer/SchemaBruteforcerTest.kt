package io.bitbytelab.raijin.graphql.bruteforcer

import io.bitbytelab.raijin.graphql.TargetUnreachableException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SchemaBruteforcerTest {

    private val probeField = RegexStore.PROBE_FIELD
    private val probeArg = RegexStore.PROBE_ARG

    /** Responses of the fake schema Query { viewer: User, label: String }, User { label: String, self: User, nested: Nested }. */
    private val viewerSchema = mapOf(
        "query { $probeField }" to err("Cannot query field \"$probeField\" on type \"Query\"."),
        "mutation { $probeField }" to err("Schema is not configured for mutations."),
        "subscription { $probeField }" to err("Schema is not configured for subscriptions."),

        "query { viewer label self nested zzz1 zzz2 $probeField }" to errs(
            "Cannot query field \"self\" on type \"Query\".",
            "Cannot query field \"nested\" on type \"Query\".",
            "Cannot query field \"zzz1\" on type \"Query\".",
            "Cannot query field \"zzz2\" on type \"Query\".",
            "Cannot query field \"$probeField\" on type \"Query\".",
        ),
        "query { viewer { viewer label self nested zzz1 zzz2 $probeField } }" to errs(
            "Cannot query field \"viewer\" on type \"User\".",
            "Cannot query field \"zzz1\" on type \"User\".",
            "Cannot query field \"zzz2\" on type \"User\".",
            "Cannot query field \"$probeField\" on type \"User\".",
        ),

        "query { label { $probeField } }" to
            err("Field \"label\" must not have a selection since type \"String\" has no subfields."),
        "query { label($probeArg: null) { __typename } }" to
            err("Field \"label\" must not have a selection since type \"String\" has no subfields."),

        "query { viewer { $probeField } }" to err("Cannot query field \"$probeField\" on type \"User\"."),
        "query { viewer($probeArg: null) { __typename } }" to err("Unknown argument \"$probeArg\" on field \"viewer\"."),

        "query { viewer { label { $probeField } } }" to
            err("Field \"label\" must not have a selection since type \"String\" has no subfields."),
        "query { viewer { label($probeArg: null) { __typename } } }" to
            err("Field \"label\" must not have a selection since type \"String\" has no subfields."),

        "query { viewer { nested { $probeField } } }" to err("Cannot query field \"$probeField\" on type \"Nested\"."),
        "query { viewer { nested($probeArg: null) { __typename } } }" to
            err("Unknown argument \"$probeArg\" on field \"nested\"."),

        "query { viewer { self { $probeField } } }" to err("Cannot query field \"$probeField\" on type \"User\"."),
        "query { viewer { self($probeArg: null) { __typename } } }" to err("Unknown argument \"$probeArg\" on field \"self\"."),
    )

    private val viewerWordlist = listOf("viewer", "label", "self", "nested", "zzz1", "zzz2")

    private fun viewerBruteforcer(maxRequests: Int = SchemaBruteforcer.DEFAULT_MAX_REQUESTS, send: (String) -> String) =
        SchemaBruteforcer(
            sendQuery = send,
            bucketSize = 10,
            depthLimit = 1,
            bruteforceArguments = true,
            wordlist = viewerWordlist,
            argumentWordlist = emptyList(),
            maxRequests = maxRequests,
        )

    @Test
    fun `discovers fields, classifies scalar vs object, dedupes a self-cycle, and respects depth_limit`() {
        // "Nested" sits one level past depth_limit=1, so it must be referenced as a type_hint but never scanned.
        val sent = mutableListOf<String>()
        val result = viewerBruteforcer { q -> sent += q; viewerSchema[q] ?: "{}" }.run()
        val byName = result.types.associateBy { it.name }

        assertEquals(setOf("Query", "User"), byName.keys)

        val query = byName["Query"]!!
        assertEquals("object", query.kind)
        assertEquals(
            setOf("label" to "String", "viewer" to "User"),
            query.fields.map { it.name to it.typeHint }.toSet(),
        )

        val user = byName["User"]!!
        assertEquals("object", user.kind)
        assertEquals(
            setOf("label" to "String", "self" to "User", "nested" to "Nested"),
            user.fields.map { it.name to it.typeHint }.toSet(),
        )

        // "Nested" is referenced as a type_hint but, sitting past depth_limit, was never itself scanned.
        assertTrue("Nested" !in byName)

        assertNull(result.stopped)
        assertEquals(sent.size, result.requestsSent)
        // Every request of this run is one the fake schema answers: nothing else was guessed at.
        assertEquals(emptyList(), sent.filter { it !in viewerSchema })
    }

    @Test
    fun `discovers a required argument from the errors of the field's own probe`() {
        // The typename probe selects a fake subfield and passes no arguments, so the server names
        // both the type and the argument it is missing. No second, executable request is needed.
        val responses = mapOf(
            "query { $probeField }" to err("Cannot query field \"$probeField\" on type \"Query\"."),
            "mutation { $probeField }" to err("Schema is not configured for mutations."),
            "subscription { $probeField }" to err("Schema is not configured for subscriptions."),

            "query { widget zzz1 zzz2 $probeField }" to errs(
                "Cannot query field \"zzz1\" on type \"Query\".",
                "Cannot query field \"zzz2\" on type \"Query\".",
                "Cannot query field \"$probeField\" on type \"Query\".",
            ),
            "query { widget { $probeField } }" to errs(
                "Cannot query field \"$probeField\" on type \"Widget\".",
                "Field \"widget\" argument \"id\" of type \"ID!\" is required, but it was not provided.",
            ),
            "query { widget($probeArg: null) { __typename } }" to
                err("Unknown argument \"$probeArg\" on field \"widget\"."),
        )

        val bruteforcer = SchemaBruteforcer(
            sendQuery = { q -> responses[q] ?: error("unexpected request: $q") },
            bucketSize = 10,
            depthLimit = 0,
            bruteforceArguments = true,
            wordlist = listOf("widget", "zzz1", "zzz2"),
            argumentWordlist = listOf("limit", "offset"),
        )

        val result = bruteforcer.run()
        val query = result.types.single { it.name == "Query" }
        val widget = query.fields.single { it.name == "widget" }

        assertEquals("Widget", widget.typeHint)
        assertEquals(listOf("id"), widget.args)
        assertTrue(result.types.none { it.name == "Widget" }) // past depth_limit=0, never scanned
        // The argument wordlist is only sent for fields whose arguments the cheap probes could not name.
        assertEquals(responses.size, result.requestsSent)
    }

    @Test
    fun `an endpoint that never leaks a recognizable error yields an empty reconstruction`() {
        // Every probe gets back an error that none of the Clairvoyance regexes recognize — so
        // nothing is confirmed valid or invalid, and no field survives the elimination logic.
        val bruteforcer = SchemaBruteforcer(
            sendQuery = { err("Internal Server Error") },
            bucketSize = 10,
            depthLimit = 2,
            wordlist = listOf("a", "b"),
            argumentWordlist = emptyList(),
        )
        val result = bruteforcer.run()
        // Root type name defaults to "Query" when even that can't be determined.
        assertEquals(listOf("Query"), result.types.map { it.name })
        assertEquals("object", result.types.single().kind)
        assertTrue(result.types.single().fields.isEmpty())
        assertNull(result.types.single().fields.firstOrNull())
    }

    @Test
    fun `a body that is not a GraphQL error reply confirms no field`() {
        // An HTML error page or an empty body has no errors to read. Taking "no errors" for "all
        // valid" would turn the whole wordlist into fields of a schema that does not exist.
        for (body in listOf("", "<html>502 Bad Gateway</html>", "{}", "[]", "null", """{"data":{"a":1,"b":2}}""")) {
            val result = SchemaBruteforcer(
                sendQuery = { body },
                bucketSize = 2,
                wordlist = listOf("a", "b", "c"),
                argumentWordlist = listOf("x"),
            ).run()
            assertEquals(listOf("Query"), result.types.map { it.name }, "body '$body'")
            assertTrue(result.types.single().fields.isEmpty(), "body '$body'")
            assertEquals(3 + 2, result.requestsSent, "three root probes and two field buckets for body '$body'")
        }
    }

    @Test
    fun `a bucket of real fields only is confirmed by the fake field being the one rejected`() {
        val responses = mapOf(
            "query { $probeField }" to err("Cannot query field \"$probeField\" on type \"Query\"."),
            "mutation { $probeField }" to err("Schema is not configured for mutations."),
            "subscription { $probeField }" to err("Schema is not configured for subscriptions."),
            "query { version uptime $probeField }" to err("Cannot query field \"$probeField\" on type \"Query\"."),
            "query { version { $probeField } }" to
                err("Field \"version\" must not have a selection since type \"String\" has no subfields."),
            "query { uptime { $probeField } }" to
                err("Field \"uptime\" must not have a selection since type \"Int\" has no subfields."),
        )
        val result = SchemaBruteforcer(
            sendQuery = { q -> responses[q] ?: err("Validation failed.") },
            bucketSize = 10,
            depthLimit = 0,
            wordlist = listOf("version", "uptime"),
            argumentWordlist = emptyList(),
        ).run()

        assertEquals(
            listOf("uptime" to "Int", "version" to "String"),
            result.types.single().fields.map { it.name to it.typeHint },
        )
    }

    /**
     * A server for Query { items(first, after): Item } and Mutation { logout: Session, ping: Boolean }
     * that validates documents the way graphql-js words it, and records every document that passes
     * validation, i.e. that a real server would execute. With [firstErrorOnly] it reports just the
     * first unknown argument of a request, like servers that stop at their first error.
     */
    private class ArgumentServer(private val firstErrorOnly: Boolean = false) {
        val sent = mutableListOf<String>()
        val executed = mutableListOf<String>()

        private val rootTypes = mapOf("query" to "Query", "mutation" to "Mutation")
        private val fields = mapOf(
            "query" to mapOf("items" to "Item"),
            "mutation" to mapOf("logout" to "Session", "ping" to "Boolean"),
        )
        private val scalars = setOf("Boolean")
        private val arguments = mapOf("items" to setOf("first", "after"), "logout" to emptySet(), "ping" to emptySet())

        private val withArguments = Regex("""^(query|mutation) \{ (\w+)\((.*)\) \{ __typename \} \}$""")
        private val withSelection = Regex("""^(query|mutation) \{ (\w+) \{ (\w+) \} \}$""")
        private val bucket = Regex("""^(query|mutation) \{ ([\w ]+) \}$""")

        fun answer(query: String): String {
            sent += query
            if (query.startsWith("subscription")) return err("Schema is not configured for subscriptions.")

            withArguments.matchEntire(query)?.let { m ->
                val (operation, field, passed) = m.destructured
                val unknown = passed.split(", ").map { it.substringBefore(":") }.filter { it !in arguments.getValue(field) }
                val reported = if (firstErrorOnly) unknown.take(1) else unknown
                if (reported.isEmpty()) return execute(query)
                return errs(*reported.map { "Unknown argument \"$it\" on field \"${rootTypes.getValue(operation)}.$field\"." }.toTypedArray())
            }
            withSelection.matchEntire(query)?.let { m ->
                val (operation, field, selection) = m.destructured
                val type = fields.getValue(operation).getValue(field)
                return when {
                    type in scalars -> err("Field \"$field\" must not have a selection since type \"$type\" has no subfields.")
                    selection == "__typename" -> execute(query)
                    else -> err("Cannot query field \"$selection\" on type \"$type\".")
                }
            }
            bucket.matchEntire(query)?.let { m ->
                val (operation, names) = m.destructured
                val known = fields.getValue(operation)
                val messages = names.split(" ").mapNotNull { name ->
                    when (val type = known[name]) {
                        null -> "Cannot query field \"$name\" on type \"${rootTypes.getValue(operation)}\"."
                        in scalars -> null
                        else -> "Field \"$name\" of type \"$type\" must have a selection of subfields. Did you mean \"$name { ... }\"?"
                    }
                }
                return if (messages.isEmpty()) execute(query) else errs(*messages.toTypedArray())
            }
            error("unexpected request: $query")
        }

        private fun execute(query: String): String {
            executed += query
            return """{"data":{}}"""
        }

        /** The wordlist buckets: argument probes that carry more than the fake argument. */
        val bucketRequests: List<String> get() = sent.filter { withArguments.matches(it) && "," in it }
    }

    private val argumentWords = listOf("id", "first", "limit", "after", "name", "x1", "x2", "x3")

    private fun argumentBruteforcer(server: ArgumentServer, wordlist: List<String>, bucketSize: Int = 4) = SchemaBruteforcer(
        sendQuery = server::answer,
        bucketSize = bucketSize,
        depthLimit = 0,
        wordlist = wordlist,
        argumentWordlist = argumentWords,
    )

    @Test
    fun `argument names are tested a bucket per request`() {
        val server = ArgumentServer()
        val result = argumentBruteforcer(server, listOf("items", "zzz")).run()

        val items = result.types.single { it.name == "Query" }.fields.single { it.name == "items" }
        assertEquals("Item", items.typeHint)
        assertEquals(listOf("first", "after"), items.args)
        // Eight candidates in buckets of four: two requests, where one per candidate used to be sent.
        assertEquals(
            listOf(
                "query { items(id: null, first: null, limit: null, after: null, $probeArg: null) { __typename } }",
                "query { items(name: null, x1: null, x2: null, x3: null, $probeArg: null) { __typename } }",
            ),
            server.bucketRequests,
        )
    }

    @Test
    fun `a server that reports one unknown argument at a time still gets no false positives`() {
        val server = ArgumentServer(firstErrorOnly = true)
        val result = argumentBruteforcer(server, listOf("items", "zzz")).run()

        val items = result.types.single { it.name == "Query" }.fields.single { it.name == "items" }
        assertEquals(listOf("first", "after"), items.args)
        // Each reply rejects one name, so a bucket shrinks until the fake argument is the one reported:
        // three requests for the bucket holding the two real arguments, four for the one holding none.
        assertEquals(3 + 4, server.bucketRequests.size)
    }

    @Test
    fun `no document of a run can execute, whatever the bucket size`() {
        // With one name per bucket, `mutation { ping }` and `mutation { logout { __typename } }` would be
        // valid documents: a server would run the mutations just to tell the brute force they exist.
        for (bucketSize in listOf(1, 2, 64)) {
            val server = ArgumentServer()
            val result = argumentBruteforcer(server, listOf("items", "logout", "ping", "zzz"), bucketSize).run()

            assertEquals(emptyList(), server.executed, "bucket size $bucketSize")
            assertTrue(server.sent.all { probeField in it || probeArg in it }, "bucket size $bucketSize: ${server.sent}")

            val mutation = result.types.single { it.name == "Mutation" }
            assertEquals(
                listOf("logout" to "Session", "ping" to "Boolean"),
                mutation.fields.map { it.name to it.typeHint },
                "bucket size $bucketSize",
            )
            assertTrue(mutation.fields.all { it.args.isEmpty() }, "bucket size $bucketSize")
            assertEquals(listOf("first", "after"), result.types.single { it.name == "Query" }.fields.single().args, "bucket size $bucketSize")
        }
    }

    @Test
    fun `suggestions on the fake argument name every argument without a brute force`() {
        // graphql-js 15+ names the field as "Type.field" and lists several suggestions.
        val responses = mapOf(
            "query { $probeField }" to err("Cannot query field \"$probeField\" on type \"Query\"."),
            "mutation { $probeField }" to err("Schema is not configured for mutations."),
            "subscription { $probeField }" to err("Schema is not configured for subscriptions."),
            "query { user zzz $probeField }" to errs(
                "Cannot query field \"zzz\" on type \"Query\".",
                "Cannot query field \"$probeField\" on type \"Query\".",
            ),
            "query { user { $probeField } }" to err("Cannot query field \"$probeField\" on type \"User\"."),
            "query { user($probeArg: null) { __typename } }" to
                err("Unknown argument \"$probeArg\" on field \"Query.user\". Did you mean \"id\", \"email\", or \"name\"?"),
        )
        val sent = mutableListOf<String>()
        val result = SchemaBruteforcer(
            sendQuery = { q -> sent += q; responses[q] ?: error("unexpected request: $q") },
            bucketSize = 4,
            depthLimit = 0,
            wordlist = listOf("user", "zzz"),
            argumentWordlist = argumentWords,
        ).run()

        assertEquals(listOf("id", "email", "name"), result.types.single().fields.single().args)
        assertEquals(responses.keys.toList(), sent)
    }

    @Test
    fun `type names suggested for an inline fragment are not taken for fields`() {
        // On an interface, graphql-js answers a field that only some implementations have with
        // "Did you mean to use an inline fragment on ...": those are types, not fields of the interface.
        val responses = mapOf(
            "query { $probeField }" to err("Cannot query field \"$probeField\" on type \"Query\"."),
            "mutation { $probeField }" to err("Schema is not configured for mutations."),
            "subscription { $probeField }" to err("Schema is not configured for subscriptions."),
            "query { hero name $probeField }" to errs(
                "Cannot query field \"name\" on type \"Query\".",
                "Cannot query field \"$probeField\" on type \"Query\".",
            ),
            "query { hero { $probeField } }" to err("Cannot query field \"$probeField\" on type \"Character\"."),
            "query { hero($probeArg: null) { __typename } }" to err("Unknown argument \"$probeArg\" on field \"Query.hero\"."),
            "query { hero { hero name $probeField } }" to errs(
                "Cannot query field \"hero\" on type \"Character\".",
                "Cannot query field \"name\" on type \"Character\". Did you mean to use an inline fragment on \"Human\" or \"Droid\"?",
                "Cannot query field \"$probeField\" on type \"Character\".",
            ),
        )
        val result = SchemaBruteforcer(
            sendQuery = { q -> responses[q] ?: error("unexpected request: $q") },
            bucketSize = 4,
            depthLimit = 1,
            wordlist = listOf("hero", "name"),
            argumentWordlist = emptyList(),
        ).run()

        val byName = result.types.associateBy { it.name }
        assertEquals(listOf("hero" to "Character"), byName.getValue("Query").fields.map { it.name to it.typeHint })
        assertEquals(emptyList(), byName.getValue("Character").fields)
    }

    @Test
    fun `a server that names no unknown argument is not brute-forced`() {
        // Without that error every candidate would look accepted; the wordlist is not sent at all.
        val responses = mapOf(
            "query { $probeField }" to err("Cannot query field \"$probeField\" on type \"Query\"."),
            "mutation { $probeField }" to err("Schema is not configured for mutations."),
            "subscription { $probeField }" to err("Schema is not configured for subscriptions."),
            "query { user zzz $probeField }" to err("Cannot query field \"zzz\" on type \"Query\"."),
            "query { user { $probeField } }" to err("Cannot query field \"$probeField\" on type \"User\"."),
            "query { user($probeArg: null) { __typename } }" to err("Validation failed."),
        )
        val result = SchemaBruteforcer(
            sendQuery = { q -> responses[q] ?: error("unexpected request: $q") },
            bucketSize = 4,
            depthLimit = 0,
            wordlist = listOf("user", "zzz"),
            argumentWordlist = argumentWords,
        ).run()

        assertEquals(emptyList(), result.types.single().fields.single().args)
        assertEquals(responses.size, result.requestsSent)
    }

    @Test
    fun `argument brute force can be switched off`() {
        val server = ArgumentServer()
        val result = SchemaBruteforcer(
            sendQuery = server::answer,
            bucketSize = 4,
            depthLimit = 0,
            bruteforceArguments = false,
            wordlist = listOf("items", "zzz"),
            argumentWordlist = argumentWords,
        ).run()

        assertEquals(emptyList(), result.types.single { it.name == "Query" }.fields.single().args)
        assertEquals(emptyList(), server.bucketRequests)
    }

    @Test
    fun `a scalar is recognised when the server wraps the error text`() {
        // The message has a prefix and a suffix around the text the pattern describes.
        val wrapped = "Validation error: Field \"blob\" must not have a selection since type \"Blob\" has no subfields. (line 1)"
        val responses = mapOf(
            "query { $probeField }" to err("Cannot query field \"$probeField\" on type \"Query\"."),
            "mutation { $probeField }" to err("Schema is not configured for mutations."),
            "subscription { $probeField }" to err("Schema is not configured for subscriptions."),
            "query { blob zzz $probeField }" to err("Cannot query field \"zzz\" on type \"Query\"."),
            "query { blob { $probeField } }" to err(wrapped),
            "query { blob($probeArg: null) { __typename } }" to err(wrapped),
            "query { blob { blob zzz $probeField } }" to err(wrapped),
        )
        val result = SchemaBruteforcer(
            sendQuery = { q -> responses[q] ?: error("unexpected request: $q") },
            bucketSize = 4,
            depthLimit = 1,
            wordlist = listOf("blob", "zzz"),
            argumentWordlist = emptyList(),
        ).run()

        val byName = result.types.associateBy { it.name }
        assertEquals("Blob", byName.getValue("Query").fields.single().typeHint)
        assertEquals("scalar", byName.getValue("Blob").kind)
    }

    @Test
    fun `the run stops at its request budget and keeps what it found`() {
        var calls = 0
        val result = viewerBruteforcer(maxRequests = 6) { q -> calls++; viewerSchema[q] ?: "{}" }.run()

        assertEquals(SchemaBruteforcer.StopReason.REQUEST_BUDGET, result.stopped)
        assertEquals(6, result.requestsSent)
        assertEquals(6, calls)
        // Three root probes, the field bucket, then "label" was worked out before the budget ran out on "viewer".
        val query = result.types.single()
        assertEquals("Query", query.name)
        assertEquals(listOf("label" to "String"), query.fields.map { it.name to it.typeHint })
    }

    @Test
    fun `a budget just large enough for the whole run does not stop it`() {
        val unlimited = viewerBruteforcer { q -> viewerSchema[q] ?: "{}" }.run()
        val exact = viewerBruteforcer(maxRequests = unlimited.requestsSent) { q -> viewerSchema[q] ?: "{}" }.run()

        assertNull(exact.stopped)
        assertEquals(unlimited.requestsSent, exact.requestsSent)
        assertEquals(unlimited.types, exact.types)
    }

    @Test
    fun `an unreachable target stops the run at once`() {
        var calls = 0
        val result = viewerBruteforcer { q ->
            calls++
            if (calls >= 5) throw TargetUnreachableException("no response")
            viewerSchema[q] ?: "{}"
        }.run()

        assertEquals(SchemaBruteforcer.StopReason.UNREACHABLE, result.stopped)
        assertEquals(5, calls)
        assertEquals(5, result.requestsSent)
    }

    @Test
    fun `an unreachable target on the first request yields nothing`() {
        val result = viewerBruteforcer { throw TargetUnreachableException("no response") }.run()

        assertEquals(SchemaBruteforcer.StopReason.UNREACHABLE, result.stopped)
        assertTrue(result.types.isEmpty())
        assertEquals(1, result.requestsSent)
    }

    @Test
    fun `a bucket size or budget below one is rejected`() {
        assertFailsWith<IllegalArgumentException> { SchemaBruteforcer(sendQuery = { "{}" }, bucketSize = 0) }
        assertFailsWith<IllegalArgumentException> { SchemaBruteforcer(sendQuery = { "{}" }, maxRequests = 0) }
    }

    @Test
    fun `typesAsJson lists each type with its fields, type hints and arguments`() {
        val result = argumentBruteforcer(ArgumentServer(), listOf("items", "zzz")).run()
        assertEquals(
            """{"Query":{"kind":"object","fields":[{"name":"items","type_hint":"Item","args":["first","after"]}]},""" +
                """"Mutation":{"kind":"object","fields":[]}}""",
            result.typesAsJson().toString(),
        )
    }

    companion object {
        /** JSON-escapes [message] (its embedded quotes are plain `"`) so it's safe as a JSON string value. */
        private fun jsonEscape(message: String): String = message.replace("\\", "\\\\").replace("\"", "\\\"")

        private fun err(message: String) = """{"errors":[{"message":"${jsonEscape(message)}"}]}"""
        private fun errs(vararg messages: String) =
            """{"errors":[${messages.joinToString(",") { """{"message":"${jsonEscape(it)}"}""" }}]}"""
    }
}
