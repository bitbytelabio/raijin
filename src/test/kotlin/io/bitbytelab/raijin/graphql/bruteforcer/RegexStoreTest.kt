package io.bitbytelab.raijin.graphql.bruteforcer

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RegexStoreTest {

    private fun fieldSuggestions(message: String) = RegexStore.getSuggestions(message, RegexStore.FIELD_SUGGESTIONS)

    @Test
    fun `WRONG_TYPENAME extracts the invalid field and its container type`() {
        val message = "Cannot query field \"zzz1\" on type \"Query\"."
        val match = RegexStore.WRONG_TYPENAME.firstNotNullOf { it.find(message) }
        assertEquals("zzz1", match.groups["field"]?.value)
        assertEquals("Query", match.groups["typename"]?.value)
    }

    @Test
    fun `FIELD_SUGGESTIONS extracts a did-you-mean suggestion`() {
        val message = "Cannot query field \"vewer\" on type \"Query\". Did you mean \"viewer\"?"
        val suggestions = RegexStore.getSuggestions(message, RegexStore.FIELD_SUGGESTIONS)
        assertEquals(listOf("viewer"), suggestions)
    }

    @Test
    fun `both names of a two-suggestion message are extracted`() {
        // graphql-js writes two suggestions as `"a" or "b"?`; the second one is only ever captured as suggestion3.
        assertEquals(
            listOf("users", "user"),
            fieldSuggestions("Cannot query field \"usr\" on type \"Query\". Did you mean \"users\" or \"user\"?"),
        )
        assertEquals(
            listOf("users", "user"),
            fieldSuggestions("Cannot query field 'usr' on type 'Query'. Did you mean 'users' or 'user'?"),
        )
    }

    @Test
    fun `the name after 'or' is extracted from lists of three to five suggestions`() {
        assertEquals(
            listOf("user", "users", "usersByName"),
            fieldSuggestions("Cannot query field \"usr\" on type \"Query\". Did you mean \"user\", \"users\", or \"usersByName\"?"),
        )
        assertEquals(
            listOf("a1", "b2", "c3", "d4"),
            fieldSuggestions("Cannot query field \"x\" on type \"Query\". Did you mean \"a1\", \"b2\", \"c3\", or \"d4\"?"),
        )
        // Five is the most graphql-js lists.
        assertEquals(
            listOf("a1", "b2", "c3", "d4", "e5"),
            fieldSuggestions("Cannot query field \"x\" on type \"Query\". Did you mean \"a1\", \"b2\", \"c3\", \"d4\", or \"e5\"?"),
        )
    }

    @Test
    fun `unquoted suggestions and fragment suggestions are extracted`() {
        assertEquals(listOf("users", "user"), fieldSuggestions("Cannot query field usr on type Query. Did you mean users or user?"))
        assertEquals(
            listOf("Human", "Droid"),
            fieldSuggestions("Cannot query field \"nam\" on type \"Character\". Did you mean to use an inline fragment on \"Human\" or \"Droid\"?"),
        )
    }

    @Test
    fun `a message without a suggestion list yields nothing`() {
        assertEquals(emptyList(), fieldSuggestions("Cannot query field \"zzz\" on type \"Query\"."))
        // The hint to add a selection set names no other field.
        assertEquals(
            emptyList(),
            fieldSuggestions("Field \"viewer\" of type \"User\" must have a selection of subfields. Did you mean \"viewer { ... }\"?"),
        )
    }

    @Test
    fun `MISSING_ARGUMENT extracts the field and required argument name`() {
        val message = "Field \"widget\" argument \"id\" of type \"ID!\" is required, but it was not provided."
        val match = RegexStore.MISSING_ARGUMENT.find(message)
        assertEquals("widget", match?.groups?.get("field")?.value)
        assertEquals("id", match?.groups?.get("argument")?.value)
    }

    @Test
    fun `UNKNOWN_ARGUMENT names the argument in either graphql-js wording`() {
        fun unknown(message: String) = RegexStore.UNKNOWN_ARGUMENT.firstNotNullOfOrNull { it.find(message) }?.groups?.get("argument")?.value
        assertEquals("foo", unknown("Unknown argument \"foo\" on field \"Query.user\"."))
        assertEquals("foo", unknown("Unknown argument \"foo\" on field \"user\" of type \"Query\"."))
        assertEquals("foo", unknown("Field 'user' doesn't accept argument 'foo'"))
    }

    @Test
    fun `NO_SUBFIELDS is found inside a longer message but does not match it whole`() {
        val bare = "Field \"label\" must not have a selection since type \"String\" has no subfields."
        val wrapped = "Validation error: $bare (line 1)"
        assertTrue(RegexStore.NO_SUBFIELDS.matches(bare))
        assertFalse(RegexStore.NO_SUBFIELDS.matches(wrapped))
        assertEquals("String", RegexStore.NO_SUBFIELDS.find(wrapped)?.groups?.get("type")?.value)
    }
}
