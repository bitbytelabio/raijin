package io.bitbytelab.raijin.graphql.bruteforcer

import kotlin.test.Test
import kotlin.test.assertEquals

class RegexStoreTest {

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
    fun `MISSING_ARGUMENT extracts the field and required argument name`() {
        val message = "Field \"widget\" argument \"id\" of type \"ID!\" is required, but it was not provided."
        val match = RegexStore.MISSING_ARGUMENT.find(message)
        assertEquals("widget", match?.groups?.get("field")?.value)
        assertEquals("id", match?.groups?.get("argument")?.value)
    }
}
