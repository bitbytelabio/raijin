package io.bitbytelab.raijin.graphql

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class GQLQueryPrinterTest {

    private fun print(sdl: String, field: String): String {
        val schema = GQLSchema(sdl.trimIndent())
        return GQLQueryPrinter(schema.queries.getValue(field), GQLSchema.OperationType.QUERY).printSDL()
    }

    @Test
    fun `an enum description ending in a newline is printed instead of throwing`() {
        // The description's last line is empty, which used to make `description.last().last()` throw
        // NoSuchElementException. `\n` is the GraphQL string escape: this is a raw Kotlin string.
        val text = print(
            """
            "Roles a user can hold\n"
            enum Role {
                ADMIN
                USER
            }
            type Query {
                role: Role
            }
            """,
            "role",
        )
        val lines = text.lines()
        assertEquals("query role {", lines.first())
        assertTrue("  # (enum) Roles a user can hold" in lines, text)
        assertTrue(lines.any { it.startsWith("  #  - ADMIN") }, text)
        assertTrue(lines.any { it.startsWith("  #  - USER") }, text)
        assertTrue("  role" in lines, text)
    }

    @Test
    fun `an enum description of only a newline still lists the enum values`() {
        val text = print(
            """
            "\n"
            enum Role {
                ADMIN
            }
            type Query {
                role: Role
            }
            """,
            "role",
        )
        assertTrue(text.lines().any { it.trim() == "# (enum):" }, text)
        assertTrue(text.lines().any { it.startsWith("  #  - ADMIN") }, text)
    }

    @Test
    fun `a field description ending in a newline is printed with its argument descriptions`() {
        // Same empty last line, on the path that appends the argument descriptions.
        val text = print(
            """
            type Query {
                "Looks a user up\n"
                user(
                    "The user id"
                    id: ID!
                ): String
            }
            """,
            "user",
        )
        val lines = text.lines()
        assertTrue("  # Looks a user up" in lines, text)
        assertTrue("  #  - id: The user id" in lines, text)
        assertTrue("  user(id: ID!)" in lines, text)
    }

    @Test
    fun `a description without a trailing newline gets a colon before the enum values`() {
        val text = print(
            """
            "Roles a user can hold"
            enum Role {
                ADMIN
            }
            type Query {
                role: Role
            }
            """,
            "role",
        )
        assertTrue("  # (enum) Roles a user can hold:" in text.lines(), text)
    }
}
