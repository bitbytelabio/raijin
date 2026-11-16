package io.bitbytelab.raijin.graphql.scanners

import io.bitbytelab.raijin.graphql.GQLSchema
import org.junit.jupiter.api.Timeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CyclesScannerTest {

    private fun scan(sdl: String) = CyclesScanner(GQLSchema(sdl.trimIndent())).detect()

    @Test
    fun `detects a self-referencing type as a cycle`() {
        val schema = GQLSchema(
            """
            type Query { viewer: User }
            type User { id: ID!, friends: [User!] }
            """.trimIndent()
        )
        val cycles = CyclesScanner(schema).detect().cycles()
        assertTrue(cycles.isNotEmpty())
        assertTrue(cycles.any { cycle -> cycle.any { (_, type) -> type == "User" } })
    }

    @Test
    fun `an acyclic schema reports no cycles`() {
        val schema = GQLSchema(
            """
            type Query { viewer: User }
            type User { id: ID!, account: Account }
            type Account { balance: Int }
            """.trimIndent()
        )
        val scanner = CyclesScanner(schema).detect()
        assertEquals(0, scanner.cycles().size)
        assertEquals(emptyList(), scanner.cyclicTypes())
        assertFalse(scanner.truncated)
    }

    @Test
    fun `detects a longer mutual cycle between two types`() {
        val schema = GQLSchema(
            """
            type Query { viewer: User }
            type User { id: ID!, account: Account }
            type Account { owner: User }
            """.trimIndent()
        )
        val cycles = CyclesScanner(schema).detect().cycles()
        assertTrue(cycles.isNotEmpty())
    }

    @Test
    fun `a cycle reads as the path from a root field to the type that closes the loop`() {
        val scanner = scan(
            """
            type Query { viewer: User }
            type User { id: ID!, account: Account }
            type Account { owner: User }
            """
        )
        assertEquals(listOf("Query.viewer -> User.account -> Account.owner -> User"), scanner.cyclesAsStrings())
        assertEquals(listOf(listOf("viewer" to "User", "account" to "Account", "owner" to "User")), scanner.cycles())

        val cycle = scanner.found().single()
        assertEquals(listOf(CyclesScanner.Hop("Query", "viewer", "User")), cycle.entry)
        assertEquals(
            listOf(CyclesScanner.Hop("User", "account", "Account"), CyclesScanner.Hop("Account", "owner", "User")),
            cycle.loop,
        )
    }

    @Test
    fun `every cycle is reported, not only the first one under a root field`() {
        val scanner = scan(
            """
            type Query { viewer: User, post: Post }
            type User { id: ID!, friends: [User!], account: Account, posts: [Post] }
            type Account { owner: User }
            type Post { author: User, comments: [Comment] }
            type Comment { post: Post, replies: [Comment] }
            """
        )
        // Shortest first; each cycle once, from the type the walk from the roots met first.
        assertEquals(
            listOf(
                "Query.post -> Post.comments -> Comment.replies -> Comment",
                "Query.viewer -> User.friends -> User",
                "Query.post -> Post.comments -> Comment.post -> Post",
                "Query.viewer -> User.account -> Account.owner -> User",
                "Query.viewer -> User.posts -> Post.author -> User",
            ),
            scanner.cyclesAsStrings(),
        )
        assertEquals(listOf("Account", "Comment", "Post", "User"), scanner.cyclicTypes())
        assertFalse(scanner.truncated)
    }

    @Test
    fun `a cycle that only closes through an already explored type is reported too`() {
        // A -> B -> A is found first; A -> C -> B -> A reaches B again after B was fully explored,
        // which a search that marks types as visited never reports.
        val scanner = scan(
            """
            type Query { a: A }
            type A { b: B, c: C }
            type B { a: A }
            type C { b: B }
            """
        )
        assertEquals(
            listOf("Query.a -> A.b -> B.a -> A", "Query.a -> A.c -> C.b -> B.a -> A"),
            scanner.cyclesAsStrings(),
        )
        assertEquals(listOf("A", "B", "C"), scanner.cyclicTypes())
    }

    @Test
    fun `parallel fields between the same types are separate cycles`() {
        val scanner = scan(
            """
            type Query { viewer: User }
            type User { friends: [User], bestFriend: User }
            """
        )
        assertEquals(
            listOf("Query.viewer -> User.bestFriend -> User", "Query.viewer -> User.friends -> User"),
            scanner.cyclesAsStrings(),
        )
    }

    @Test
    fun `a cycle through an interface is found by way of its implementation`() {
        val scanner = scan(
            """
            type Query { node: Node }
            interface Node { id: ID! }
            type User implements Node { id: ID!, related: Node }
            type Leaf implements Node { id: ID! }
            """
        )
        assertEquals(listOf("Query.node -> Node ... on User -> User.related -> Node"), scanner.cyclesAsStrings())
        assertEquals(listOf("Node", "User"), scanner.cyclicTypes())
        assertEquals(
            listOf(listOf("node" to "Node", "... on User" to "User", "related" to "Node")),
            scanner.cycles(),
        )
    }

    @Test
    fun `a field of an interface that returns the interface is a cycle`() {
        val scanner = scan(
            """
            type Query { node: Node }
            interface Node { parent: Node }
            type Folder implements Node { parent: Node }
            """
        )
        assertEquals(
            listOf(
                "Query.node -> Node.parent -> Node",
                "Query.node -> Node ... on Folder -> Folder.parent -> Node",
            ),
            scanner.cyclesAsStrings(),
        )
    }

    @Test
    fun `a cycle through a union is found by way of its member`() {
        val scanner = scan(
            """
            type Query { search: SearchResult }
            union SearchResult = Person | Page
            type Person { name: String, favourite: SearchResult }
            type Page { title: String }
            """
        )
        assertEquals(
            listOf("Query.search -> SearchResult ... on Person -> Person.favourite -> SearchResult"),
            scanner.cyclesAsStrings(),
        )
    }

    @Test
    fun `a cycle through a root operation type starts at that type`() {
        val scanner = scan(
            """
            type Query { me: User }
            type User { query: Query }
            """
        )
        assertEquals(listOf("Query.me -> User.query -> Query"), scanner.cyclesAsStrings())
        assertEquals(emptyList(), scanner.found().single().entry)
    }

    @Test
    fun `cycles reachable only from the mutation root are found`() {
        val scanner = scan(
            """
            type Query { ping: String }
            type Mutation { createNode: Tree }
            type Tree { children: [Tree] }
            """
        )
        assertEquals(listOf("Mutation.createNode -> Tree.children -> Tree"), scanner.cyclesAsStrings())
    }

    /** [size] types, each with a field to every type including itself. */
    private fun fullyConnected(size: Int): GQLSchema {
        val names = (1..size).map { "T$it" }
        return GQLSchema(
            buildString {
                append("type Query { root: T1 }\n")
                for (name in names) append("type $name { ${names.joinToString(" ") { "to$it: $it" }} }\n")
            }
        )
    }

    @Test
    fun `all elementary cycles of a dense schema are listed once, shortest first`() {
        // 4 fully connected types: 4 self-loops + 6 pairs + 4 triples in 2 directions + 6 orderings of all four.
        val scanner = CyclesScanner(fullyConnected(4)).detect()
        val found = scanner.found()
        assertEquals(24, found.size)
        assertEquals(24, found.map { it.loop }.toSet().size)
        assertEquals(listOf(4, 6, 8, 6), (1..4).map { length -> found.count { it.loop.size == length } })
        assertEquals(found.map { it.loop.size }.sorted(), found.map { it.loop.size })
        assertTrue(found.all { cycle -> cycle.loop.map { it.owner }.toSet().size == cycle.loop.size }, "a cycle repeats no type")
        assertFalse(scanner.truncated)
    }

    @Test
    fun `the list stops at the cap, short cycles first, and cyclic types stay complete`() {
        val scanner = CyclesScanner(fullyConnected(4), maxCycles = 3).detect()
        assertEquals(3, scanner.found().size)
        assertTrue(scanner.truncated)
        assertTrue(scanner.found().all { it.loop.size <= 2 }, scanner.cyclesAsStrings().toString())
        assertEquals(listOf("T1", "T2", "T3", "T4"), scanner.cyclicTypes())
    }

    @Test
    fun `a cap equal to the number of cycles is not a truncation`() {
        val scanner = CyclesScanner(fullyConnected(4), maxCycles = 24).detect()
        assertEquals(24, scanner.found().size)
        assertFalse(scanner.truncated)
    }

    @Test
    fun `maxDepth bounds the length of the cycles looked for`() {
        val schema = GQLSchema(
            """
            type Query { viewer: User }
            type User { friends: [User], account: Account }
            type Account { owner: User }
            """.trimIndent()
        )
        val scanner = CyclesScanner(schema, maxDepth = 1).detect()
        assertEquals(listOf("Query.viewer -> User.friends -> User"), scanner.cyclesAsStrings())
        assertEquals(listOf("Account", "User"), scanner.cyclicTypes())
    }

    @Test
    @Timeout(30)
    fun `a schema with more cycles than can be listed still terminates`() {
        // 12 fully connected types have over a hundred million elementary cycles.
        val scanner = CyclesScanner(fullyConnected(12)).detect()
        assertEquals(CyclesScanner.DEFAULT_MAX_CYCLES, scanner.found().size)
        assertTrue(scanner.truncated)
        assertEquals(12, scanner.cyclicTypes().size)
        assertEquals(scanner.found().size, scanner.cyclesAsStrings().toSet().size)
    }
}
