package io.bitbytelab.raijin.graphql.scanners

import graphql.schema.GraphQLFieldsContainer
import graphql.schema.GraphQLInterfaceType
import graphql.schema.GraphQLNamedType
import graphql.schema.GraphQLObjectType
import graphql.schema.GraphQLType
import graphql.schema.GraphQLTypeReference
import graphql.schema.GraphQLTypeUtil
import graphql.schema.GraphQLUnionType
import io.bitbytelab.raijin.graphql.GQLSchema

/**
 * Finds the cycles of a schema's type graph — types that can recurse into themselves, a
 * DoS/deeply-nested-query risk. Started as a port of InQL's `CyclesScanner`, whose depth-first
 * search returned at the first cycle it met under each root field and looked at object types only.
 *
 * Here the graph is every composite type reachable from the query/mutation/subscription roots: a
 * field is an edge to its (unwrapped) type, and an interface or union has an edge to each type an
 * `... on Type` fragment can select. [detect] then lists every elementary cycle (one that repeats
 * no type), each exactly once, shortest first. A densely connected schema has more cycles than
 * anyone can read, so the list stops at [maxCycles] ([truncated] says so); [cyclicTypes] is always
 * complete.
 *
 * @param maxDepth longest cycle, in hops, that is looked for.
 */
class CyclesScanner(
    private val schema: GQLSchema,
    private val maxDepth: Int = 100,
    private val maxCycles: Int = DEFAULT_MAX_CYCLES,
) {
    /**
     * One step of a path: selecting [field] on type [owner] lands on type [target]. With [fragment]
     * set the step is an `... on Target` spread on an abstract [owner], and [field] is the target's name.
     */
    data class Hop(val owner: String, val field: String, val target: String, val fragment: Boolean = false) {
        override fun toString(): String = if (fragment) "$owner ... on $target" else "$owner.$field"
    }

    /** [loop] starts and ends on one type; [entry] is the shortest way to that type from a root operation type. */
    data class Cycle(val entry: List<Hop>, val loop: List<Hop>) {
        /** `Query.viewer -> User.friends -> User`: every hop as `Type.field`, then the type that closes the loop. */
        override fun toString(): String = (entry + loop).joinToString(" -> ") + " -> " + loop.last().target
    }

    companion object {
        const val DEFAULT_MAX_CYCLES = 500

        /** Edge visits spent on the search before it gives up on listing more cycles. */
        private const val MAX_STEPS = 2_000_000
    }

    private class Edge(val label: String, val fragment: Boolean, val to: Int)

    /**
     * Composite types in discovery order from the roots: their names, outgoing edges, and for each
     * the hop that first reached it together with the type that hop starts from (null / -1 for a root).
     */
    private class Graph(
        val names: List<String>,
        val edges: List<List<Edge>>,
        val reachedBy: List<Hop?>,
        val reachedFrom: List<Int>,
    )

    private var detected: List<Cycle> = emptyList()
    private var cyclic: List<String> = emptyList()

    /** True when [detect] stopped at [maxCycles] (or ran out of search budget) with cycles left unlisted. */
    var truncated: Boolean = false
        private set

    /** Runs the scan; read [found], [cyclicTypes] and [truncated] afterward. */
    fun detect(): CyclesScanner {
        val graph = buildGraph()
        val size = graph.names.size
        val component = stronglyConnectedComponents(graph.edges)
        val componentSize = IntArray(size)
        for (node in 0 until size) componentSize[component[node]]++
        val onCycle = BooleanArray(size) { node ->
            componentSize[component[node]] > 1 || graph.edges[node].any { it.to == node }
        }
        val cyclicNodes = (0 until size).filter { onCycle[it] }
        cyclic = cyclicNodes.map { graph.names[it] }.sorted()

        // No cycle is longer than the largest group of mutually reachable types.
        val longest = minOf(maxDepth, cyclicNodes.maxOfOrNull { componentSize[component[it]] } ?: 0)
        val search = Search(graph, component)
        var listedUpTo = 0
        for (limit in lengthLimits(longest)) {
            for (start in cyclicNodes) {
                if (search.halted) break
                search.from(start, listedUpTo, limit)
            }
            listedUpTo = limit
        }
        truncated = search.truncated
        detected = search.cycles.sortedWith(compareBy({ it.loop.size }, { it.toString() }))
        return this
    }

    /** Every cycle found, shortest first. */
    fun found(): List<Cycle> = detected

    /** Names of all types that lie on at least one cycle, sorted; complete even when [truncated]. */
    fun cyclicTypes(): List<String> = cyclic

    /** Each cycle as its (field, type reached) hops, from a root operation field to the type that closes the loop. */
    fun cycles(): List<List<Pair<String, String?>>> = detected.map { cycle ->
        (cycle.entry + cycle.loop).map { hop -> (if (hop.fragment) "... on ${hop.target}" else hop.field) to hop.target }
    }

    fun cyclesAsStrings(): List<String> = detected.map { it.toString() }

    /** Doubling length limits ending at [longest]: short cycles are listed before the budget can run out on long ones. */
    private fun lengthLimits(longest: Int): List<Int> {
        if (longest < 1) return emptyList()
        val limits = mutableListOf<Int>()
        var limit = 2
        while (limit < longest) {
            limits.add(limit)
            limit *= 2
        }
        limits.add(longest)
        return limits
    }

    private fun buildGraph(): Graph {
        val index = HashMap<String, Int>()
        val types = ArrayList<GraphQLNamedType>()
        val reachedBy = ArrayList<Hop?>()
        val reachedFrom = ArrayList<Int>()
        val edges = ArrayList<List<Edge>>()

        fun idOf(type: GraphQLNamedType, via: Hop?, from: Int): Int = index.getOrPut(type.name) {
            types.add(type)
            reachedBy.add(via)
            reachedFrom.add(from)
            types.size - 1
        }

        val gql = schema.schema
        for (root in listOfNotNull(gql.queryType, gql.mutationType, gql.subscriptionType)) idOf(root, null, -1)

        // `types` grows while it is walked: breadth-first, so `reachedBy` holds shortest entry paths.
        var current = 0
        while (current < types.size) {
            val type = types[current]
            val out = ArrayList<Edge>()
            if (type is GraphQLFieldsContainer) {
                for (field in type.fieldDefinitions) {
                    val target = composite(field.type) ?: continue
                    out.add(Edge(field.name, false, idOf(target, Hop(type.name, field.name, target.name), current)))
                }
            }
            val selectable: List<GraphQLNamedType> = when (type) {
                is GraphQLInterfaceType -> gql.getImplementations(type).orEmpty()
                is GraphQLUnionType -> type.types
                else -> emptyList()
            }
            for (target in selectable) {
                out.add(Edge(target.name, true, idOf(target, Hop(type.name, target.name, target.name, fragment = true), current)))
            }
            edges.add(out)
            current++
        }
        return Graph(types.map { it.name }, edges, reachedBy, reachedFrom)
    }

    /** The object, interface or union type under [type]'s list/non-null wrappers, or null for a scalar or enum. */
    private fun composite(type: GraphQLType): GraphQLNamedType? {
        val unwrapped: GraphQLType = GraphQLTypeUtil.unwrapAll(type)
        val resolved = if (unwrapped is GraphQLTypeReference) schema.schema.getType(unwrapped.name) else unwrapped
        return when (resolved) {
            is GraphQLObjectType -> resolved
            is GraphQLInterfaceType -> resolved
            is GraphQLUnionType -> resolved
            else -> null
        }
    }

    /** Kosaraju's algorithm, iterative so that a long chain of types cannot overflow the stack. */
    private fun stronglyConnectedComponents(edges: List<List<Edge>>): IntArray {
        val size = edges.size
        val finished = IntArray(size)
        var finishedCount = 0
        val seen = BooleanArray(size)
        val nextEdge = IntArray(size)
        val stack = IntArray(size)
        for (root in 0 until size) {
            if (seen[root]) continue
            var depth = 0
            stack[depth++] = root
            seen[root] = true
            while (depth > 0) {
                val node = stack[depth - 1]
                if (nextEdge[node] < edges[node].size) {
                    val to = edges[node][nextEdge[node]++].to
                    if (!seen[to]) {
                        seen[to] = true
                        stack[depth++] = to
                    }
                } else {
                    finished[finishedCount++] = node
                    depth--
                }
            }
        }

        val incoming = List(size) { ArrayList<Int>() }
        for (node in 0 until size) for (edge in edges[node]) incoming[edge.to].add(node)
        val component = IntArray(size) { -1 }
        var components = 0
        for (i in size - 1 downTo 0) {
            val root = finished[i]
            if (component[root] != -1) continue
            var depth = 0
            stack[depth++] = root
            component[root] = components
            while (depth > 0) {
                val node = stack[--depth]
                for (from in incoming[node]) {
                    if (component[from] == -1) {
                        component[from] = components
                        stack[depth++] = from
                    }
                }
            }
            components++
        }
        return component
    }

    /**
     * Depth-first enumeration of elementary cycles. A cycle is found from its earliest-discovered
     * type only (a later start never steps back to an earlier type), so each one is listed once.
     */
    private inner class Search(private val graph: Graph, private val component: IntArray) {
        val cycles = ArrayList<Cycle>()
        var truncated = false
        var halted = false
        private var steps = 0
        private val onPath = BooleanArray(graph.names.size)
        private val pathNodes = ArrayList<Int>()
        private val pathEdges = ArrayList<Edge>()

        /** Lists the cycles through [start] that are longer than [listedUpTo] hops and at most [limit]. */
        fun from(start: Int, listedUpTo: Int, limit: Int) {
            pathNodes.add(start)
            visit(start, start, listedUpTo, limit)
            pathNodes.clear()
        }

        private fun visit(start: Int, node: Int, listedUpTo: Int, limit: Int) {
            for (edge in graph.edges[node]) {
                if (halted) return
                if (++steps > MAX_STEPS) {
                    stop()
                    return
                }
                val to = edge.to
                if (to == start) {
                    if (pathEdges.size + 1 in (listedUpTo + 1)..limit) {
                        if (cycles.size >= maxCycles) {
                            stop()
                            return
                        }
                        pathEdges.add(edge)
                        cycles.add(Cycle(entryTo(start), loop(start)))
                        pathEdges.removeAt(pathEdges.size - 1)
                    }
                } else if (to > start && component[to] == component[start] && !onPath[to] && pathEdges.size + 1 < limit) {
                    onPath[to] = true
                    pathNodes.add(to)
                    pathEdges.add(edge)
                    visit(start, to, listedUpTo, limit)
                    pathEdges.removeAt(pathEdges.size - 1)
                    pathNodes.removeAt(pathNodes.size - 1)
                    onPath[to] = false
                }
            }
        }

        private fun stop() {
            truncated = true
            halted = true
        }

        /** The current path, closed back onto [start], as hops. */
        private fun loop(start: Int): List<Hop> = pathEdges.mapIndexed { i, edge ->
            val target = if (i + 1 < pathNodes.size) pathNodes[i + 1] else start
            Hop(graph.names[pathNodes[i]], edge.label, graph.names[target], edge.fragment)
        }

        /** Hops from a root operation type to [node], following the edges that first discovered each type. */
        private fun entryTo(node: Int): List<Hop> {
            val hops = ArrayList<Hop>()
            var at = node
            while (true) {
                hops.add(graph.reachedBy[at] ?: break)
                at = graph.reachedFrom[at]
            }
            hops.reverse()
            return hops
        }
    }
}
