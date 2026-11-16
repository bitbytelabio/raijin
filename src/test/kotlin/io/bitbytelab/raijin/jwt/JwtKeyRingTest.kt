package io.bitbytelab.raijin.jwt

import io.bitbytelab.raijin.bridge.JwtBridge
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import java.util.Collections
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Two tools can write the ring at once (an MCP call and the JWT tab, or two MCP calls). No key may
 * get lost, in memory or in the store, and the store must never hold half a ring.
 */
class JwtKeyRingTest {

    private fun storedIds(snapshot: String): Set<String> =
        Json.parseToJsonElement(snapshot).jsonObject.getValue("keys").jsonArray
            .map { it.jsonObject.getValue("id").jsonPrimitive.content }
            .toSet()

    private fun listedIds(bridge: JwtBridge): Set<String> =
        bridge.keys(action = "list").getValue("keys").jsonArray
            .map { it.jsonObject.getValue("key_id").jsonPrimitive.content }
            .toSet()

    /** Runs [task] on [threads] threads released at the same instant; returns what each produced. */
    private fun <T> together(threads: Int, task: (Int) -> T): List<T> {
        val pool = Executors.newFixedThreadPool(threads)
        try {
            val start = CountDownLatch(1)
            val futures = (0 until threads).map { worker ->
                pool.submit(Callable {
                    start.await()
                    task(worker)
                })
            }
            start.countDown()
            return futures.map { it.get(120, TimeUnit.SECONDS) }
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `concurrent writers lose no key and every store holds a whole ring`() {
        val stores = Collections.synchronizedList(mutableListOf<String>())
        val ring = JwtKeyRing { snapshot ->
            Thread.sleep(1) // a slow store widens the window in which writers overlap
            stores.add(snapshot)
        }
        val threads = 12
        val each = 6
        val ids = together(threads) { (0 until each).map { ring.generate("oct", 256, null, null, null).id } }.flatten()

        assertEquals(threads * each, ids.toSet().size, "two generations were given the same id")
        assertEquals(ids.toSet(), ring.list().map { it.id }.toSet())

        // One store per change, in the order the ring changed: each holds one key more than the one before.
        val stored = stores.map { storedIds(it) }
        assertEquals(threads * each, stored.size)
        stored.forEachIndexed { index, keys -> assertEquals(index + 1, keys.size) }
        stored.zipWithNext { earlier, later -> assertTrue(later.containsAll(earlier), "a store dropped a key") }
        assertEquals(ids.toSet(), stored.last())

        // The last store alone brings the whole ring back.
        val restored = JwtKeyRing().also { it.restore(stores.last()) }
        assertEquals(ids.toSet(), restored.list().map { it.id }.toSet())
    }

    @Test
    fun `an id asked for by several generations at once goes to one of them`() {
        val ring = JwtKeyRing()
        val outcomes = together(10) {
            try {
                ring.generate("EC", null, "P-256", null, "same").id
            } catch (e: IllegalArgumentException) {
                "refused: ${e.message}"
            }
        }
        assertEquals(1, outcomes.count { it == "same" }, outcomes.toString())
        assertEquals(9, outcomes.count { it == "refused: key_id 'same' already exists" }, outcomes.toString())
        assertEquals(listOf("same"), ring.list().map { it.id })
    }

    @Test
    fun `the store equals the ring after generate, import and delete race`() {
        val stored = AtomicReference<String>()
        val bridge = JwtBridge(save = { stored.set(it) })
        val donor = JwtKeyRing()
        val imports = (0 until 8).map { n ->
            (donor.generate("oct", 256, null, null, "imported-$n") as JwtKey.Jose).jwk.toJSONString()
        }

        together(3) { worker ->
            when (worker) {
                0 -> (0 until 8).forEach { n -> bridge.keys(action = "generate", kty = "EC", crv = "P-256", keyId = "generated-$n") }
                1 -> imports.forEach { jwk -> bridge.keys(action = "import", jwk = jwk) }
                else -> (0 until 8).forEach { n ->
                    bridge.keys(action = "generate", kty = "oct", keyId = "temporary-$n")
                    bridge.keys(action = "delete", keyId = "temporary-$n")
                }
            }
        }

        val expected = ((0 until 8).map { "generated-$it" } + (0 until 8).map { "imported-$it" }).toSet()
        assertEquals(expected, listedIds(bridge))
        assertEquals(expected, storedIds(stored.get()))
        // A new session that loads what was stored sees the same ring.
        assertEquals(expected, listedIds(JwtBridge(load = { stored.get() })))
    }

    @Test
    fun `an import stores every key or none`() {
        val stores = mutableListOf<String>()
        val ring = JwtKeyRing { stores.add(it) }
        ring.generate("oct", 256, null, null, "taken")
        val donor = JwtKeyRing()
        val fresh = (donor.generate("oct", 256, null, null, "fresh") as JwtKey.Jose).jwk.toJSONString()
        val clash = (donor.generate("oct", 256, null, null, "taken") as JwtKey.Jose).jwk.toJSONString()

        val failure = assertFailsWith<IllegalArgumentException> {
            ring.import(null, """{"keys":[$fresh,$clash]}""", null)
        }
        assertTrue("'taken' already exists" in failure.message!!, failure.message)
        assertEquals(listOf("taken"), ring.list().map { it.id })
        assertEquals(1, stores.size)

        // Without the clash the set goes in whole, and a set may not repeat an id within itself.
        assertEquals(listOf("fresh"), ring.import(null, """{"keys":[$fresh]}""", null).map { it.id })
        assertEquals(2, stores.size)
        assertEquals(setOf("fresh", "taken"), storedIds(stores.last()))
        assertFailsWith<IllegalArgumentException> { JwtKeyRing().import(null, """{"keys":[$fresh,$fresh]}""", null) }
    }

    @Test
    fun `imported keys without a kid get ids that do not collide`() {
        val ring = JwtKeyRing()
        ring.generate("oct", 256, null, null, "oct-2")
        val anonymous = """{"keys":[{"kty":"oct","k":"AAAA"},{"kty":"oct","k":"BBBB"},{"kty":"oct","k":"CCCC"}]}"""
        val ids = ring.import(null, anonymous, null).map { it.id }
        assertEquals(3, ids.toSet().size)
        assertFalse("oct-2" in ids, ids.toString())
        assertEquals((ids + "oct-2").toSet(), ring.list().map { it.id }.toSet())
        // The id is also the kid of the stored key, so a token signed with it names the right key.
        ids.forEach { id -> assertEquals(id, (ring.get(id) as JwtKey.Jose).jwk.keyID) }
    }

    @Test
    fun `a failing store keeps the key and says so`() {
        var failing = true
        val ring = JwtKeyRing { if (failing) throw IllegalStateException("disk full") }
        val key = ring.generate("oct", 256, null, null, "k")
        assertEquals(listOf(key), ring.list())
        assertEquals("disk full", ring.storeError)
        assertFalse(ring.persist())

        failing = false
        assertTrue(ring.persist())
        assertNull(ring.storeError)

        val bridge = JwtBridge(save = { throw IllegalStateException("disk full") })
        val generated = bridge.keys(action = "generate", kty = "oct", keyId = "k")
        assertNull(generated["error"])
        assertEquals("k", generated.getValue("key_id").jsonPrimitive.content)
        assertTrue("disk full" in generated.getValue("warning").jsonPrimitive.content)
        assertEquals(setOf("k"), listedIds(bridge))
        // Nothing to warn about when there is no store.
        assertNull(JwtBridge().keys(action = "generate", kty = "oct")["warning"])
    }

    @Test
    fun `a generation that fails gives its id back`() {
        val ring = JwtKeyRing()
        assertFailsWith<IllegalArgumentException> { ring.generate("RSA", 100, null, null, "k") }
        assertFailsWith<IllegalArgumentException> { ring.generate("EC", null, "Ed25519", null, "k") }
        assertFailsWith<IllegalArgumentException> { ring.generate("nonsense", null, null, null, "k") }
        assertEquals("k", ring.generate("oct", 256, null, null, "k").id)
        assertEquals(1, ring.list().size)
    }

    @Test
    fun `restore skips entries it cannot read and does not write the store`() {
        val stores = mutableListOf<String>()
        val good = (JwtKeyRing().generate("oct", 256, null, null, "good") as JwtKey.Jose).jwk.toJSONString()
        val snapshot = buildJsonObject {
            put("v", 1)
            putJsonArray("keys") {
                add(buildJsonObject { put("id", "broken"); put("material", "{not json") })
                add(buildJsonObject { put("id", "good"); put("material", good) })
                add(buildJsonObject { put("id", "pw"); put("material", buildJsonObject { put("kty", "password"); put("k", "hunter2") }.toString()) })
                add("not an entry")
            }
            putJsonObject("extra") { put("ignored", true) }
        }.toString()

        val ring = JwtKeyRing { stores.add(it) }
        ring.restore(snapshot)
        assertEquals(listOf("good", "pw"), ring.list().map { it.id })
        assertEquals("hunter2", (ring.get("pw") as JwtKey.Password).password)
        assertTrue(stores.isEmpty())
    }
}
