package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.bridge.HttpFuzzPlan.AttackMode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HttpFuzzPlanTest {

    private fun result(
        raw: String,
        sets: List<List<String>>,
        mode: AttackMode = AttackMode.SNIPER,
        marker: String? = null,
        positions: List<Pair<Int, Int>>? = null,
        encode: (String) -> String = { it },
        maxRequests: Long = Long.MAX_VALUE,
    ): HttpFuzzPlan.AttackResult = HttpFuzzPlan.planAttack(raw, positions, sets, marker, mode, encode, maxRequests)

    private fun plan(
        raw: String,
        payloads: List<String>,
        mode: AttackMode = AttackMode.SNIPER,
        marker: String? = null,
        positions: List<Pair<Int, Int>>? = null,
        sets: List<List<String>> = listOf(payloads),
        encode: (String) -> String = { it },
        maxRequests: Long = Long.MAX_VALUE,
    ): HttpFuzzPlan.AttackPlan {
        val r = result(raw, sets, mode, marker, positions, encode, maxRequests)
        assertTrue(r is HttpFuzzPlan.AttackResult.Ok, (r as? HttpFuzzPlan.AttackResult.Error)?.message)
        return r.plan
    }

    private fun texts(plan: HttpFuzzPlan.AttackPlan): List<String> = plan.requests.map { it.request }.toList()

    private fun error(raw: String, sets: List<List<String>> = listOf(listOf("X")), positions: List<Pair<Int, Int>>? = null, marker: String? = null): String {
        val r = result(raw, sets, positions = positions, marker = marker)
        assertTrue(r is HttpFuzzPlan.AttackResult.Error, "expected an error for $raw")
        return r.message
    }

    // --- injection points ---

    @Test
    fun `fuzz keyword replaces every occurrence with each payload`() {
        val p = plan("GET /a?x=FUZZ&y=FUZZ HTTP/1.1", listOf("1", "2"))
        assertEquals(HttpFuzzPlan.KEYWORD_POSITIONS, p.positionMode)
        assertEquals(listOf("GET /a?x=1&y=1 HTTP/1.1", "GET /a?x=2&y=2 HTTP/1.1"), texts(p))
        assertEquals(listOf(0, 0), p.requests.map { it.position }.toList())
        assertEquals(listOf("1", "2"), p.requests.map { it.label }.toList())
    }

    @Test
    fun `custom multi-char marker is detected and substituted`() {
        val p = plan("GET /a?id=MARKseedMARK HTTP/1.1", listOf("p1", "p2"), marker = "MARK")
        assertEquals(HttpFuzzPlan.MARKER_POSITIONS, p.positionMode)
        assertEquals(listOf("GET /a?id=p1 HTTP/1.1", "GET /a?id=p2 HTTP/1.1"), texts(p))
    }

    @Test
    fun `bracket style marker pairs and blank marker falling back to the default`() {
        assertEquals(listOf("GET /?q=Z HTTP/1.1"), texts(plan("GET /?q=[[x[[ HTTP/1.1", listOf("Z"), marker = "[[")))
        assertEquals(listOf("GET /?q=Z HTTP/1.1"), texts(plan("GET /?q=§v§ HTTP/1.1", listOf("Z"), marker = "")))
    }

    @Test
    fun `astral char payload survives substitution unchanged`() {
        val emoji = "💥"
        assertEquals(listOf("GET /?q=$emoji HTTP/1.1"), texts(plan("GET /?q=FUZZ HTTP/1.1", listOf(emoji))))
    }

    @Test
    fun `offset positions substitute in range and keep the caller's numbering`() {
        val base = "GET /?a=000&b=111 HTTP/1.1"
        val a = base.indexOf("000")
        val b = base.indexOf("111")
        // Given out of text order: position 0 is b, position 1 is a.
        val p = plan(base, listOf("X"), positions = listOf(b to b + 3, a to a + 3))
        assertEquals(HttpFuzzPlan.OFFSET_POSITIONS, p.positionMode)
        assertEquals(listOf("GET /?a=000&b=X HTTP/1.1", "GET /?a=X&b=111 HTTP/1.1"), texts(p))
        assertEquals(listOf(0, 1), p.requests.map { it.position }.toList())
    }

    @Test
    fun `bad offsets, odd markers and missing injection points are rejected`() {
        val base = "GET /?id=000 HTTP/1.1"
        assertTrue(error(base, positions = listOf(12 to 9)).let { "start" in it && "<=" in it })
        assertTrue("out of bounds" in error("short", positions = listOf(0 to 999)))
        assertTrue("non-negative" in error("hello", positions = listOf(-1 to 2)))
        assertTrue("overlaps" in error("0123456789", positions = listOf(1 to 5, 3 to 7)))
        assertTrue("Odd number" in error("GET /?a=§one HTTP/1.1"))
        assertTrue("Odd number" in error("GET /?a=§one§&b=§two HTTP/1.1"))
        assertTrue("No injection points" in error("GET /plain HTTP/1.1"))
        assertTrue("at least one payload" in error("GET /?q=FUZZ HTTP/1.1", sets = listOf(emptyList())))
    }

    // --- attack types, in the order Burp Intruder sends them ---

    @Test
    fun `sniper walks each position through every payload while the others keep their value`() {
        val p = plan("GET /?a=§one§&b=§two§ HTTP/1.1", listOf("P1", "P2"))
        assertEquals(
            listOf(
                "GET /?a=P1&b=two HTTP/1.1",
                "GET /?a=P2&b=two HTTP/1.1",
                "GET /?a=one&b=P1 HTTP/1.1",
                "GET /?a=one&b=P2 HTTP/1.1",
            ),
            texts(p),
        )
        assertEquals(4, p.total)
        assertEquals(listOf(0, 0, 1, 1), p.requests.map { it.position }.toList())
        assertEquals(listOf("P1", null), p.requests.first().payloads)
    }

    @Test
    fun `sniper with three marker pairs strips every inactive marker`() {
        val p = plan("POST /a?x=§1§ HTTP/1.1\r\nX-T: §t§\r\n\r\nb=§2§", listOf("P"))
        assertEquals(
            listOf(
                "POST /a?x=P HTTP/1.1\r\nX-T: t\r\n\r\nb=2",
                "POST /a?x=1 HTTP/1.1\r\nX-T: P\r\n\r\nb=2",
                "POST /a?x=1 HTTP/1.1\r\nX-T: t\r\n\r\nb=P",
            ),
            texts(p),
        )
    }

    @Test
    fun `battering ram puts the same payload in every position`() {
        val p = plan("GET /?a=§one§&b=§two§ HTTP/1.1", listOf("X", "Y"), mode = AttackMode.BATTERING_RAM)
        assertEquals(listOf("GET /?a=X&b=X HTTP/1.1", "GET /?a=Y&b=Y HTTP/1.1"), texts(p))
        assertEquals(listOf(-1, -1), p.requests.map { it.position }.toList())
    }

    @Test
    fun `pitchfork walks the sets in step and stops with the smallest`() {
        val p = plan(
            "GET /?u=§u§&p=§p§ HTTP/1.1", emptyList(), mode = AttackMode.PITCHFORK,
            sets = listOf(listOf("alice", "bob", "carol"), listOf("1", "2")),
        )
        assertEquals(listOf("GET /?u=alice&p=1 HTTP/1.1", "GET /?u=bob&p=2 HTTP/1.1"), texts(p))
        assertEquals(2, p.total)
        assertEquals(listOf("alice", "1"), p.requests.first().payloads)
    }

    @Test
    fun `cluster bomb sends every combination with the first position turning fastest`() {
        val p = plan(
            "GET /?u=§u§&p=§p§ HTTP/1.1", emptyList(), mode = AttackMode.CLUSTER_BOMB,
            sets = listOf(listOf("a", "b"), listOf("1", "2", "3")),
        )
        assertEquals(
            listOf("a" to "1", "b" to "1", "a" to "2", "b" to "2", "a" to "3", "b" to "3").map { (u, pw) -> "GET /?u=$u&p=$pw HTTP/1.1" },
            texts(p),
        )
        assertEquals(6, p.total)
        assertEquals(6, p.planned)
    }

    @Test
    fun `every FUZZ occurrence is its own position for the multi-set attacks`() {
        val p = plan(
            "GET /?u=FUZZ&p=FUZZ HTTP/1.1", emptyList(), mode = AttackMode.PITCHFORK,
            sets = listOf(listOf("x", "y"), listOf("1", "2")),
        )
        assertEquals(listOf("GET /?u=x&p=1 HTTP/1.1", "GET /?u=y&p=2 HTTP/1.1"), texts(p))
    }

    @Test
    fun `payload sets are reused or ignored with a note`() {
        val reused = plan("GET /?a=§a§&b=§b§&c=§c§ HTTP/1.1", emptyList(), mode = AttackMode.CLUSTER_BOMB, sets = listOf(listOf("1"), listOf("2", "3")))
        assertEquals(
            listOf("GET /?a=1&b=2&c=2 HTTP/1.1", "GET /?a=1&b=3&c=2 HTTP/1.1", "GET /?a=1&b=2&c=3 HTTP/1.1", "GET /?a=1&b=3&c=3 HTTP/1.1"),
            texts(reused),
        )
        assertTrue(reused.notes.any { "reuse set 2" in it }, reused.notes.toString())

        val sniper = plan("GET /?a=§a§ HTTP/1.1", emptyList(), sets = listOf(listOf("1"), listOf("2")))
        assertEquals(listOf("GET /?a=1 HTTP/1.1"), texts(sniper))
        assertTrue(sniper.notes.any { "first of 2" in it }, sniper.notes.toString())

        val extra = plan("GET /?a=§a§ HTTP/1.1", emptyList(), mode = AttackMode.PITCHFORK, sets = listOf(listOf("1"), listOf("2")))
        assertTrue(extra.notes.any { "were not used" in it }, extra.notes.toString())
    }

    @Test
    fun `encoders run on the placed payload while reports keep the raw one`() {
        val p = plan("GET /?q=§x§ HTTP/1.1", listOf("a b&c"), encode = PayloadEncoders.chain(listOf("url")))
        val only = p.requests.single()
        assertEquals("GET /?q=a%20b%26c HTTP/1.1", only.request)
        assertEquals("a b&c", only.label)
    }

    @Test
    fun `max_requests caps the attack with a note`() {
        val p = plan(
            "GET /?u=§u§&p=§p§ HTTP/1.1", emptyList(), mode = AttackMode.CLUSTER_BOMB,
            sets = listOf(listOf("a", "b", "c"), listOf("1", "2", "3")), maxRequests = 4,
        )
        assertEquals(9, p.total)
        assertEquals(4, p.planned)
        assertEquals(4, texts(p).size)
        assertTrue(p.notes.any { "only the first 4" in it }, p.notes.toString())
    }

    // --- ready-to-send requests ---

    @Test
    fun `Content-Length is recomputed after a payload changes the body length`() {
        val base = "POST /login HTTP/1.1\r\nHost: h\r\nContent-Length: 7\r\n\r\nq=§abc§"
        val sent = texts(plan(base, listOf("much-longer", "é")))
        assertEquals("POST /login HTTP/1.1\r\nHost: h\r\nContent-Length: 13\r\n\r\nq=much-longer", sent[0])
        // Counted as the UTF-8 bytes fuzz sends: "q=é" is 4 bytes.
        assertTrue(sent[1].contains("Content-Length: 4\r\n"), sent[1])
    }

    @Test
    fun `the Content-Length of a CL-TE request is left alone`() {
        val base = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nFUZZ\r\n0\r\n\r\n"
        assertEquals(listOf(base.replace("FUZZ", "Z")), texts(plan(base, listOf("Z"))))
    }

    @Test
    fun `offsets typed against a bare-LF request are mapped onto the normalized request`() {
        val raw = "GET /?id=000 HTTP/1.1\nHost: h\n\nbody=XYZ"
        val start = raw.indexOf("XYZ")
        val p = plan(raw, listOf("P"), positions = listOf(start to start + 3))
        assertEquals(HttpFuzzPlan.OFFSET_POSITIONS, p.positionMode)
        assertEquals(listOf("GET /?id=000 HTTP/1.1\r\nHost: h\r\n\r\nbody=P"), texts(p))
    }

    @Test
    fun `a bad offset is reported in the caller's own numbers`() {
        val raw = "GET / HTTP/1.1\nHost: h\n\n"
        val message = error(raw, positions = listOf(0 to raw.length + 5))
        assertTrue(message.contains("end (${raw.length + 5})") && message.contains("length (${raw.length})"), message)
    }

    @Test
    fun `raceRequests fixes Content-Length per payload or copies the request count times`() {
        val base = "POST /redeem HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\ncode=FUZZ"
        assertEquals(
            listOf(
                "POST /redeem HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\n\r\ncode=A",
                "POST /redeem HTTP/1.1\r\nHost: h\r\nContent-Length: 9\r\n\r\ncode=BBBB",
            ),
            HttpFuzzPlan.raceRequests(base, count = 10, payloads = listOf("A", "BBBB"))
        )
        assertEquals(
            List(3) { "GET / HTTP/1.1\r\nHost: h\r\n\r\n" },
            HttpFuzzPlan.raceRequests("GET / HTTP/1.1\nHost: h\n\n", count = 3, payloads = null)
        )
    }

    // --- helpers ---

    @Test
    fun `countOccurrences counts non-overlapping whole markers`() {
        assertEquals(2, HttpFuzzPlan.countOccurrences("MARKaMARKb", "MARK"))
        assertEquals(0, HttpFuzzPlan.countOccurrences("abc", ""))
        assertEquals(1, HttpFuzzPlan.countOccurrences("aaa", "aa"))
    }

    @Test
    fun `validatePositions flags the first bad pair and accepts valid ones`() {
        assertNull(HttpFuzzPlan.validatePositions(listOf(0 to 1, 2 to 5), 10))
        val msg = HttpFuzzPlan.validatePositions(listOf(0 to 1, 5 to 3), 10)
        assertNotNull(msg)
        assertTrue(msg.contains("positions[1]"))
    }

    @Test
    fun `attack modes are looked up by id case-insensitively`() {
        assertEquals(AttackMode.CLUSTER_BOMB, AttackMode.of(" Cluster_Bomb "))
        assertNull(AttackMode.of("intruder"))
        assertEquals(listOf("sniper", "battering_ram", "pitchfork", "cluster_bomb"), AttackMode.ids)
    }

    @Test
    fun `explicit positions succeed even when the request contains a stray section marker`() {
        val raw = "POST / HTTP/1.1\r\nHost: h\r\n\r\nnote=§only_one&val=XYZ"
        val start = raw.indexOf("XYZ")
        val p = plan(raw, listOf("P"), positions = listOf(start to start + 3))
        assertEquals(HttpFuzzPlan.OFFSET_POSITIONS, p.positionMode)
        assertEquals(listOf("POST / HTTP/1.1\r\nHost: h\r\n\r\nnote=§only_one&val=P"), texts(p))
    }
}
