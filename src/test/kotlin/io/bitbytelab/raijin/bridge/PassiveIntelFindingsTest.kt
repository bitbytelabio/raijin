package io.bitbytelab.raijin.bridge

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** How passive intel groups what a scan matched: one finding per distinct value, capped per category on values. */
class PassiveIntelFindingsTest {

    private fun json(findings: IntelFindings): JsonObject = buildJsonObject { findings.writeTo(this) }

    private fun listed(result: JsonObject, category: String): List<JsonObject> =
        result.getValue("findings").jsonObject[category]?.jsonArray?.map { it.jsonObject }.orEmpty()

    @Test
    fun `a token sent on every page takes one slot, so a different one is still listed`() {
        val findings = IntelFindings(maxPerCategory = 100)
        for (page in 1..150) findings.add("jwt_token", "eyJsession", "https://t.example/page$page", "request", "t.example")
        findings.add("jwt_token", "eyJleaked", "https://t.example/debug", "response", "t.example")

        val result = json(findings)
        assertEquals(listOf("eyJsession", "eyJleaked"), listed(result, "jwt_token").map { it.getValue("match").jsonPrimitive.content })
        assertTrue("omitted" !in result, result.toString())
        assertEquals(2, result.getValue("total_findings").jsonPrimitive.int)
        assertEquals(2, result.getValue("summary").jsonObject.getValue("jwt_token").jsonPrimitive.int)

        val session = listed(result, "jwt_token")[0]
        assertEquals("https://t.example/page1", session.getValue("url").jsonPrimitive.content)
        assertEquals("request", session.getValue("location").jsonPrimitive.content)
        assertEquals(150, session.getValue("occurrences").jsonPrimitive.int)
        val more = session.getValue("also_seen").jsonArray.map { it.jsonObject.getValue("url").jsonPrimitive.content }
        assertEquals((2..5).map { "https://t.example/page$it" }, more)

        val leaked = listed(result, "jwt_token")[1]
        assertEquals("https://t.example/debug", leaked.getValue("url").jsonPrimitive.content)
        assertEquals(1, leaked.getValue("occurrences").jsonPrimitive.int)
        assertTrue("also_seen" !in leaked)
    }

    @Test
    fun `the cap counts distinct values, and an omitted value seen again is not counted twice`() {
        val findings = IntelFindings(maxPerCategory = 3)
        for (n in 1..5) findings.add("email_address", "user$n@t.example", "https://t.example/a", "response", "t.example")
        for (page in 1..10) findings.add("email_address", "user5@t.example", "https://t.example/p$page", "response", "t.example")
        findings.add("ipv4_internal", "10.0.0.1", "https://t.example/a", "response", "t.example")

        val result = json(findings)
        assertEquals(3, listed(result, "email_address").size)
        assertEquals(2, result.getValue("omitted").jsonObject.getValue("email_address").jsonPrimitive.int)
        assertEquals(1, listed(result, "ipv4_internal").size)
        assertEquals(2, result.getValue("categories_with_findings").jsonPrimitive.int)
    }

    @Test
    fun `the same value at the same place counts once, its request and response are two places`() {
        val findings = IntelFindings()
        repeat(3) { findings.add("aws_access_key", "AKIAEXAMPLE", "https://t.example/x", "response", "t.example") }
        findings.add("aws_access_key", "AKIAEXAMPLE", "https://t.example/x", "request", "t.example")

        val key = listed(json(findings), "aws_access_key").single()
        assertEquals(2, key.getValue("occurrences").jsonPrimitive.int)
        assertEquals("request", key.getValue("also_seen").jsonArray.single().jsonObject.getValue("location").jsonPrimitive.content)
    }
}
