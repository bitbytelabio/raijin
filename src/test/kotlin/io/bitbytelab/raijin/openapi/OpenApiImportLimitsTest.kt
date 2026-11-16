package io.bitbytelab.raijin.openapi

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The size limits of an import. The model shares an example reused through `$ref`s instead of copying it, so a
 * small document can plan far more text than it holds: one oversized body or parameter skips its operation,
 * and more text than the whole plan may hold fails the import before anything reaches Burp.
 */
class OpenApiImportLimitsTest {

    private fun plan(text: String): ImportPlan = OpenApiImport.plan(OpenApiDocument.parse(text))

    private fun planError(text: String): String = assertFailsWith<IllegalArgumentException> { plan(text) }.message.orEmpty()

    @Test
    fun `a body example over the size cap skips its operation and the rest is imported`() {
        // 40 properties, each a reference to one 32 KiB example: 1.3 MiB of body from a 34 KB document.
        val properties = (1..40).joinToString(", ") { "\"p$it\": {\"$REF\": \"#/components/schemas/Big\"}" }
        val plan = plan(
            """
            {"openapi": "3.0.3", "servers": [{"url": "https://api.example.com"}],
             "paths": {"/big": {"post": {"requestBody": {"content": {"application/json": {
                         "schema": {"type": "object", "properties": {$properties}}}}}}},
                       "/small": {"get": {}}},
             "components": {"schemas": {"Big": {"type": "string", "example": "${"x".repeat(32 * 1024)}"}}}}
            """
        )
        assertEquals(listOf("GET /small"), plan.requests.map { "${it.method} ${it.target}" })
        assertEquals(listOf("POST /big was skipped: the request body example is larger than 1 MiB"), plan.warnings)
    }

    @Test
    fun `a parameter whose style repeats its name past the cap skips its operation`() {
        // A 4 KiB name exploded over 1,000 items: 4 MiB of query string from a 6 KB document.
        val name = "n".repeat(4096)
        val items = List(1000) { "1" }.joinToString(", ")
        val plan = plan(
            """
            {"openapi": "3.0.3", "servers": [{"url": "https://api.example.com"}],
             "paths": {"/q": {"get": {"parameters": [{"name": "$name", "in": "query", "example": [$items]}]}}}}
            """
        )
        assertTrue(plan.requests.isEmpty())
        assertEquals(listOf("GET /q was skipped: the example of parameter '$name' is larger than 1 MiB"), plan.warnings)
    }

    @Test
    fun `an example reused through refs fails the import once the plan passes its budget`() {
        // One 512 KiB example as the request body of 150 operations: 75 MiB of bodies from a 0.5 MB document.
        val paths = (1..150).joinToString(", ") {
            "\"/op$it\": {\"post\": {\"requestBody\": {\"$REF\": \"#/components/requestBodies/Big\"}}}"
        }
        val message = planError(
            """
            {"openapi": "3.0.3", "servers": [{"url": "https://api.example.com"}], "paths": {$paths},
             "components": {"requestBodies": {"Big": {"content": {"application/json": {
                              "example": {"blob": "${"x".repeat(512 * 1024)}"}}}}}}}
            """
        )
        assertTrue("more than 64 MiB" in message, message)
    }

    @Test
    fun `an XML body whose schema names repeat past the plan budget fails the import`() {
        // 20,000 items under a 4 KiB element name: 160 MiB of XML from a 44 KB document.
        val name = "n".repeat(4096)
        val items = List(20_000) { "1" }.joinToString(",")
        val message = planError(
            """
            {"openapi": "3.0.3", "servers": [{"url": "https://api.example.com"}],
             "paths": {"/x": {"post": {"requestBody": {"content": {"application/xml": {
               "schema": {"type": "array", "items": {"type": "integer", "xml": {"name": "$name"}}},
               "example": [$items]}}}}}}}
            """
        )
        assertTrue("more than 64 MiB" in message, message)
    }
}
