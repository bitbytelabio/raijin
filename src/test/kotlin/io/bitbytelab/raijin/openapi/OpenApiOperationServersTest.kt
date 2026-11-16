package io.bitbytelab.raijin.openapi

import kotlin.test.Test
import kotlin.test.assertEquals

class OpenApiOperationServersTest {
    @Test
    fun `invalid operation server never falls back to the specification host`() {
        val specification = """
            {
              "openapi": "3.0.3",
              "servers": [{"url": "https://api.example.test"}],
              "paths": {
                "/good": {"get": {}},
                "/bad": {"get": {"servers": [{"url": "http://%zz/"}]}}
              }
            }
        """.trimIndent()
        val imported = OpenApiImport.plan(
            OpenApiDocument.parse(specification), null, "https://spec.example.test/openapi.json"
        )
        assertEquals(listOf("/good"), imported.requests.map { it.target })
    }
}
