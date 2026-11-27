package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import io.bitbytelab.raijin.safety.ScopeGate
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

class HttpRequestChainTest {

    private fun rules(json: String) =
        HttpRequestChain.parseExtractRules(Json.parseToJsonElement(json))

    private fun rejection(json: String): String =
        assertFailsWith<IllegalArgumentException> { rules(json) }.message!!

    @Test
    fun `extract rules take a regex, a JSONPath or an XPath`() {
        val parsed =
            rules(
                """[{"name":"csrf","pattern":"csrf=(\\w+)"},{"name":"jwt","json_path":"$.data.token"},""" +
                    """{"name":"id","xpath":"//user/@id"},{"name":"sid","pattern":"SID=([^;]+)","from":"HEADER"}]""",
            )
        assertEquals(listOf("csrf", "jwt", "id", "sid"), parsed.map { it.name })
        assertEquals(listOf(false, false, false, true), parsed.map { it.fromHeader })

        val body = """{"data":{"token":"eyJ.a.b"},"html":"csrf=abc123"}"""
        val headers =
            "Content-Type: application/json\r\nSet-Cookie: theme=dark\r\nSet-Cookie: SID=s3cr3t; Path=/"
        assertEquals(
            mapOf("csrf" to "abc123", "jwt" to "eyJ.a.b", "sid" to "s3cr3t"),
            HttpRequestChain.extract(parsed, headers, body),
        )
        assertEquals(
            mapOf("id" to "42"),
            HttpRequestChain.extract(
                parsed.filter { it.name == "id" },
                "",
                """<r><user id="42"/></r>""",
            ),
        )
    }

    @Test
    fun `malformed extract rules are rejected before anything is sent`() {
        assertTrue("JSON ARRAY" in rejection("""{"name":"x","pattern":"a"}"""))
        assertTrue("JSON OBJECT" in rejection("""["x"]"""))
        assertTrue("needs a 'name'" in rejection("""[{"pattern":"a"}]"""))
        assertTrue("needs a 'pattern'" in rejection("""[{"name":"x"}]"""))
        assertTrue(
            "extract[0].pattern is not a valid regex" in
                rejection("""[{"name":"x","pattern":"("}]"""),
        )
        assertTrue(
            "extract[0].json_path" in rejection("""[{"name":"x","json_path":"$.a[?(@.b)]"}]"""),
        )
        assertTrue("not valid XPath" in rejection("""[{"name":"x","xpath":"//*["}]"""))
        assertTrue("not both" in rejection("""[{"name":"x","json_path":"a","xpath":"//a"}]"""))
        assertTrue(
            "'body' or 'header'" in rejection("""[{"name":"x","pattern":"a","from":"cookie"}]"""),
        )
        assertTrue("header rule" in rejection("""[{"name":"x","json_path":"a","from":"header"}]"""))
        assertEquals(emptyList(), HttpRequestChain.parseExtractRules(null))
    }

    @Test
    fun `variables are substituted in every string of a step, nested ones included`() {
        val step =
            Json.parseToJsonElement(
                    """{"url":"https://h/{{id}}","headers":{"X-CSRF":"{{csrf}}"},"extract":[{"name":"n","pattern":"{{id}}"}],"port":443}""",
                )
                .jsonObject
        val substituted: JsonObject =
            HttpRequestChain.substituteVariables(step, mapOf("id" to "7", "csrf" to "abc"))
        assertEquals(
            Json.parseToJsonElement(
                """{"url":"https://h/7","headers":{"X-CSRF":"abc"},"extract":[{"name":"n","pattern":"7"}],"port":443}""",
            ),
            substituted,
        )
        assertEquals(step, HttpRequestChain.substituteVariables(step, emptyMap()))
    }

    /** A [type] whose every call answers with another such stand-in (or an empty value). */
    private fun anything(type: Class<*>): Any? =
        when {
            type == String::class.java -> ""
            type == Boolean::class.javaPrimitiveType -> false
            type == Int::class.javaPrimitiveType -> 0
            type == Long::class.javaPrimitiveType -> 0L
            type == Short::class.javaPrimitiveType -> 0.toShort()
            type == Byte::class.javaPrimitiveType -> 0.toByte()
            type.isInterface ->
                Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { proxy, method, args ->
                    when (method.name) {
                        "hashCode" -> System.identityHashCode(proxy)
                        "equals" -> proxy === args?.firstOrNull()
                        "toString" -> "stand-in ${type.simpleName}"
                        else -> anything(method.returnType)
                    }
                }
            else -> null
        }

    @Test
    fun `a step that cannot be built stops the chain before anything is sent`() {
        val previous = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY =
            anything(MontoyaObjectFactory::class.java) as MontoyaObjectFactory
        try {
            // Any Burp call fails the test: nothing may reach the scope check or the sender.
            val api =
                Proxy.newProxyInstance(
                    MontoyaApi::class.java.classLoader,
                    arrayOf(MontoyaApi::class.java),
                ) { proxy, method, args ->
                    when (method.name) {
                        "hashCode" -> System.identityHashCode(proxy)
                        "equals" -> proxy === args?.firstOrNull()
                        else -> error("sent: MontoyaApi.${method.name}")
                    }
                } as MontoyaApi
            val steps =
                listOf(
                    Json.parseToJsonElement("""{"url":"https://h/login"}""").jsonObject,
                    Json.parseToJsonElement("""{"method":"GET"}""").jsonObject,
                )
            val result =
                HttpRequestChain(api, ScopeGate(api), HttpTimeouts())
                    .run(steps, HttpMode.AUTO, stopOnError = true)

            val failed = result.steps.single()
            assertEquals(1, failed.index)
            assertEquals("build", failed.phase)
            assertEquals(HttpRequestBuilder.MISSING_TARGET, failed.error)
            assertNull(failed.exchange)

            // A step whose URL comes from a variable is only checked for a target.
            val deferred =
                listOf(
                    Json.parseToJsonElement(
                            """{"url":"{{next}}","extract":[{"name":"n","pattern":"{{id}}"}]}""",
                        )
                        .jsonObject,
                )
            val later =
                HttpRequestChain(api, ScopeGate(api), HttpTimeouts())
                    .run(deferred, HttpMode.AUTO, stopOnError = true)
            assertEquals("build", later.steps.single().phase)
            assertTrue(later.steps.single().error!! != HttpRequestBuilder.MISSING_TARGET)
        } finally {
            ObjectFactoryLocator.FACTORY = previous
        }
    }
}
