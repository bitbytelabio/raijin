package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.intruder.Intruder
import burp.api.montoya.intruder.PayloadProcessor
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Intruder payload processors (plan P0.3 item 4): what each transform does to a payload, and that
 * a processor which could only fail once Intruder is running is refused when it is registered.
 */
class IntruderBridgeTest {

    private class FakeRegistration : Registration {
        var deregistered = false
        override fun isRegistered(): Boolean = !deregistered
        override fun deregister() { deregistered = true }
    }

    private class FakeIntruder {
        val processors = mutableListOf<PayloadProcessor>()
        val handles = mutableListOf<FakeRegistration>()

        val api: MontoyaApi = run {
            val intruder = Proxy.newProxyInstance(Intruder::class.java.classLoader, arrayOf(Intruder::class.java)) { _, method, args ->
                check(method.name == "registerPayloadProcessor") { "unexpected Intruder.${method.name}" }
                processors += args[0] as PayloadProcessor
                FakeRegistration().also { handles += it }
            }
            Proxy.newProxyInstance(MontoyaApi::class.java.classLoader, arrayOf(MontoyaApi::class.java)) { _, method, _ ->
                check(method.name == "intruder") { "unexpected MontoyaApi.${method.name}" }
                intruder
            } as MontoyaApi
        }
    }

    private fun transform(type: String, payload: String, vararg params: Pair<String, String>) =
        IntruderBridge.transform(type, mapOf(*params), payload) { "url(${it})" }

    private fun JsonObject.text(key: String): String? = this[key]?.jsonPrimitive?.content

    // ---- transforms -------------------------------------------------------

    @Test
    fun `each transform does what its name says`() {
        assertEquals("YWRtaW4=", transform("encode_base64", "admin"))
        assertEquals("url(a b)", transform("encode_url", "a b"))
        assertEquals("21232f297a57a5a743894a0e4a801fc3", transform("hash_md5", "admin"))
        assertEquals("d033e22ae348aeb5660fc2140aec35850c4da997", transform("hash_sha1", "admin"))
        assertEquals("8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", transform("hash_sha256", "admin"))
        assertEquals("id=7", transform("prefix", "7", "prefix_value" to "id="))
        assertEquals("7--", transform("suffix", "7", "suffix_value" to "--"))
        assertEquals("user-admin", transform("regex_replace", "admin@corp", "regex_pattern" to "(\\w+)@.*", "regex_replacement" to "user-$1"))
    }

    @Test
    fun `payloads are hashed and encoded as UTF-8`() {
        assertEquals("w6k=", transform("encode_base64", "\u00e9"))
    }

    // ---- validation at registration ------------------------------------------

    @Test
    fun `regex_replace needs a pattern that compiles and a replacement that fits it`() {
        assertNull(IntruderBridge.regexReplaceError(mapOf("regex_pattern" to "(a)", "regex_replacement" to "[$1]")))
        assertNull(IntruderBridge.regexReplaceError(mapOf("regex_pattern" to "a")), "no replacement deletes the match")
        assertEquals("regex_replace requires a non-empty regex_pattern", IntruderBridge.regexReplaceError(emptyMap()))
        assertTrue(IntruderBridge.regexReplaceError(mapOf("regex_pattern" to "(a"))!!.startsWith("Invalid regex_pattern:"))
        assertEquals(
            "Invalid regex_replacement: regex_pattern has no group 2 (it has 1)",
            IntruderBridge.regexReplaceError(mapOf("regex_pattern" to "(a)", "regex_replacement" to "$2")),
        )
    }

    @Test
    fun `a replacement is checked the way Java reads it`() {
        // Two digits only name a group when that group exists: with one group, $12 is group 1 then "2".
        assertNull(IntruderBridge.replacementError("(a)", "$12"))
        assertEquals("a2", IntruderBridge.transform("regex_replace", mapOf("regex_pattern" to "(a)", "regex_replacement" to "$12"), "a") { it })
        // An escaped dollar or backslash is text.
        assertNull(IntruderBridge.replacementError("a", "\\$1 and \\\\"))
        assertTrue(IntruderBridge.replacementError("a", "\${1}")!!.contains("'1'"))
        assertTrue(IntruderBridge.replacementError("(?<n>a)", "\${n")!!.contains("closing brace"))
    }

    @Test
    fun `an invalid processor is refused and never reaches Intruder`() {
        val burp = FakeIntruder()
        val bridge = IntruderBridge(burp.api, StateManager())

        val unknownType = bridge.registerPayloadProcessor("p", "rot13", emptyMap())
        assertTrue(unknownType.text("error")!!.contains("transform_type"), unknownType.toString())

        val badRegex = bridge.registerPayloadProcessor("p", "regex_replace", mapOf("regex_pattern" to "([a-z"))
        assertTrue(badRegex.text("error")!!.startsWith("Invalid regex_pattern:"), badRegex.toString())

        val badReplacement = bridge.registerPayloadProcessor("p", "regex_replace", mapOf("regex_pattern" to "a", "regex_replacement" to "\$1"))
        assertTrue(badReplacement.text("error")!!.startsWith("Invalid regex_replacement:"), badReplacement.toString())

        val unnamed = bridge.registerPayloadProcessor(" ", "prefix", mapOf("prefix_value" to "x"))
        assertEquals("name must not be blank", unnamed.text("error"))

        assertTrue(burp.processors.isEmpty())
    }

    @Test
    fun `registering a name again replaces the processor and keeps one handle for unload`() {
        val burp = FakeIntruder()
        val state = StateManager()
        val bridge = IntruderBridge(burp.api, state)

        assertEquals("registered", bridge.registerPayloadProcessor("b64", "encode_base64", emptyMap()).text("status"))
        val again = bridge.registerPayloadProcessor("b64", "ENCODE_BASE64", emptyMap())

        assertEquals("encode_base64", again.text("transform_type"))
        assertEquals("1", again.text("total_registered"))
        assertTrue(burp.handles[0].deregistered, "the replaced processor must leave Intruder")
        assertFalse(burp.handles[1].deregistered)
        assertEquals(listOf("b64"), state.registeredPayloadProcessors.toList())
        assertEquals("b64", burp.processors.last().displayName())

        // Unload deregisters what is left.
        state.cleanup()
        assertTrue(burp.handles[1].deregistered)
    }
}
