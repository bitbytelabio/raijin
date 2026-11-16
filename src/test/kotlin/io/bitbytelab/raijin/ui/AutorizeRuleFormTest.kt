package io.bitbytelab.raijin.ui

import io.bitbytelab.raijin.bridge.AutorizeBridge
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AutorizeRuleFormTest {

    private val lowPriv = AutorizeIdentity("low-priv", "Cookie", "session=low")
    private val unauth = AutorizeIdentity("unauth")
    private val valid = AutorizeRuleForm(identities = listOf(lowPriv, unauth))

    private fun error(form: AutorizeRuleForm): String = assertNotNull(form.validate())

    @Test
    fun `a complete form validates`() {
        assertNull(valid.validate())
        assertNull(valid.copy(includeHostPattern = "*.example.com", excludeUrlRegex = "/logout", methods = listOf("GET")).validate())
        assertNull(valid.copy(includeHostPattern = ".*\\.example\\.com").validate())
    }

    @Test
    fun `the editor rejects what the replay could not use`() {
        assertTrue("at least 2" in error(valid.copy(identities = listOf(unauth))))
        assertTrue("unique" in error(valid.copy(identities = listOf(unauth, AutorizeIdentity("UNAUTH")))))
        assertTrue("name" in error(valid.copy(identities = listOf(unauth, AutorizeIdentity(" ")))))
        assertTrue("header name" in error(valid.copy(identities = listOf(unauth, AutorizeIdentity("x", "", "v")))))
        assertTrue("not a valid header name" in error(valid.copy(identities = listOf(unauth, AutorizeIdentity("x", "Bad:Name", "v")))))
        assertTrue("Cookie value" in error(AutorizeRuleForm.newRule()))
        assertTrue("line breaks" in error(valid.copy(identities = listOf(unauth, AutorizeIdentity("x", "Cookie", "a\r\nInjected: 1")))))
        assertTrue("between 0 and 100" in error(valid.copy(similarityThreshold = 101.0)))
        assertTrue("between 0 and 100" in error(valid.copy(similarityThreshold = Double.NaN)))
        assertTrue("exclude URL regex" in error(valid.copy(excludeUrlRegex = "(unclosed")))
        assertTrue("host pattern" in error(valid.copy(includeHostPattern = "*.example.(com")))
    }

    @Test
    fun `identities carry header fields only when a header is named`() {
        val json = valid.identitiesJson()
        assertEquals("Cookie", (json[0]["header_name"] as JsonPrimitive).contentOrNull)
        assertEquals("session=low", (json[0]["header_value"] as JsonPrimitive).contentOrNull)
        assertEquals(setOf("name"), json[1].keys)
    }

    @Test
    fun `methods parse to upper case and blank means every method`() {
        assertEquals(listOf("GET", "POST", "PUT"), AutorizeRuleForm.parseMethods("get, Post;PUT get"))
        assertNull(AutorizeRuleForm.parseMethods("  "))
    }

    @Test
    fun `percent drops a whole number's decimals`() {
        assertEquals("90%", AutorizeRuleForm.percent(90.0))
        assertEquals("87.5%", AutorizeRuleForm.percent(87.5))
    }

    @Test
    fun `saving creates a rule the bridge lists with the form's values`() {
        val state = StateManager()
        val bridge = AutorizeBridge(state)
        val result = valid.copy(methods = listOf("GET", "POST"), similarityThreshold = 80.0).save(bridge, state, null)

        val ruleId = (result["rule_id"] as JsonPrimitive).content
        val rule = state.autorizeRules.single { it.ruleId == ruleId }
        assertEquals(setOf("GET", "POST"), rule.methods)
        assertEquals(80.0, rule.similarityThreshold)
        assertEquals(valid.copy(methods = listOf("GET", "POST"), similarityThreshold = 80.0), AutorizeRuleForm.from(rule))
    }

    @Test
    fun `an invalid form is refused before it reaches the bridge`() {
        val state = StateManager()
        val result = valid.copy(identities = listOf(unauth)).save(AutorizeBridge(state), state, null)
        assertNotNull(result["error"])
        assertTrue(state.autorizeRules.isEmpty())
    }

    @Test
    fun `clearing a filter on edit removes it and keeps the rule id`() {
        val state = StateManager()
        val bridge = AutorizeBridge(state)
        val created = valid.copy(includeHostPattern = "*.example.com", methods = listOf("POST")).save(bridge, state, null)
        val ruleId = (created["rule_id"] as JsonPrimitive).content

        val edited = AutorizeRuleForm.from(state.autorizeRules.single()).copy(includeHostPattern = null, methods = null)
        assertTrue(edited.clearsFilterOf(state.autorizeRules.single()))
        edited.save(bridge, state, ruleId)

        val rule = state.autorizeRules.single()
        assertEquals(ruleId, rule.ruleId)
        assertNull(rule.includeHostPattern)
        assertNull(rule.methods)
    }

    @Test
    fun `an edit that keeps every filter updates the rule in place`() {
        val state = StateManager()
        val bridge = AutorizeBridge(state)
        val ruleId = (valid.copy(includeHostPattern = "*.example.com").save(bridge, state, null)["rule_id"] as JsonPrimitive).content
        val createdAt = state.autorizeRules.single().createdAt

        val edited = AutorizeRuleForm.from(state.autorizeRules.single()).copy(enabled = false, similarityThreshold = 70.0)
        assertFalse(edited.clearsFilterOf(state.autorizeRules.single()))
        edited.save(bridge, state, ruleId)

        val rule = state.autorizeRules.single()
        assertEquals(createdAt, rule.createdAt)
        assertEquals("*.example.com", rule.includeHostPattern)
        assertFalse(rule.enabled)
        assertEquals(70.0, rule.similarityThreshold)
    }

    @Test
    fun `filter summary reads the rule's taps`() {
        val state = StateManager()
        valid.copy(includeHostPattern = "*.example.com", methods = listOf("POST", "GET"), excludeUrlRegex = "/logout")
            .save(AutorizeBridge(state), state, null)
        assertEquals(
            "in scope · host *.example.com · GET,POST · skip //logout/ · no static",
            AutorizeRuleForm.filtersSummary(state.autorizeRules.single()),
        )
        assertEquals("low-priv, unauth", AutorizeRuleForm.identityNames(state.autorizeRules.single()))
    }
}
