package io.bitbytelab.raijin.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

/**
 * [HeaderModifier] on both message kinds, against the fake messages of
 * [FakeHttpMessages][fakeRequest], which update and remove only the first header written exactly
 * as named.
 */
class HeaderModifierTest {

    private val duplicated = FakeMessage(headers = listOf("X-A" to "1", "Host" to "a.test", "x-a" to "2", "X-A" to "3"))

    @Test
    fun `remove takes out every occurrence whatever its case, two written alike included`() {
        assertEquals(listOf("Host" to "a.test"), HeaderModifier.remove(fakeRequest(duplicated), "x-A").headerPairs())
        assertEquals(listOf("Host" to "a.test"), HeaderModifier.remove(fakeResponse(duplicated), "x-A").headerPairs())
    }

    @Test
    fun `set leaves one header, written last when there were several, with its value as given`() {
        val expected = listOf("Host" to "a.test", "X-A" to "v\r\nInjected: 1")
        assertEquals(expected, HeaderModifier.set(fakeRequest(duplicated), "X-A", "v\r\nInjected: 1").headerPairs())
        assertEquals(expected, HeaderModifier.set(fakeResponse(duplicated), "X-A", "v\r\nInjected: 1").headerPairs())
    }

    @Test
    fun `replace updates a header the message has in place, and leaves a message without it as it is`() {
        val present = fakeResponse(FakeMessage(headers = listOf("x-a" to "0", "Host" to "a.test")))
        assertEquals(listOf("x-a" to "1", "Host" to "a.test"), HeaderModifier.replace(present, "X-A", "1").headerPairs())

        val absent = fakeResponse(FakeMessage(headers = listOf("Host" to "a.test")))
        assertSame(absent, HeaderModifier.replace(absent, "X-A", "1"))
    }
}
