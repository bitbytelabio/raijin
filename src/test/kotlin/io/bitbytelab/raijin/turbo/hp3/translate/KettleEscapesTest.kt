package io.bitbytelab.raijin.turbo.hp3.translate

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class KettleEscapesTest {

    @Test
    fun `a backtick in a field name decodes to a colon`() {
        assertEquals("Transfer-Encoding:chunked ", KettleEscapes.decodeName("Transfer-Encoding`chunked "))
        assertEquals(":authority", KettleEscapes.decodeName("`authority"))
    }

    @Test
    fun `a name decodes the rest of the alphabet in the same pass`() {
        assertEquals("Transfer-Encoding:chunked\r\nxz", KettleEscapes.decodeName("Transfer-Encoding`chunked^~xz"))
        assertEquals("a b\u0000", KettleEscapes.decodeName("a^sb^0"))
    }

    @Test
    fun `an escaped backtick stays a literal backtick in a name`() {
        assertEquals("a`b", KettleEscapes.decodeName("a^x60b"))
    }

    @Test
    fun `a value keeps its backticks`() {
        assertEquals("\${alert`1`}", KettleEscapes.decode("\${alert`1`}"))
        assertEquals("a`b\r\n", KettleEscapes.decode("a`b^~"))
    }

    @Test
    fun `a malformed escape in a name is still an error`() {
        assertFailsWith<KettleSyntaxException> { KettleEscapes.decodeName("bad`name^q") }
        assertFailsWith<KettleSyntaxException> { KettleEscapes.decodeName("trailing`^") }
    }
}
