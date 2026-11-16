package io.bitbytelab.raijin.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HttpPayloadEncodersTest {

    private fun encode(value: String, vararg names: String) = PayloadEncoders.chain(names.toList())(value)

    @Test
    fun `url encoding keeps only unreserved characters and works on UTF-8 bytes`() {
        assertEquals("a%20b%26c%3D%2F~-._", encode("a b&c=/~-._", "url"))
        assertEquals("%C3%A9%F0%9F%92%A5", encode("é💥", "url"))
        assertEquals("%61%2D", encode("a-", "url_all"))
        assertEquals("%2520", encode(" ", "double_url"))
    }

    @Test
    fun `json, html, base64 and hex encoders`() {
        assertEquals("a\\\"b\\\\c\\n", encode("a\"b\\c\n", "json"))
        assertEquals("&lt;a href=&quot;x&quot;&gt;&amp;&#x27;", encode("<a href=\"x\">&'", "html"))
        assertEquals("aGk/Pz4=", encode("hi??>", "base64"))
        assertEquals("aGk_Pz4", encode("hi??>", "base64url"))
        assertEquals("c3a9", encode("é", "hex"))
        assertEquals("as is", encode("as is", "raw"))
    }

    @Test
    fun `encoders chain left to right and names are case-insensitive`() {
        assertEquals("YSZi", encode("a&b", "base64"))
        assertEquals("YSZi", encode("a&b", " Base64 ", "url"))
        assertEquals("JTNDeA%3D%3D", encode("<x", "url", "base64", "url"))
        assertEquals("unchanged", encode("unchanged"))
    }

    @Test
    fun `unknown encoders are named`() {
        assertNull(PayloadEncoders.unknown(listOf("url", "BASE64")))
        assertEquals("rot13", PayloadEncoders.unknown(listOf("url", "rot13")))
        val error = assertFailsWith<IllegalArgumentException> { PayloadEncoders.chain(listOf("rot13")) }
        assertTrue("rot13" in error.message!! && "base64" in error.message!!, error.message)
    }
}
