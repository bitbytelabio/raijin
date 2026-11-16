package io.bitbytelab.raijin.bridge

import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.RedirectionMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import java.lang.reflect.Proxy
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import burp.api.montoya.core.ByteArray as BurpByteArray

/** Burp request options and native HTTP/2 requests as they are handed to Montoya. */
class HttpSendOptionsTest {

    private inline fun <reified T : Any> fake(noinline handler: (String, Array<out Any?>) -> Any?): T =
        Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { proxy, method, args ->
            when (method.name) {
                "toString" -> "fake ${T::class.simpleName}"
                "hashCode" -> System.identityHashCode(proxy)
                "equals" -> proxy === args?.firstOrNull()
                else -> handler(method.name, args ?: emptyArray<Any?>())
            }
        } as T

    private val calls = ArrayList<String>()
    private var http2Args: Array<out Any?>? = null

    private fun options(): RequestOptions = fake { m, a ->
        calls += if (a.isEmpty()) m else "$m(${a.joinToString()})"
        options()
    }

    private val factory: MontoyaObjectFactory = fake { m, a ->
        when (m) {
            "requestOptions" -> options()
            "httpService" -> fake<HttpService> { sm, _ ->
                when (sm) {
                    "host" -> a[0]
                    "port" -> a[1]
                    "secure" -> a[2]
                    else -> error("HttpService.$sm")
                }
            }
            "httpHeader" -> fake<HttpHeader> { hm, _ -> if (hm == "name") a[0] else if (hm == "value") a[1] else error("HttpHeader.$hm") }
            "byteArray" -> fake<BurpByteArray> { bm, _ -> if (bm == "getBytes") a[0] else error("ByteArray.$bm") }
            "http2Request" -> {
                http2Args = a
                fake<HttpRequest> { rm, _ -> error("HttpRequest.$rm") }
            }
            else -> error("MontoyaObjectFactory.$m")
        }
    }

    private var previousFactory: MontoyaObjectFactory? = null

    @BeforeTest
    fun installFactory() {
        previousFactory = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = factory
    }

    @AfterTest
    fun restoreFactory() {
        ObjectFactoryLocator.FACTORY = previousFactory
    }

    @Test
    fun `every option set is passed to Montoya's RequestOptions`() {
        HttpSendOptions(RedirectionMode.SAME_HOST, "sni.example", 0, verifyTls = true).toRequestOptions(HttpMode.HTTP_2, "conn-1")
        assertEquals(
            listOf(
                "withHttpMode(HTTP_2)", "withConnectionId(conn-1)", "withRedirectionMode(SAME_HOST)",
                "withServerNameIndicator(sni.example)", "withResponseTimeout(0)", "withUpstreamTLSVerification",
            ),
            calls,
        )
        assertTrue(HttpSendOptions().isDefault)
        assertFalse(HttpSendOptions(sni = "").isDefault)
        assertEquals(RedirectionMode.IN_SCOPE, HttpSendOptions.REDIRECTS.getValue("in_scope"))
    }

    @Test
    fun `a native HTTP2 request carries the header list as given and the body bytes`() {
        val fields = listOf(":method" to "POST", ":path" to "/a\r\nb", ":authority" to "x", ":authority" to "y", "content-length" to "3")
        HttpRequestBuilder.http2("https://h.example:8443/ignored", "GET", fields, "é!", null, null, null)
        val (service, headers, body) = http2Args!!.let { Triple(it[0] as HttpService, it[1] as List<*>, it[2] as BurpByteArray) }
        assertEquals(Triple("h.example", 8443, true), Triple(service.host(), service.port(), service.secure()))
        assertEquals(fields, headers.map { (it as HttpHeader).name() to it.value() })
        // Latin-1 text goes out one byte per char, as Burp holds raw bytes.
        assertEquals(listOf(0xE9.toByte(), '!'.code.toByte()), body.bytes.toList())
    }
}
