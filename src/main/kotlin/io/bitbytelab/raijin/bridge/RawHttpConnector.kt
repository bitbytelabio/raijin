package io.bitbytelab.raijin.bridge

import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SNIServerName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Connections for the tools that talk to a target on their own socket instead of through Burp
 * (`http_send_pipeline`, `http_race` with `sync: last_byte`). TLS accepts any certificate (the
 * target is under test, not trusted) and offers only `http/1.1` through ALPN. Nagle's algorithm is
 * off, so every write leaves as written.
 */
internal object RawHttpConnector {

    private val trustAll: SSLSocketFactory by lazy {
        val context = SSLContext.getInstance("TLS")
        context.init(
            null,
            arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            }),
            SecureRandom(),
        )
        context.socketFactory
    }

    /**
     * Opens a connection to [host]:[port].
     *
     * @param timeoutMs bounds the TCP connect and the TLS handshake.
     * @param sni the TLS server name: null sends [host] (and none for an IP literal, as the JDK
     *   does), an empty string sends no SNI extension, anything else is sent as given.
     */
    fun connect(host: String, port: Int, useTls: Boolean, timeoutMs: Int, sni: String? = null): Socket {
        val plain = Socket()
        try {
            plain.tcpNoDelay = true
            plain.connect(InetSocketAddress(host, port), timeoutMs)
            if (!useTls) return plain
            val ssl = trustAll.createSocket(plain, host, port, true) as SSLSocket
            // Bounds the handshake: a server that accepts TCP but never answers the ClientHello
            // would otherwise block forever.
            ssl.soTimeout = timeoutMs
            val params = ssl.sslParameters
            params.applicationProtocols = arrayOf("http/1.1")
            if (sni != null) params.serverNames = if (sni.isEmpty()) emptyList() else listOf(serverName(sni))
            ssl.sslParameters = params
            ssl.startHandshake()
            return ssl
        } catch (e: Exception) {
            runCatching { plain.close() }
            throw e
        }
    }

    /**
     * [value] as an SNI host name. The strict form (RFC 6066 host name rules) is tried first, then
     * the lenient encoded form, which also takes names a test needs, such as one with `_`.
     *
     * @throws IllegalArgumentException when the TLS stack cannot send [value] at all.
     */
    fun serverName(value: String): SNIServerName =
        runCatching { SNIHostName(value) }.getOrNull()
            ?: value.takeIf { name -> name.all { it.code in 0x21..0x7E } }
                ?.let { runCatching { SNIHostName(it.toByteArray(Charsets.US_ASCII)) }.getOrNull() }
            ?: throw IllegalArgumentException("sni '$value' cannot be sent as a TLS server name (printable ASCII host names only)")
}
