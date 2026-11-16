package io.bitbytelab.raijin.turbo

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Opens [ThreadedRequestEngine]'s connections to [target], whose address is resolved once, here.
 * Every certificate is trusted, and the names each one carries are collected in [domains].
 */
internal class Http1Connector(private val target: URL, private val domains: MutableSet<String>) {
    private val address: InetAddress = InetAddress.getByName(target.host)
    private val port = if (target.port == -1) target.defaultPort else target.port
    /** The TLS factory every connection shares while TLS sessions are resumed. */
    private val sharedTls = trustingTlsFactory(domains)

    /**
     * Connects within [timeoutMillis] and, for HTTPS, layers TLS over the connected socket under
     * the target's host name. That sends SNI, which a TLS socket opened straight to the resolved
     * address never did, so name-based virtual hosts and CDNs answered as their default site.
     * With [reuseTls] the TLS comes from the shared factory, so its session can be resumed.
     */
    fun open(reuseTls: Boolean, timeoutMillis: Int): Socket {
        val plain = Socket()
        try {
            plain.connect(InetSocketAddress(address, port), timeoutMillis.coerceAtLeast(0))
            if (target.protocol != "https") {
                return plain
            }
            val factory = if (reuseTls) sharedTls else trustingTlsFactory(domains)
            // An IPv6 literal keeps its brackets in URL.host; without them it is recognised as an
            // address, for which no SNI is sent.
            val serverName = target.host.removePrefix("[").removeSuffix("]")
            return factory.createSocket(plain, serverName, port, true)
        } catch (failure: Throwable) {
            runCatching { plain.close() }
            throw failure
        }
    }

    private class TrustingTrustManager(private val domains: MutableSet<String>) : X509TrustManager {

        override fun getAcceptedIssuers(): Array<X509Certificate>? {
            return null
        }

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            val altNames = chain.get(0).subjectAlternativeNames ?: return
            for (x in altNames) {
                domains.add(x.get(1).toString())
            }
        }
    }

    companion object {
        /** A TLS socket factory that trusts every certificate, adding the names each one carries to [domains]. */
        fun trustingTlsFactory(domains: MutableSet<String>): SSLSocketFactory {
            val trustingSslContext = SSLContext.getInstance("TLS")
            trustingSslContext.init(null, arrayOf<TrustManager>(TrustingTrustManager(domains)), null)
            return trustingSslContext.socketFactory
        }
    }
}

/**
 * One of [ThreadedRequestEngine]'s connections once it is connected: the socket tuned for the run,
 * requests written onto it as each one asks, and responses read back through an
 * [Http1ResponseReader].
 */
internal class Http1Connection(
    private val socket: Socket,
    timeoutMillis: Int,
    readSize: Int,
    onRead: (String) -> Unit,
    private val shouldAbandon: () -> Boolean,
) {
    private val reader: Http1ResponseReader

    init {
        socket.soTimeout = timeoutMillis
        socket.tcpNoDelay = true
        socket.receiveBufferSize = readSize
        socket.keepAlive = true
        reader = Http1ResponseReader(SocketHttp1Source(socket), readSize, onRead, shouldAbandon)
    }

    /** Drops whatever is buffered, so that a batch starts on a clean buffer. */
    fun discard() = reader.discard()

    /** The next response, or null when the run is abandoned before it is complete. */
    fun readResponse(ignoreLength: Boolean): Http1Response? = reader.readResponse(ignoreLength)

    /**
     * Writes [req] whole; or with its last byte held back until its gate opens; or stopping before
     * byte [Request.pauseBefore] (counted from the end when negative), or after each of
     * [Request.pauseMarkers], for up to [Request.pauseTime] ms or until the server answers. An
     * answer to a paused request throws IllegalStateException when [explodeOnEarlyRead] is set.
     *
     * [Request.sent] is reset first and stamped when the request counts as sent: as its gate lets
     * the last byte go, once the bytes before its pause are written, as the bytes up to its first
     * pause marker start to go, or once it is written whole.
     */
    fun write(req: Request, explodeOnEarlyRead: Boolean) {
        val byteReq = req.getRequestAsBytes()
        val outputstream = socket.getOutputStream()
        // Each request carries its own send time, so every response in a pipelined
        // batch is timed from its own request, not from the last one written.
        req.sent = 0L
        if (req.gate != null) {
            val withHold = 1
            outputstream.write(byteReq, 0, byteReq.size-withHold)
            req.gate!!.waitForGo()
            req.sent = System.nanoTime()
            outputstream.write(byteReq, byteReq.size-withHold, withHold)
        }
        else if (req.pauseBefore != 0) {
            val end: Int
            if (req.pauseBefore < 0) {
                end = byteReq.size + req.pauseBefore
            } else {
                end = req.pauseBefore - 1 // since it's 0-indexed
            }
            val part1 = byteReq.sliceArray(0 until end)
            outputstream.write(part1)
            req.sent = System.nanoTime()

            waitForData(req.pauseTime, explodeOnEarlyRead)

            val part2 = byteReq.sliceArray(end until byteReq.size)
            outputstream.write(part2)
        } else if (!req.pauseMarkers.isEmpty()) {
            var i = 0
            req.sent = System.nanoTime()
            // pauses *after* sending the pauseMarker
            while (i < byteReq.size && !shouldAbandon()) {
                var pausePoint = -1
                for (pauseMarker in req.pauseMarkers) {
                    val pauseBytes = pauseMarker.toByteArray(Charsets.ISO_8859_1)
                    pausePoint = Utils.indexOf(byteReq, pauseBytes, i, byteReq.size)
                    if (pausePoint != -1) {
                        outputstream.write(byteReq.sliceArray(i until (pausePoint+pauseBytes.size)))
                        waitForData(req.pauseTime, explodeOnEarlyRead)
                        i = pausePoint + pauseBytes.size
                        break
                    }
                }

                if (pausePoint == -1) {
                    outputstream.write(byteReq.sliceArray(i until byteReq.size))
                    break
                }

            }
        }
        else {
            outputstream.write(byteReq)
            req.sent = System.nanoTime()
        }
    }

    /**
     * Holds a part-sent request for up to [pauseTime] ms, ending early if the server answers. What
     * arrives joins the reader's buffer: it is the start of a response, and replacing it at each
     * pause lost an early response when a later pause heard nothing.
     */
    private fun waitForData(pauseTime: Int, explodeOnEarlyRead: Boolean) {
        val received = reader.readWithin(pauseTime)
        if (explodeOnEarlyRead && received > 0) {
            throw IllegalStateException()
        }
    }
}
