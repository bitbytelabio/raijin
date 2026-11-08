package io.bitbytelab.raijin.turbo.hp3.quic

import java.time.Duration

/**
 * Connection parameters for the QUIC transport.
 *
 * <p>The handshake timeout default is 10 seconds, which looks generous until you measure it. On a
 * network where a middlebox drops the first QUIC Initial packets, the handshake completes only
 * after PTO backoff retransmits them: measured handshakes to quic.nginx.org, www.google.com and
 * interop.seemann.io all landed at 6-7 seconds, against 0.2 seconds for a host on a non-443 port.
 * A tighter default would report "HTTP/3 does not work" on any such network.
 *
 * @param handshakeTimeout  how long to wait for the QUIC handshake
 * @param idleTimeout       how long an idle connection is kept
 * @param verifyCertificates whether to validate the server certificate; off by default to match
 *                           Burp's own upstream behaviour, since a proxy that refuses bad
 *                           certificates cannot be used to test them
 */
class QuicConfig(
    private val handshakeTimeout: Duration,
    private val idleTimeout: Duration,
    private val verifyCertificates: Boolean,
) {

    fun handshakeTimeout(): Duration = handshakeTimeout

    fun idleTimeout(): Duration = idleTimeout

    fun verifyCertificates(): Boolean = verifyCertificates

    fun withHandshakeTimeout(timeout: Duration): QuicConfig {
        return QuicConfig(timeout, idleTimeout, verifyCertificates)
    }

    fun withVerifyCertificates(verify: Boolean): QuicConfig {
        return QuicConfig(handshakeTimeout, idleTimeout, verify)
    }

    companion object {
        @JvmStatic
        fun defaults(): QuicConfig {
            return QuicConfig(Duration.ofSeconds(10), Duration.ofSeconds(30), false)
        }
    }
}
