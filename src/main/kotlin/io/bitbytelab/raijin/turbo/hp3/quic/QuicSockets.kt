package io.bitbytelab.raijin.turbo.hp3.quic

import tech.kwik.core.DatagramSocketFactory
import java.net.DatagramSocket

/**
 * UDP sockets sized for a high request rate.
 *
 * <p>Kwik's default is a bare {@code new DatagramSocket()}, which takes whatever the OS hands out.
 * On macOS that is a 64KB send buffer, and a run that puts thousands of requests per second onto a
 * connection fills it. An undersized receive buffer is worse: datagrams the kernel cannot store are
 * dropped before Kwik's receiver thread ever sees them, and QUIC pays for each one with a
 * retransmission and a congestion-window cut.
 *
 * <p>The OS clamps the request down to its own maximum ({@code kern.ipc.maxsockbuf} on macOS,
 * {@code net.core.rmem_max} and {@code net.core.wmem_max} on Linux), so asking for more than it
 * allows is harmless. It does not clamp upwards: a request below the default is applied, and
 * lowers the buffer. Hosts tuned for throughput hand out defaults well above
 * {@link #HIGH_THROUGHPUT_BYTES} - 16MB on the Linux box this was measured on, against the 4MB
 * asked for here - so a flat request there shrinks the receive buffer fourfold and buys the
 * drops described above. {@link #highThroughput()} therefore raises only, and
 * {@link #withBufferSizes} stays literal for callers that mean to set a specific size.
 */
object QuicSockets {

    /**
     * Requested buffer size in each direction. Comfortably above the bandwidth-delay product of any
     * path this tool is pointed at, and above the macOS default in both directions.
     */
    const val HIGH_THROUGHPUT_BYTES: Int = 4 * 1024 * 1024

    /**
     * The size to ask for given what the socket already has. Raising a buffer is the point;
     * lowering one the OS has already granted would cost exactly the dropped datagrams this class
     * exists to avoid, so a request below the current size resolves to the current size.
     */
    internal fun raiseOnly(current: Int, requested: Int): Int {
        return Math.max(current, requested)
    }

    /** A factory whose sockets ask for {@code receiveBytes} and {@code sendBytes}. */
    @JvmStatic
    fun withBufferSizes(receiveBytes: Int, sendBytes: Int): DatagramSocketFactory {
        if (receiveBytes < 1 || sendBytes < 1) {
            throw IllegalArgumentException("socket buffer sizes must be positive")
        }
        return DatagramSocketFactory { _ ->
            val socket = DatagramSocket()
            socket.receiveBufferSize = receiveBytes
            socket.sendBufferSize = sendBytes
            socket
        }
    }

    /**
     * The factory used by real runs: at least {@link #HIGH_THROUGHPUT_BYTES} in each direction,
     * and whatever the host already granted where that is more generous.
     */
    @JvmStatic
    fun highThroughput(): DatagramSocketFactory {
        return DatagramSocketFactory { _ ->
            val socket = DatagramSocket()
            socket.receiveBufferSize =
                raiseOnly(socket.receiveBufferSize, HIGH_THROUGHPUT_BYTES)
            socket.sendBufferSize =
                raiseOnly(socket.sendBufferSize, HIGH_THROUGHPUT_BYTES)
            socket
        }
    }
}
