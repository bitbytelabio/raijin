package io.bitbytelab.raijin.turbo
import java.io.ByteArrayInputStream
import java.lang.StringBuilder
import com.twitter.hpack.Decoder
import com.twitter.hpack.HeaderListener


open class Frame(val type: Byte, val flags: Byte, val streamID: Int, val payload: ByteArray) {
    var die: Boolean = false

    fun asBytes(): ByteArray {
        val length = HTTP2Utils.intToThreeBytes(payload.size)
        return length + type + flags + HTTP2Utils.intToFourBytes(streamID) + payload
    }
}

class HeaderFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray, decoder: Decoder): Frame(type, flags, streamID, payload) {

    val headerString: String

    init {
        //Connection.debug("Parsing headers")
        if ((flags.toInt() and 1) == 1) {
            H2Connection.debug("Frame has set END_STREAM")
            die = true
        }

        val `in` = ByteArrayInputStream(payload)
        val headers = StringBuilder()
        // ISO-8859-1 both ways, like the body: one char per byte, so the response text round-trips.
        val listener = HeaderListener { name, value, _ ->
            headers.append(String(name, Charsets.ISO_8859_1))
            headers.append(": ")
            headers.append(String(value, Charsets.ISO_8859_1))
            headers.append("\r\n")
        }
        // The connection's decoder: HPACK state spans every header block on the connection.
        decoder.decode(`in`, listener)
        decoder.endHeaderBlock()
        headerString = headers.toString()
    }
}

class DataFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray): Frame(type, flags, streamID, payload) {
    val body: String


    init {
        //Connection.debug("Parsing data frame")
        // fixme don't use exact matching on a bloody flag!!
        if ((flags.toInt() and 1) == 1) {
            H2Connection.debug("Frame has set END_STREAM")
            die = true
        }

        body = String(payload, Charsets.ISO_8859_1)

    }
}

class SettingsFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray): Frame(type, flags, streamID, payload) {

    /** An acknowledgement of our SETTINGS rather than the server's own: the ACK flag, not an empty payload (an empty SETTINGS is legal). */
    val isAck: Boolean = (flags.toInt() and 1) == 1
    var maxConcurrentStreams = 0
    /** SETTINGS_HEADER_TABLE_SIZE, when the server sent it: the most our HPACK encoder may use. */
    var headerTableSize: Int? = null

    init {
        H2Connection.debug("Parsing settings...")

        if (payload.size == 0) {
            H2Connection.debug("No settings")
        } else {

            var head = 0
            while (head < payload.size) {
                val key = HTTP2Utils.twoByteInt(payload.slice(head..head + 1).toByteArray())
                val value = HTTP2Utils.fourByteInt(payload.slice(head + 2..head + 5).toByteArray())
                when (key) {
                    1 -> {
                        H2Connection.debug("HEADER_TABLE_SIZE = $value")
                        headerTableSize = value
                    }
                    2 -> H2Connection.debug("ENABLE_PUSH = $value")
                    3 -> {
                        H2Connection.debug("MAX_CONCURRENT_STREAMS = $value")
                        maxConcurrentStreams = value
                    }
                    4 -> H2Connection.debug("INITIAL_WINDOW_SIZE = $value")
                    5 -> H2Connection.debug("MAX_FRAME_SIZE = $value")
                    6 -> H2Connection.debug("Max headers = $value")
                    else -> H2Connection.debug("Unrecognised setting $key=$value")
                }

                head += 6
            }
        }
    }
}

class PingFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray): Frame(type, flags, streamID, payload) {
    val data: List<Byte>

    init {
        H2Connection.debug("Parsing PING")
        H2Connection.debug("Data: "+payload.asList())
        data = payload.asList()
    }
}

class WindowFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray): Frame(type, flags, streamID, payload) {


    init {
        H2Connection.debug("Parsing WINDOW_UPDATE")
        H2Connection.debug("Increment window size by "+payload.asList())
    }
}

class RstStreamFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray): Frame(type, flags, streamID, payload) {
    init {
        //Utils.out("Parsing RST_STREAM")
    }
}

class GoAwayFrame(type: Byte, flags: Byte, streamID: Int, payload: ByteArray): Frame(type, flags, streamID, payload) {

    init {
        Utils.out("Parsing GOAWAY")
        Utils.out("Last stream ID: "+payload.sliceArray(0..3).asList())
        Utils.out("Error code: "+payload.sliceArray(4..7).asList())
        val error = payload[7].toInt()
        val error_message = when (error) {
            0 -> "NO_ERROR"
            1 -> "PROTOCOL_ERROR"
            2 -> "INTERNAL_ERROR"
            3 -> "FLOW_CONTROL_ERROR"
            4 -> "SETTINGS_TIMEOUT"
            5 -> "STREAM_CLOSED"
            6 -> "FRAME_SIZE_ERROR"
            else -> "unknown error code"
        }
        H2Connection.debug(error_message)
        if (payload.size > 8) {
            H2Connection.debug("Debug data: " + payload.sliceArray(8..payload.size-1).asList())
        }
    }
}

class HTTP2Utils {
    companion object {
        fun twoByteInt(raw: ByteArray): Int {
            val b1 = raw[0].toInt()
            val b2 = raw[1].toInt()
            return (b1 and 0xFF shl 8) or (b2 and 0xFF)
        }


        fun threeByteInt(raw: ByteArray): Int {
            val b1 = raw[0].toInt()
            val b2 = raw[1].toInt()
            val b3 = raw[2].toInt()
            return (b1 and 0xFF shl 16) or (b2 and 0xFF shl 8) or (b3 and 0xFF)
        }

        fun fourByteInt(raw: ByteArray): Int {
            val b1 = raw[0].toInt()
            val b2 = raw[1].toInt()
            val b3 = raw[2].toInt()
            val b4 = raw[3].toInt()
            return (b1 and 0xFF shl 24) or (b2 and 0xFF shl 16) or (b3 and 0xFF shl 8) or (b4 and 0xFF)
        }

        fun intToThreeBytes(num: Int): ByteArray {
            val s1 = num
            val s2 = num shr 8
            val s3 = num shr 16
            return byteArrayOf(s3.toByte(), s2.toByte(), s1.toByte())
        }

        fun intToFourBytes(num: Int): ByteArray {
            val s1 = num
            val s2 = num shr 8
            val s3 = num shr 16
            val s4 = num shr 24
            return byteArrayOf(s4.toByte(), s3.toByte(), s2.toByte(), s1.toByte())
        }
    }
}

