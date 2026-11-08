package io.bitbytelab.raijin.turbo.hp3.h3

import io.bitbytelab.raijin.turbo.hp3.h3.qpack.FieldLine

/**
 * An HTTP/3 request as it will go on the wire: an ordered field list and a body.
 *
 * <p>Pseudo-headers are ordinary entries in {@code fields}, in whatever order and multiplicity the
 * caller chose. Nothing is derived, defaulted or validated here — the translator above decides what
 * the fields are, and this record carries them unchanged.
 *
 * @param fields ordered field lines, pseudo-headers included
 * @param body   request body; empty means no DATA frame is sent at all
 */
class Http3Request(fields: List<FieldLine>, private val body: ByteArray) {

    private val fields: List<FieldLine> = java.util.List.copyOf(fields)

    fun fields(): List<FieldLine> = fields

    fun body(): ByteArray = body

    fun hasBody(): Boolean {
        return body.size > 0
    }

    companion object {
        @JvmStatic
        fun of(fields: List<FieldLine>): Http3Request {
            return Http3Request(fields, ByteArray(0))
        }

        @JvmStatic
        fun of(fields: List<FieldLine>, body: ByteArray): Http3Request {
            return Http3Request(fields, body)
        }
    }
}
