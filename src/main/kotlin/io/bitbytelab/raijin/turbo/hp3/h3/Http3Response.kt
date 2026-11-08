package io.bitbytelab.raijin.turbo.hp3.h3

import io.bitbytelab.raijin.turbo.hp3.h3.qpack.FieldLine

/**
 * An HTTP/3 response exactly as received: the field list in wire order, the concatenated DATA
 * payload, and any trailer field section.
 *
 * @param fields   ordered response field lines, {@code :status} included wherever it appeared
 * @param body     concatenation of every DATA frame
 * @param trailers trailer fields, empty when the response had none
 */
class Http3Response(
    fields: List<FieldLine>,
    private val body: ByteArray,
    trailers: List<FieldLine>,
) {

    private val fields: List<FieldLine> = java.util.List.copyOf(fields)
    private val trailers: List<FieldLine> = java.util.List.copyOf(trailers)

    fun fields(): List<FieldLine> = fields

    fun body(): ByteArray = body

    fun trailers(): List<FieldLine> = trailers

    /**
     * The value of the first {@code :status} field, or -1 if there is none or it is not numeric.
     * A missing or malformed status is a real possibility here, because nothing in this stack
     * rejects a response for being malformed.
     */
    fun status(): Int {
        for (field in fields) {
            if (field.name() == ":status") {
                return try {
                    Integer.parseInt(field.value())
                } catch (e: NumberFormatException) {
                    -1
                }
            }
        }
        return -1
    }

    /** First value for {@code name}, case-sensitive, or null. */
    fun firstValue(name: String): String? {
        for (field in fields) {
            if (field.name() == name) {
                return field.value()
            }
        }
        return null
    }
}
