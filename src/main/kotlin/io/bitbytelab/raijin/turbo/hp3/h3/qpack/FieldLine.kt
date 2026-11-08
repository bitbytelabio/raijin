package io.bitbytelab.raijin.turbo.hp3.h3.qpack

/**
 * One header field as it appears on the wire: a raw name and a raw value, in the order the caller
 * supplied them.
 *
 * <p>Pseudo-headers are ordinary field lines whose name begins with a colon. There is deliberately
 * no separate pseudo-header map and no canonical ordering, because reproducing Burp's HTTP/2
 * capabilities means being able to emit duplicate, out-of-order, uppercase or otherwise malformed
 * fields exactly as written.
 *
 * @param name  field name, never normalised
 * @param value field value, never normalised
 */
class FieldLine(val name: String, val value: String) {

    fun name(): String = name

    fun value(): String = value

    fun isPseudoHeader(): Boolean {
        return name.startsWith(":")
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is FieldLine) return false
        return name == other.name && value == other.value
    }

    override fun hashCode(): Int {
        return 31 * name.hashCode() + value.hashCode()
    }

    override fun toString(): String {
        return name + ": " + value
    }

    companion object {
        @JvmStatic
        fun of(name: String, value: String): FieldLine {
            return FieldLine(name, value)
        }
    }
}
