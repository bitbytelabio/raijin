package io.bitbytelab.raijin.turbo.hp3.quic

class StreamFragment(
    private val streamId: Int,
    private val offset: Long,
    data: ByteArray,
    private val fin: Boolean,
) {

    private val data: ByteArray

    init {
        if (streamId < 0 || offset < 0) {
            throw IllegalArgumentException("invalid stream fragment")
        }
        this.data = data.clone()
    }

    fun streamId(): Int = streamId

    fun offset(): Long = offset

    fun data(): ByteArray = data.clone()

    fun fin(): Boolean = fin
}
