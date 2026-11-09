package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import kotlinx.serialization.json.*

class DecoderBridge(private val sendOne: (String) -> Unit) {

    constructor(api: MontoyaApi) : this({ data ->
        api.decoder().sendToDecoder(BurpByteArray.byteArray(data))
    })

    /**
     * Sends each string to Burp Suite's Decoder as its own item.
     *
     * @param dataItems The strings to send. Each one opens a Decoder item.
     * @return JSON object confirming how many items were sent.
     */
    fun send(dataItems: List<String>): JsonObject {
        dataItems.forEach(sendOne)
        return buildJsonObject {
            put("items_sent", dataItems.size)
            put("status", "sent_to_decoder")
            put("data_length", dataItems.sumOf { it.length })
        }
    }
}
