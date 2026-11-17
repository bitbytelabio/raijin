package io.bitbytelab.raijin.turbo
import burp.api.montoya.core.ByteArray as MontoyaBytes
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.lang.Exception
import java.net.URL
import java.util.*
import java.util.concurrent.ConcurrentHashMap

/**
 * Returns the effective port for a URL, using the default port for the protocol
 * if no explicit port is specified. This handles the case where URL.getPort()
 * returns -1 for URLs like "https://example.com" without explicit port.
 */
fun getEffectivePort(url: URL): Int {
    return if (url.port == -1) url.defaultPort else url.port
}

open class Request(val template: String, val words: List<String?>, val learnBoring: Int, var label: String = "") {

    // Written by the worker that received it, read by the GUI and MCP threads, and cleared when the
    // body is dropped to save memory.
    @Volatile var response: String? = null
    var interesting: Boolean = false
    var targetUrl: URL? = null
    var engine: Any? = null
    var connectionId: String? = null   // connection identifier (user-specified or auto-assigned)
    var gateMode: String? = null       // which gate released this request, for gated HTTP/3 requests
    var callback: ((Request, Boolean) -> Boolean)? = null
    var gate: Floodgate? = null
    var order: Int = 0
    var time: Long = 0L
    var ttfb: Long = 0L
    var ttlb: Long = 0L
    var sent: Long = 0L
    var arrival: Long = 0
    var id = -1
    var pauseBefore: Int = 0
    var pauseTime: Int = 1000
    var pauseMarkers: List<String> = emptyList()
    var endpointOverride: String? = null
    var montoyaReq: HttpRequestResponse? = null
    var autoFixContentLength: Boolean = true
    var kettled: Boolean = false
    var anomalyRank: Int? = null

    // Computed lazily by whichever thread reads first (worker, GUI, MCP), so a concurrent map.
    private val attributes = ConcurrentHashMap<String, Any>()

    val code: Int get() = getAttribute("code") as Int
    val status: Int get() = code
    val length: Int get() = getAttribute("length") as Int
    val wordcount: Int get() = getAttribute("wordcount") as Int

    fun invokeCallback(isinteresting: Boolean) {
        if (callback != null) {
            callback!!.invoke(this, isinteresting)
        }
        else {
            throw IllegalStateException("Request has no callback set")
        }
    }

    fun getAttribute(name: String): Any? {
        return attributes.getOrPut(name) {
            when(name) {
                "length" -> response?.length ?: 0
                "wordcount" -> countWords(response ?: "")
                "code" -> calculateCode()
                else -> "Unknown attribute"
            }
        }
    }

    fun materializeAttributes() {
        getAttribute("code")
        getAttribute("length")
        getAttribute("wordcount")
    }

    /** Drops the body (and the Montoya copy of it), keeping what was computed from it. */
    internal fun dropResponseBody() {
        materializeAttributes()
        response = null
        montoyaReq = null
    }

    fun stripResponseBody() {
        dropResponseBody()
        engine = null
        callback = null
        gate = null
    }

    fun calculateCode(): Int {
        val current = response ?: return 0
        try {
            if(current.startsWith(":status")) {
                return Integer.parseInt(current.split(" ", "\r", "\n", limit=3).get(1))
            }

            return Integer.parseInt(current.split(" ", ignoreCase = false, limit = 3).get(1))
        } catch (e: Exception) {
            return 0
        }
    }

    constructor(template: String): this(template, emptyList<String>(), 0, "")
    constructor(template: String, words: List<String?>): this(template, words, 0, "")
    constructor(template: String, words: List<String?>, learnBoring: Int): this(template, words, learnBoring, "")

    /** Montoya service for [targetUrl]. */
    fun getHttpService(): HttpService {
        val url = targetUrl!!
        return HttpService.httpService(url.host, getEffectivePort(url), url.protocol == "https")
    }

    fun getMontoyaRequest(): HttpRequestResponse? {
        montoyaReq?.let {
            return montoyaReq
        }
        val resp = response
        if (resp == null || !(resp.startsWith("HTTP/") || resp.startsWith(":status"))) {
            return null
        }
        return HttpRequestResponse.httpRequestResponse(
            HttpRequest.httpRequest(getHttpService(), MontoyaBytes.byteArray(*getRequestAsBytes())),
            HttpResponse.httpResponse(MontoyaBytes.byteArray(*Utils.stringToBytes(resp)))
        )
    }

    fun getRequest(): String {
        if (words.isEmpty()) {
            return fixContentLength(template)
        }

        if (!template.contains("%s")) {
            Utils.out("Bad base request - nowhere to inject payload")
        }

        var req = template

        for (w in words){
            req = req.replaceFirst("%s", w.toString(), false)
        }

        if (req.contains("%s")) {

            Utils.out("Bad base request ${words.size} words and more %s")
        }

        return fixContentLength(req)
    }

    fun getRequestAsBytes(): ByteArray {
        return fixContentLength(Utils.stringToBytes(getRequest()))
    }

    fun getResponseAsBytes(): ByteArray? {
        val current = response ?: return "null".toByteArray()
        return Utils.stringToBytes(current)
    }

    // todo fix performance
    fun fixContentLength(request: String): String {
        // ISO-8859-1 both ways: each char is one byte. The default charset turned 0x80-0xFF into U+FFFD.
        return Utils.bytesToString(fixContentLength(Utils.stringToBytes(request)))
    }

    fun fixContentLength(request: ByteArray): ByteArray {
        if (!autoFixContentLength) {
            return request
        }

        // No blank line after the headers means no body to measure; such a request is usually
        // deliberately unfinished, so it goes out as written.
        val bodyStart = Utils.findBodyStart(request)
        if (bodyStart < 0) {
            return request
        }
        return try {
            setHeader(request, "Content-Length", (request.size - bodyStart).toString())
        } catch (e: RuntimeException) {
            request
        }
    }

    fun setHeader(request: ByteArray, header: String, value: String): ByteArray {
        val offsets = getHeaderOffsets(request, header)
        val outputStream = ByteArrayOutputStream()
        try {
            outputStream.write(Arrays.copyOfRange(request, 0, offsets[1]))
            outputStream.write(value.toByteArray(Charsets.ISO_8859_1))
            outputStream.write(Arrays.copyOfRange(request, offsets[2], request.size))
            return outputStream.toByteArray()
        } catch (e: IOException) {
            throw RuntimeException("Request creation unexpectedly failed")
        } catch (e: NullPointerException) {
            Utils.out("header locating fail: $header")
            throw RuntimeException("Can't find the header")
        }

    }

    /**
     * Offsets of [header] in the headers of [request]: where its line starts, where its value
     * starts, and where the value ends (before the line ending). The name must start the line and
     * match exactly, case included: a deliberately odd header (` Content-Length`, `content-length`)
     * is left alone. The value follows `name:` and at most one space.
     */
    fun getHeaderOffsets(request: ByteArray, header: String): IntArray {
        val name = Utils.stringToBytes(header)
        val headersEnd = Utils.findBodyStart(request).let { if (it < 0) request.size else it }
        // The first line is the request line.
        var lineStart = indexOfByte(request, LF, 0, headersEnd) + 1
        while (lineStart in 1 until headersEnd) {
            val lineEnd = indexOfByte(request, LF, lineStart, headersEnd).let { if (it < 0) headersEnd else it }
            val valueEnd = if (lineEnd > lineStart && request[lineEnd - 1] == CR) lineEnd - 1 else lineEnd
            val colon = lineStart + name.size
            if (colon < valueEnd && request[colon] == COLON && startsWithAt(request, lineStart, name)) {
                val valueStart = if (colon + 1 < valueEnd && request[colon + 1] == SPACE) colon + 2 else colon + 1
                return intArrayOf(lineStart, valueStart, valueEnd)
            }
            lineStart = lineEnd + 1
        }
        throw RuntimeException("Couldn't find header: '$header'")
    }

    private companion object {
        const val LF = '\n'.code.toByte()
        const val CR = '\r'.code.toByte()
        const val COLON = ':'.code.toByte()
        const val SPACE = ' '.code.toByte()

        fun indexOfByte(bytes: ByteArray, value: Byte, from: Int, to: Int): Int {
            for (i in from until to) {
                if (bytes[i] == value) return i
            }
            return -1
        }

        fun startsWithAt(bytes: ByteArray, at: Int, prefix: ByteArray): Boolean {
            if (at + prefix.size > bytes.size) return false
            for (i in prefix.indices) {
                if (bytes[at + i] != prefix[i]) return false
            }
            return true
        }

        /** Same count as `split(Regex("[^a-zA-Z0-9]")).size`, without building the pieces. */
        fun countWords(text: String): Int {
            var count = 1
            var i = 0
            while (i < text.length) {
                val codePoint = text.codePointAt(i)
                val alphanumeric = codePoint in 'a'.code..'z'.code ||
                    codePoint in 'A'.code..'Z'.code ||
                    codePoint in '0'.code..'9'.code
                if (!alphanumeric) count++
                i += Character.charCount(codePoint)
            }
            return count
        }
    }
}
