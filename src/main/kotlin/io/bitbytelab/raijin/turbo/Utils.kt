package io.bitbytelab.raijin.turbo

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import java.awt.Dimension
import java.awt.Toolkit
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.StringSelection
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * Process-wide Turbo state and byte helpers. Members are @JvmStatic because the Jython
 * script environment calls some of them (e.g. `Utils.isBurpProfessional()`).
 *
 * Montoya-only: [gotBurp] is true once [init] has run inside Burp. In unit tests it stays
 * false and every Burp-backed feature is skipped.
 */
object Utils {

    @JvmStatic @Volatile var montoyaApi: MontoyaApi? = null
        private set

    /** True when running inside Burp (Montoya initialised). */
    @JvmStatic @Volatile var gotBurp: Boolean = false
        private set

    @JvmStatic @Volatile var unloaded: Boolean = false

    @JvmStatic val witnessedWords = WordRecorder()

    /** Engines that must be told to stop when the extension unloads. */
    private val liveEngines: MutableSet<RequestEngine> = ConcurrentHashMap.newKeySet()

    private const val PREF_TURBO_HEIGHT = "turbo.window.height"
    private const val PREF_TURBO_WIDTH = "turbo.window.width"

    @JvmStatic
    fun init(api: MontoyaApi) {
        montoyaApi = api
        gotBurp = true
        unloaded = false
    }

    /** Called from the extension unloading handler. */
    @JvmStatic
    fun shutdown() {
        unloaded = true
        for (engine in liveEngines.toList()) {
            try { engine.extensionUnloaded() } catch (_: Exception) {}
        }
        liveEngines.clear()
        montoyaApi = null
        gotBurp = false
    }

    @JvmStatic fun registerEngine(engine: RequestEngine) { liveEngines.add(engine) }
    @JvmStatic fun unregisterEngine(engine: RequestEngine) { liveEngines.remove(engine) }

    // ---------------------------------------------------------------- logging

    @JvmStatic
    fun out(message: String) {
        val api = montoyaApi
        if (api != null) api.logging().logToOutput(message) else System.err.println(message)
    }

    @JvmStatic
    fun err(message: String) {
        val api = montoyaApi
        if (api != null) api.logging().logToError(message) else System.err.println(message)
    }

    /** Streams for the Jython interpreter's stdout/stderr. */
    @JvmStatic fun outputStream(): PrintStream = montoyaApi?.logging()?.output() ?: System.out
    @JvmStatic fun errorStream(): PrintStream = montoyaApi?.logging()?.error() ?: System.err

    // ---------------------------------------------------------------- preferences

    @JvmStatic
    fun getPreference(key: String): String? = try {
        montoyaApi?.persistence()?.preferences()?.getString(key)
    } catch (_: Exception) { null }

    @JvmStatic
    fun setPreference(key: String, value: String) {
        try { montoyaApi?.persistence()?.preferences()?.setString(key, value) } catch (_: Exception) {}
    }

    @JvmStatic
    fun setTurboSize(size: Dimension) {
        setPreference(PREF_TURBO_HEIGHT, size.height.toString())
        setPreference(PREF_TURBO_WIDTH, size.width.toString())
    }

    @JvmStatic
    fun getTurboSize(): Dimension = try {
        val height = getPreference(PREF_TURBO_HEIGHT)!!.toInt() - 20 // window chrome
        val width = getPreference(PREF_TURBO_WIDTH)!!.toInt()
        Dimension(width, height)
    } catch (_: Exception) {
        Dimension(1280, 800)
    }

    // ---------------------------------------------------------------- edition checks

    @JvmStatic
    fun isBurpProfessional(): Boolean = try {
        montoyaApi?.burpSuite()?.version()?.edition() == BurpSuiteEdition.PROFESSIONAL
    } catch (_: RuntimeException) {
        false
    }

    @JvmStatic fun requireBurpProfessional() = requireBurpProfessional("Engine.HTTP3")
    @JvmStatic fun requireAutoEngineAvailable() = requireBurpProfessional("Engine.AUTO")

    private fun requireBurpProfessional(feature: String) {
        require(isBurpProfessional()) { "$feature requires Burp Suite Professional" }
    }

    // ---------------------------------------------------------------- clipboard

    @JvmStatic
    fun getClipboard(): ArrayList<String> {
        var clipboard = ""
        try {
            clipboard = Toolkit.getDefaultToolkit().systemClipboard.getData(DataFlavor.stringFlavor) as String
        } catch (_: Exception) {
            err("failed to read from clipboard")
        }
        return ArrayList(clipboard.split(Regex("\\r?\\n")))
    }

    @JvmStatic
    fun setClipboard(contents: String) {
        val selection = StringSelection(contents)
        Toolkit.getDefaultToolkit().systemClipboard.setContents(selection, selection)
    }

    // ---------------------------------------------------------------- bytes & strings

    @JvmStatic fun bytesToString(bytes: ByteArray?): String =
        if (bytes == null) "" else String(bytes, Charsets.ISO_8859_1)

    @JvmStatic fun stringToBytes(string: String): ByteArray = string.toByteArray(StandardCharsets.ISO_8859_1)

    @JvmStatic
    fun getHeaders(request: String): String {
        val bodyStart = request.indexOf("\r\n\r\n")
        return if (bodyStart < 0) request else request.substring(0, bodyStart)
    }

    @JvmStatic
    fun getBodyBytes(response: ByteArray?): ByteArray? {
        if (response == null) return null
        return response.copyOfRange(getBodyStart(response), response.size)
    }

    @JvmStatic
    fun normalizeLineEndings(request: String): String =
        if (!request.contains("\r\n")) request.replace("\n", "\r\n") else request

    @JvmStatic fun getBodyStart(response: ByteArray): Int = indexOf(response, "\r\n\r\n".toByteArray()) + 4

    @JvmStatic
    fun indexOf(outer: ByteArray, inner: ByteArray): Int = indexOf(outer, inner, 0, outer.size)

    /** First index of [inner] in [outer] within [from, to), or -1. */
    @JvmStatic
    fun indexOf(outer: ByteArray, inner: ByteArray, from: Int, to: Int): Int {
        val end = minOf(to, outer.size) - inner.size
        var i = maxOf(from, 0)
        while (i <= end) {
            var j = 0
            while (j < inner.size && outer[i + j] == inner[j]) j++
            if (j == inner.size) return i
            i++
        }
        return -1
    }

    /** True if the request line ends with `HTTP/2` (Burp's convention for HTTP/2 requests). */
    @JvmStatic
    fun isHTTP2(request: ByteArray): Boolean {
        var i = 0
        while (i < request.size && request[i] != '\r'.code.toByte() && request[i] != '\n'.code.toByte()) i++
        if (i < 6) return false
        return String(request, i - 6, 6, Charsets.ISO_8859_1) == "HTTP/2"
    }

    /** Replace the first occurrence of [find] with [replace] (ISO-8859-1 byte semantics). */
    @JvmStatic
    fun replaceFirst(request: ByteArray, find: String, replace: String): ByteArray {
        val needle = stringToBytes(find)
        val idx = indexOf(request, needle)
        if (idx < 0) return request
        val replacement = stringToBytes(replace)
        val out = ByteArray(request.size - needle.size + replacement.size)
        System.arraycopy(request, 0, out, 0, idx)
        System.arraycopy(replacement, 0, out, idx, replacement.size)
        System.arraycopy(request, idx + needle.size, out, idx + replacement.size, request.size - idx - needle.size)
        return out
    }

    private val random = SecureRandom()
    private const val ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    @JvmStatic
    fun randomAlphanumeric(length: Int): String =
        String(CharArray(length) { ALPHANUMERIC[random.nextInt(ALPHANUMERIC.length)] })
}
