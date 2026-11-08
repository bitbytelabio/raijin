package io.bitbytelab.raijin.turbo

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.scanner.scancheck.ScanCheckType
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse
import burp.api.montoya.ui.hotkey.HotKey
import burp.api.montoya.ui.hotkey.HotKeyContext
import burp.api.montoya.ui.hotkey.HotKeyEvent
import burp.api.montoya.ui.hotkey.HotKeyHandler
import io.bitbytelab.raijin.turbo.mcp.RunManager
import kotlin.jvm.optionals.getOrNull

/**
 * Wires the Turbo engine into Burp: settings panel, context menus, hotkey and the passive
 * word-recording check. Called once by the Raijin extension entry point.
 */
object TurboModule {

    /** Shared by the GUI and the MCP tools so both see the same runs. */
    val runManager: RunManager by lazy { RunManager() }

    private val registrations = mutableListOf<Registration>()

    fun install(api: MontoyaApi) {
        Utils.init(api)
        TurboSettings.register(api)

        val ui = api.userInterface()
        registrations += ui.registerContextMenuItemsProvider(OfferTurboIntruder())
        registrations += ui.registerContextMenuItemsProvider(BulkMenu())
        registrations += ui.registerContextMenuItemsProvider(OfferTurboIntruderWithScript())
        registerHotkey(api)

        try {
            registrations += api.scanner().registerPassiveScanCheck(Utils.witnessedWords, ScanCheckType.PER_REQUEST)
        } catch (e: Exception) {
            // Community Edition has no scanner
            Utils.out("Raijin Turbo: word recording unavailable (${e.message})")
        }
        Utils.out("Raijin Turbo v${Info.version} loaded")
    }

    fun uninstall() {
        runManager.stopMemoryMonitor()
        registrations.forEach { runCatching { it.deregister() } }
        registrations.clear()
        TurboSettings.unregister()
        Utils.shutdown()
    }

    /** Opens the script dialog on an empty example request (no message selected). */
    fun openBlankDialog() {
        val raw = Scripts.DEFAULT_RAW_REQUEST.toByteArray(Charsets.ISO_8859_1)
        val service = TurboService("example.com", 443, true).toMontoya()
        val target = HttpRequestResponse.httpRequestResponse(
            HttpRequest.httpRequest(service, burp.api.montoya.core.ByteArray.byteArray(*raw)),
            HttpResponse.httpResponse()
        )
        TurboIntruderFrame(target, IntArray(0), Scripts.SAMPLEBURPSCRIPT, raw, null).actionPerformed(null)
    }

    private fun registerHotkey(api: MontoyaApi) {
        try {
            val hotKey = HotKey.hotKey("Send to Raijin Turbo", "Ctrl+Alt+T")
            val handler = HotKeyHandler { event: HotKeyEvent ->
                event.messageEditorRequestResponse().ifPresent { editor: MessageEditorHttpRequestResponse ->
                    val offsets = editor.selectionOffsets().getOrNull()
                    val bounds = if (offsets != null) intArrayOf(offsets.startIndexInclusive(), offsets.endIndexExclusive()) else intArrayOf()
                    TurboIntruderFrame(editor.requestResponse(), bounds, null, null, null).actionPerformed(null)
                }
            }
            registrations += api.userInterface().registerHotKeyHandler(HotKeyContext.HTTP_MESSAGE_EDITOR, hotKey, handler)
        } catch (e: NoSuchMethodError) {
            Utils.out("Raijin Turbo: hotkey needs a newer Burp")
        }
    }
}
