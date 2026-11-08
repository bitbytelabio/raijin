package io.bitbytelab.raijin.turbo

import burp.api.montoya.core.ByteArray as MontoyaBytes
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.Theme
import org.fife.ui.rsyntaxtextarea.*
import org.fife.ui.rtextarea.*
import org.fife.rsta.ui.search.FindDialog
import org.fife.rsta.ui.search.SearchListener
import org.fife.rsta.ui.search.SearchEvent
import org.python.util.PythonInterpreter
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.Frame
import java.awt.GridBagLayout
import java.awt.GridBagConstraints
import java.awt.Insets
import java.awt.FlowLayout
import java.awt.event.*
import java.io.*
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Paths
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.swing.*
import kotlin.concurrent.thread


class Scripts() {
    companion object {
        val SCRIPTENVIRONMENT = Scripts::class.java.getResource("/ScriptEnvironment.py").readText()
        val SAMPLEBURPSCRIPT = Scripts::class.java.getResource("/examples/default.py").readText()

         val DEFAULT_RAW_REQUEST: String = listOf(
            "GET / HTTP/1.1",
            "Host: example.com",
            "Cache-Control: max-age=0",
            "Sec-Ch-Ua: \"Google Chrome\";v=\"139\", \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"139\"",
            "Sec-Ch-Ua-Mobile: ?0",
            "Sec-Ch-Ua-Platform: \"macOS\"",
            "Accept-Language: en-US;q=0.9,en;q=0.8",
            "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Sec-Fetch-Site: none",
            "Sec-Fetch-Mode: navigate",
            "Sec-Fetch-User: ?1",
            "Sec-Fetch-Dest: document",
            "Accept-Encoding: gzip, deflate, br",
            "Connection: close",
            "",
            ""
        ).joinToString("\r\n")
    }
}


class Target(val req: String, val rawreq: ByteArray, val endpoint: String, val baseInput: String)

class Wordlist(val bruteforce: Bruteforce, val observedWords: MutableSet<String>, val clipboard: ArrayList<String>)

fun evalJython(code: String, baseRequest: String, rawRequest: ByteArray, endpoint: String, host: String, baseInput: String, store: ResultStore, handler: RunHandler, reqs: MutableList<HttpRequestResponse>?, requestTable: RequestTable?) {
    val pyInterp = PythonInterpreter() // todo add path to bs4
    try {
        Utils.out("Starting run...")
        handler.code = code
        handler.baseRequest = baseRequest
        handler.rawRequest = rawRequest
        pyInterp.set("target", Target(baseRequest, rawRequest, endpoint, baseInput))
        val savedWords = Utils.witnessedWords.savedWords
        if (savedWords.isEmpty()) {
            savedWords.add("To use this wordlist, enable 'learn observed words'")
        }
        pyInterp.set("wordlists", Wordlist(Bruteforce(), Utils.witnessedWords.savedWords, Utils.getClipboard()))
        pyInterp.set("turboTypes", TurboPython.types())
        pyInterp.exec("class _TurboNamespace(object):\n    pass\nturbo = _TurboNamespace()\nfor _n, _t in turboTypes.items():\n    setattr(turbo, _n, _t)\ndel _n, _t")
        pyInterp.set("handler", handler)
        pyInterp.set("outputHandler", store)
        pyInterp.set("table", store)
        pyInterp.set("store", store)
        pyInterp.set("requestTable", requestTable)
        pyInterp.set("requests", reqs)
        pyInterp.set("host", host)
        pyInterp.set("desyncAgentMode", TurboSettings.desyncAgent)
        if (Utils.gotBurp) {
            pyInterp.set("api", Utils.montoyaApi)
            pyInterp.setOut(Utils.outputStream())
            pyInterp.setErr(Utils.errorStream())
        }
        pyInterp.exec(Scripts.SCRIPTENVIRONMENT)
        pyInterp.exec(code)
        pyInterp.exec("queueRequests(target, wordlists)")
        handler.setComplete()
        pyInterp.exec("completed(store.getAllRquests())".trimMargin())
    }
    catch (ex: Exception) {
        var error = ex
        var stackTrace = errorToStacktrace(error)
        if (stackTrace.contains("Cannot queue any more items - the run has finished")) {
            Utils.out("Run aborted with items waiting to be queued.")
            try {
                pyInterp.exec("completed(store.getAllRquests())".trimMargin())
                handler.abort()
                return
            } catch (ex2: Exception) {
                error = ex2
                stackTrace = errorToStacktrace(ex2)
            }
        }

        var message = error.cause?.message
        if (message == null) {
            message = error.toString()
        }
        handler.overrideStatus("User Python error, check extender for full details: $message")
        Utils.out("There was an error executing your Python script. This is probably due to a flaw in your script, rather than a bug in Raijin Turbo :)")
        Utils.out("If you think it is a Raijin Turbo issue, try the 'debug' example script from the script picker.")
        Utils.out("For your convenience, here's the full stack trace:")
        Utils.out(stackTrace)

        handler.abort()
    }
}


fun errorToStacktrace(ex: Exception): String {
    val stackTrace = StringWriter()
    ex.printStackTrace(PrintWriter(stackTrace))
    return stackTrace.toString()
}

class RecordResize: ComponentAdapter() {
    override fun componentResized(e: ComponentEvent?) {
        super.componentResized(e)
        e?.component?.size?.let { Utils.setTurboSize(it) }
    }

}

class TurboIntruderFrame(inputReq: HttpRequestResponse, val selectionBounds: IntArray, val fixedScript: String?, val requestOverride: ByteArray?, val reqs: MutableList<HttpRequestResponse>?): ActionListener, JDialog(findBurpFrame(), "Raijin Turbo - " + inputReq.httpService().host())  {

    private companion object {
        // Owned by Burp's main frame so the editor window follows Burp's monitor and window
        // lifecycle instead of appearing wherever the OS puts a standalone frame. Null when Burp's
        // frame cannot be found — JDialog then falls back to a shared hidden owner.
        fun findBurpFrame(): Frame? {
            return Frame.getFrames().firstOrNull { it.isVisible && it.title.startsWith("Burp Suite") }
        }
    }

    val req = inputReq
    private val reqBytes: ByteArray = inputReq.request().toByteArray().bytes

    private fun getDefaultScript(): String {
        if (fixedScript != null) {
            return fixedScript
        }
        val defaultScript = Utils.getPreference("turbo.defaultScript")
        if (defaultScript == null) {
            return Scripts.SAMPLEBURPSCRIPT
        } else {
            return defaultScript
        }
    }

    override fun actionPerformed(e: ActionEvent?) {
        SwingUtilities.invokeLater {
            val pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            pane.setDividerLocation(0.25)
            pane.addComponentListener(RecordResize())

            val panel = JPanel(BorderLayout())
            val codeCombo = JComboBox<Any>()
            codeCombo.renderer = ComboBoxRenderer(10)
            val loadDirectoryButton = JButton("Choose scripts dir")
            loadDirectoryButton.addActionListener {
                val directoryChooser = JFileChooser()
                directoryChooser.fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
                val option = directoryChooser.showOpenDialog(this)
                if (option == JFileChooser.APPROVE_OPTION) {
                    val file = directoryChooser.selectedFile
                    Utils.setPreference("turbo.scriptsPath", file.absolutePath)
                    readScriptDirectories(codeCombo)
                }
            }
            //val textEditor = Utils.callbacks.createTextEditor()
            //
            // https://github.com/bobbylight/RSyntaxTextArea/issues/269
            javax.swing.text.JTextComponent.removeKeymap("RTextAreaKeymap")
            javax.swing.UIManager.put("RTextAreaUI.inputMap", null)
            javax.swing.UIManager.put("RTextAreaUI.actionMap", null)
            javax.swing.UIManager.put("RSyntaxTextAreaUI.inputMap", null)
            javax.swing.UIManager.put("RSyntaxTextAreaUI.actionMap", null)
            val textEditor = RSyntaxTextArea(20, 60)


            textEditor.isEditable = true
            textEditor.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_PYTHON)
            textEditor.antiAliasingEnabled = true
            textEditor.isAutoIndentEnabled = true
            textEditor.paintTabLines = false
            textEditor.tabSize = 4
            textEditor.tabsEmulated = true
            textEditor.eolMarkersVisible = TurboSettings.showEol
            textEditor.isWhitespaceVisible = TurboSettings.visibleWhitespace

            val dark = Utils.montoyaApi?.userInterface()?.currentTheme() == Theme.DARK
            val themeFile = if (dark) "dark.xml" else "default.xml"
            try {
                javaClass.getResourceAsStream("/org/fife/ui/rsyntaxtextarea/themes/$themeFile")?.use {
                    org.fife.ui.rsyntaxtextarea.Theme.load(it).apply(textEditor)
                }
            } catch (ioe: IOException) {
                Utils.out(ioe.toString())
            }
            if (!dark) textEditor.highlightCurrentLine = false

            val editorFont = Utils.montoyaApi?.userInterface()?.currentEditorFont() ?: textEditor.font
            textEditor.font = editorFont.deriveFont(TurboSettings.fontSize.toFloat())

            //val scrollableTextEditor = JScrollPane(textEditor)
            val scrollableTextEditor = RTextScrollPane(textEditor)
            scrollableTextEditor.lineNumbersEnabled = TurboSettings.lineNumbers

            // Add Ctrl+F search functionality using RSyntaxTextArea's built-in FindDialog
            val searchListener = object : SearchListener {
                override fun searchEvent(e: SearchEvent) {
                    val context = e.searchContext
                    val result = SearchEngine.find(textEditor, context)
                    if (!result.wasFound() && context.searchForward) {
                        // Wrap around
                        textEditor.caretPosition = 0
                        SearchEngine.find(textEditor, context)
                    } else if (!result.wasFound() && !context.searchForward) {
                        // Wrap around backwards
                        textEditor.caretPosition = textEditor.text.length
                        SearchEngine.find(textEditor, context)
                    }
                }
                
                override fun getSelectedText(): String {
                    return textEditor.selectedText ?: ""
                }
            }
            
            val findDialog = FindDialog(this@TurboIntruderFrame, searchListener)
            
            textEditor.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
                KeyStroke.getKeyStroke("control F"), "find"
            )
            textEditor.actionMap.put("find", object : AbstractAction() {
                override fun actionPerformed(e: ActionEvent) {
                    if (!findDialog.isVisible) {
                        findDialog.isVisible = true
                    } else {
                        findDialog.toFront()
                    }
                }
            })

            val saveButton = JButton("Save")
            saveButton.isEnabled = false
            saveButton.addActionListener {
                val comboItem = codeCombo.getSelectedItem();
                if(comboItem is DirectoryItem) {
                    try {
                        Files.write( Paths.get(comboItem.fullPath), textEditor.text.toByteArray());

                    } catch (e: IOException) {
                        System.err.println("Failed to write file:$e")
                    }
                }
            }
            val topPanel = JPanel(BorderLayout())

            // Host/Port/Protocol controls
            val initialService = TurboService.fromMontoya(req.httpService())
            val hostField = JTextField(initialService.host, 16)
            val portField = JTextField(initialService.port.toString(), 5)
            val protocolCombo = JComboBox(arrayOf("http", "https"))
            protocolCombo.selectedItem = if (initialService.secure) "https" else "http"

            val leftPanel = JPanel(FlowLayout(FlowLayout.LEFT))
            leftPanel.add(JLabel("Host:"))
            leftPanel.add(hostField)
            leftPanel.add(JLabel("Port:"))
            leftPanel.add(portField)
            leftPanel.add(JLabel("Protocol:"))
            leftPanel.add(protocolCombo)

            val rightPanel = JPanel(GridBagLayout())
            val gbc = GridBagConstraints()
            gbc.insets = Insets(0, 4, 0, 0)
            gbc.gridy = 0
            gbc.gridx = 0
            gbc.weightx = 1.0
            gbc.fill = GridBagConstraints.HORIZONTAL
            rightPanel.add(codeCombo, gbc)

            gbc.gridx = 1
            gbc.weightx = 0.0
            gbc.fill = GridBagConstraints.NONE
            rightPanel.add(loadDirectoryButton, gbc)

            gbc.gridx = 2
            rightPanel.add(saveButton, gbc)

            topPanel.add(leftPanel, BorderLayout.WEST)
            topPanel.add(rightPanel, BorderLayout.CENTER)
            panel.add(topPanel, BorderLayout.NORTH);
            panel.add(scrollableTextEditor, BorderLayout.CENTER)
            val api = Utils.montoyaApi!!
            val messageEditor = api.userInterface().createHttpRequestEditor()
            fun setMessage(bytes: ByteArray) {
                messageEditor.request = HttpRequest.httpRequest(req.httpService(), MontoyaBytes.byteArray(*bytes))
            }
            fun currentMessage(): ByteArray = messageEditor.request.toByteArray().bytes

            var baseInput = ""

            if (fixedScript != null) {
                setMessage(requestOverride ?: reqBytes)
            }
            else {
                if (selectionBounds.isNotEmpty() && selectionBounds[0] != selectionBounds[1]) {
                    setMessage(reqBytes.copyOfRange(0, selectionBounds[0]) + ("%s".toByteArray()) + reqBytes.copyOfRange(selectionBounds[1], reqBytes.size))
                    baseInput = String(reqBytes.copyOfRange(selectionBounds[0], selectionBounds[1]), Charsets.ISO_8859_1)
                } else {
                    setMessage(reqBytes)
                }
            }
            textEditor.text = getDefaultScript()
            textEditor.setEditable(true)

            codeCombo.addActionListener {
                if(codeCombo.itemCount > 0 && !(codeCombo.getSelectedItem() is JSeparator)) {
                    if (codeCombo.selectedIndex == 0) {
                        saveButton.isEnabled = false;
                        textEditor.text = getDefaultScript()
                    } else {
                        val fileName = codeCombo.getSelectedItem().toString()
                        if (fileName.startsWith("examples/")) {
                            textEditor.text = Scripts::class.java.getResource("/" + fileName).readText()
                            saveButton.isEnabled = false;
                        } else {
                            saveButton.isEnabled = true;
                            val comboItem = codeCombo.getSelectedItem();
                            if(comboItem is DirectoryItem) {
                                textEditor.text = String(Files.readAllBytes(Paths.get(comboItem.fullPath)));
                            } else {
                                textEditor.text = String(Files.readAllBytes(Paths.get(fileName)));
                            }
                        }
                    }
                }
            }
            readScriptDirectories(codeCombo)
            pane.topComponent = messageEditor.uiComponent()
            pane.bottomComponent = panel


            val button = JButton("Run")
            panel.add(button, BorderLayout.SOUTH)

            val turboSize = Utils.getTurboSize()
            messageEditor.uiComponent().preferredSize = Dimension(turboSize.width, 200)
            panel.preferredSize = Dimension(turboSize.width, turboSize.height-200)

            var handler = RunHandler()
            var resultStore: ResultStore? = null
            var requestTable: RequestTable? = null

            class ToggleRun(): ActionListener {
                override fun actionPerformed(e: ActionEvent?) {
                    thread {
                        when {
                            button.text == "Halt" -> {
                                handler.abort()
                                button.text = "Configure"
                            }
                            button.text == "Configure" -> {
                                handler.abort()
                                requestTable?.clear()
                                resultStore?.clear()
                                handler = RunHandler()
                                resultStore = null
                                requestTable = null
                                SwingUtilities.invokeLater {
                                    panel.add(button, BorderLayout.SOUTH)
                                    pane.bottomComponent = panel
                                    pane.setDividerLocation(0.25)
                                    button.text = "Run"
                                    button.requestFocusInWindow()
                                    pane.rootPane.defaultButton = button
                                    title = "Raijin Turbo - " + req.httpService().host()
                                }
                            }
                            else -> {
                                // Build service/target from UI inputs
                                val inputHost = hostField.text.trim().ifEmpty { initialService.host }
                                val inputPort = try { portField.text.trim().toInt() } catch (ex: Exception) { initialService.port }
                                val inputProtocol = (protocolCombo.selectedItem?.toString() ?: (if (initialService.secure) "https" else "http")).lowercase()
                                val newService = TurboService(inputHost, inputPort, inputProtocol == "https")

                                resultStore = ResultStore()
                                TurboModule.runManager.adopt(handler, resultStore!!, "GUI")
                                requestTable = RequestTable(resultStore!!, newService, handler)
                                SwingUtilities.invokeLater {
                                    button.text = "Halt"
                                    val requestPanel = JPanel(BorderLayout())
                                    panel.remove(button)
                                    requestPanel.add(requestTable, BorderLayout.CENTER)
                                    requestPanel.add(button, BorderLayout.SOUTH)
                                    pane.bottomComponent = requestPanel
                                    button.requestFocusInWindow()
                                    pane.rootPane.defaultButton = button
                                    title = "Raijin Turbo - " + inputHost
                                }
                                var script = textEditor.text

                                Utils.setPreference("turbo.defaultScript", script)

                                val messageBytes = currentMessage()
                                val baseRequest = Utils.bytesToString(messageBytes)

                                val target: String
                                if (inputHost.contains(":")) {
                                    target = inputProtocol + "://[" + inputHost + "]:" + inputPort
                                }
                                else {
                                    target = inputProtocol + "://" + inputHost + ":" + inputPort
                                }

                                // enforce /r/n line endings
                                script = script.replace("\r\n", "\n")
                                script = script.replace("\n", "\r\n")
                                title += " - running"
                                evalJython(script, baseRequest, messageBytes, target, inputHost, baseInput, resultStore!!, handler, reqs, requestTable)
                            }
                        }
                    }
                }
            }
            button.addActionListener(ToggleRun())

            button.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
                KeyStroke.getKeyStroke(
                    "control ENTER"
                ), "toggleRun"
            )

            button.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
                KeyStroke.getKeyStroke(
                    "control SPACE"
                ), "toggleRun"
            )

            button.getActionMap().put("toggleRun", object : AbstractAction() {
                override fun actionPerformed(e: ActionEvent) {
                    ToggleRun().actionPerformed(e)
                }
            })


            this.addWindowListener(object : WindowAdapter() {
                override fun windowClosing(e: WindowEvent) {
                    handler.abort()
                    requestTable?.clear()
                    e.window.dispose()
                }
            })

            SwingUtilities.invokeLater {
                add(pane)
                pane.rootPane.defaultButton = button
                pack()
                setLocationRelativeTo(getBurpFrame())
                isVisible = true
                button.requestFocus()
                button.requestFocusInWindow()
            }
        }
    }

    fun getBurpFrame(): Frame? {
        return findBurpFrame()
    }
    fun readScriptDirectories( codeCombo : JComboBox<Any>) {
        codeCombo.removeAllItems()
        codeCombo.addItem("Last code used")
        try {
            val scriptsPath = Utils.getPreference("turbo.scriptsPath")
            if (!scriptsPath.isNullOrEmpty()) {
                val folder = File(scriptsPath)
                if (folder.isDirectory) {
                    val folderList = folder.listFiles();
                    Arrays.sort(folderList);
                    for (fileEntry in folderList) {
                        if (!fileEntry.name.startsWith(".")) {
                            codeCombo.addItem(DirectoryItem(folder.absolutePath + "/" + fileEntry.name, fileEntry.name))
                        }
                    }
                }
            }
            codeCombo.addItem( JSeparator(JSeparator.HORIZONTAL))
            val readJar = ReadFromJar()
            val exampleFiles = readJar.getFiles("examples")
            exampleFiles.sort()
            for (fileName in exampleFiles) {
                if (fileName.startsWith(".") || fileName.endsWith("__init__.py")) {
                    continue
                }
                codeCombo.addItem(fileName)
            }
        } catch (e: NoSuchFileException) {
            System.err.println("Error file not found:"+e)
        } catch (e: IOException) {
            System.err.println("Error:"+e)
        }
    }
}


class Args(args: Array<String>) {

    companion object {
        lateinit var args: Array<String>
    }

    init {
        Companion.args = args
    }
}
