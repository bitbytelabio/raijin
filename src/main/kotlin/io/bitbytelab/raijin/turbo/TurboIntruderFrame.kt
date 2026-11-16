package io.bitbytelab.raijin.turbo

import burp.api.montoya.core.ByteArray as MontoyaBytes
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.ui.Theme
import io.bitbytelab.raijin.ui.RaijinTheme
import org.fife.ui.rsyntaxtextarea.*
import org.fife.ui.rtextarea.*
import org.fife.rsta.ui.search.FindDialog
import org.fife.rsta.ui.search.SearchListener
import org.fife.rsta.ui.search.SearchEvent
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
import java.util.concurrent.ConcurrentHashMap
import javax.swing.*
import kotlin.concurrent.thread


class RecordResize: ComponentAdapter() {
    override fun componentResized(e: ComponentEvent?) {
        super.componentResized(e)
        e?.component?.size?.let { Utils.setTurboSize(it) }
    }

}

class TurboIntruderFrame(inputReq: HttpRequestResponse, val selectionBounds: IntArray, val fixedScript: String?, val requestOverride: ByteArray?, val reqs: MutableList<HttpRequestResponse>?): ActionListener, JDialog(findBurpFrame(), "Raijin Turbo - " + inputReq.request().httpService().host())  {

    companion object {
        /** Dialogs currently on screen, so extension unload can close them (and stop their runs and timers). */
        private val openDialogs: MutableSet<TurboIntruderFrame> = ConcurrentHashMap.newKeySet()

        // Owned by Burp's main frame so the editor window follows Burp's monitor and window
        // lifecycle instead of appearing wherever the OS puts a standalone frame. Null when Burp's
        // frame cannot be found — JDialog then falls back to a shared hidden owner.
        private fun findBurpFrame(): Frame? {
            return Frame.getFrames().firstOrNull { it.isVisible && it.title.startsWith("Burp Suite") }
        }

        /**
         * Closes every open script dialog. Each dialog's close handler aborts its run and stops its
         * result table's timers. Call on extension unload; safe from any thread.
         */
        fun closeAll() {
            val close = { openDialogs.toList().forEach { it.dispose() } }
            if (SwingUtilities.isEventDispatchThread()) close() else SwingUtilities.invokeLater(close)
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
          try {
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

            // Burp's theming (applied to the whole dialog below) resets the editor's colours, so the
            // matching RSyntaxTextArea scheme is applied after it.
            fun applyEditorTheme() {
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
            }
            applyEditorTheme()

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
            val initialService = TurboService.fromMontoya(req.request().httpService())
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
                messageEditor.request = HttpRequest.httpRequest(req.request().httpService(), MontoyaBytes.byteArray(*bytes))
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

            // Run state. Only touched on the EDT: ToggleRun reads every Swing input and swaps the UI
            // there, and hands the slow parts (aborting an engine, running the script) to a worker.
            var handler = RunHandler()
            var resultStore: ResultStore? = null
            var requestTable: RequestTable? = null

            class ToggleRun(): ActionListener {
                override fun actionPerformed(e: ActionEvent?) {
                    when (button.text) {
                        "Halt" -> {
                            val running = handler
                            thread(name = "raijin-turbo-halt") {
                                running.abort()
                                SwingUtilities.invokeLater { button.text = "Configure" }
                            }
                        }
                        "Configure" -> {
                            val finished = handler
                            val rt = requestTable
                            val rs = resultStore
                            handler = RunHandler()
                            resultStore = null
                            requestTable = null
                            rt?.dispose()
                            rt?.clear()
                            panel.add(button, BorderLayout.SOUTH)
                            pane.bottomComponent = panel
                            pane.setDividerLocation(0.25)
                            button.text = "Run"
                            button.requestFocusInWindow()
                            pane.rootPane.defaultButton = button
                            title = "Raijin Turbo - " + req.request().httpService().host()
                            thread(name = "raijin-turbo-reset") {
                                finished.abort()
                                rs?.clear()
                            }
                        }
                        else -> {
                            val inputHost = hostField.text.trim().ifEmpty { initialService.host }
                            val inputPort = portField.text.trim().toIntOrNull() ?: initialService.port
                            val inputProtocol = (protocolCombo.selectedItem?.toString() ?: (if (initialService.secure) "https" else "http")).lowercase()
                            val newService = TurboService(inputHost, inputPort, inputProtocol == "https")
                            val editedScript = textEditor.text
                            val messageBytes = currentMessage()
                            val runInput = baseInput

                            val runHandler = handler
                            val localStore = ResultStore()
                            resultStore = localStore
                            TurboModule.runManager.adopt(runHandler, localStore, "GUI")
                            val localTable = RequestTable(localStore, newService, runHandler)
                            requestTable = localTable
                            button.text = "Halt"
                            val requestPanel = JPanel(BorderLayout())
                            panel.remove(button)
                            requestPanel.add(localTable, BorderLayout.CENTER)
                            requestPanel.add(button, BorderLayout.SOUTH)
                            pane.bottomComponent = requestPanel
                            button.requestFocusInWindow()
                            pane.rootPane.defaultButton = button
                            title = "Raijin Turbo - $inputHost - running"

                            thread(name = "raijin-turbo-run") {
                                Utils.setPreference("turbo.defaultScript", editedScript)
                                val baseRequest = Utils.bytesToString(messageBytes)
                                val target = turboEndpoint(inputProtocol, inputHost, inputPort)
                                evalJython(normalizeScriptNewlines(editedScript), baseRequest, messageBytes, target, inputHost, runInput, localStore, runHandler, reqs, localTable)
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
                    e.window.dispose()
                }

                // Fires for the close button and for closeAll() alike.
                override fun windowClosed(e: WindowEvent) {
                    openDialogs.remove(this@TurboIntruderFrame)
                    val running = handler
                    requestTable?.dispose()
                    requestTable?.clear()
                    thread(name = "raijin-turbo-close") { running.abort() }
                }
            })

            SwingUtilities.invokeLater {
                add(pane)
                RaijinTheme.apply(this)
                applyEditorTheme()
                pane.rootPane.defaultButton = button
                pack()
                setLocationRelativeTo(getBurpFrame())
                openDialogs.add(this)
                isVisible = true
                button.requestFocus()
                button.requestFocusInWindow()
            }
          } catch (t: Throwable) {
            Utils.out("Raijin Turbo: failed to open script dialog: " + errorToStacktrace(Exception(t)))
            JOptionPane.showMessageDialog(null, "Could not open the Turbo script dialog: $t", "Raijin Turbo", JOptionPane.ERROR_MESSAGE)
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
                userScriptItems(File(scriptsPath)).forEach { codeCombo.addItem(it) }
            }
            codeCombo.addItem( JSeparator(JSeparator.HORIZONTAL))
            exampleScriptNames(ReadFromJar().getFiles("examples")).forEach { codeCombo.addItem(it) }
        } catch (e: NoSuchFileException) {
            System.err.println("Error file not found:"+e)
        } catch (e: IOException) {
            System.err.println("Error:"+e)
        }
    }
}
