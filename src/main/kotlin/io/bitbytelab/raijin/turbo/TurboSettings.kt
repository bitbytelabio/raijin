package io.bitbytelab.raijin.turbo

import burp.api.montoya.MontoyaApi
import burp.api.montoya.ui.settings.SettingsPanelBuilder
import burp.api.montoya.ui.settings.SettingsPanelPersistence
import burp.api.montoya.ui.settings.SettingsPanelSetting.booleanSetting
import burp.api.montoya.ui.settings.SettingsPanelSetting.integerSetting
import burp.api.montoya.ui.settings.SettingsPanelWithData

/**
 * Turbo settings, shown in Burp's Settings window and persisted by Burp (user scope).
 * Before [register] runs (unit tests, standalone use) every getter returns its default.
 */
object TurboSettings {
    const val LEARN_WORDS = "Learn observed words"
    const val DESYNC_AGENT = "Desync agent mode"
    const val ALLOW_MCP_RUNS = "Allow MCP clients to run Turbo scripts"
    const val FONT_SIZE = "Script editor font size"
    const val LINE_NUMBERS = "Show line numbers"
    const val SHOW_EOL = "Show end-of-line markers"
    const val VISIBLE_WHITESPACE = "Show whitespace"

    @Volatile private var panel: SettingsPanelWithData? = null

    fun register(api: MontoyaApi) {
        val built = SettingsPanelBuilder.settingsPanel()
            .withPersistence(SettingsPanelPersistence.USER_SETTINGS)
            .withTitle("Raijin Turbo")
            .withDescription("Raijin's Turbo scripting engine")
            .withKeywords("raijin", "turbo", "script", "race", "mcp")
            .withSettings(
                booleanSetting(LEARN_WORDS, "Record words seen in proxied traffic for use as wordlists", false),
                booleanSetting(DESYNC_AGENT, "Relax request validation for desync research via MCP", false),
                booleanSetting(
                    ALLOW_MCP_RUNS,
                    "Lets connected MCP clients execute Python scripts inside Burp's JVM (turbo_start_run). Leave off unless you trust every MCP client.",
                    false,
                ),
                integerSetting(FONT_SIZE, "Font size of the Turbo script editor", 14),
                booleanSetting(LINE_NUMBERS, true),
                booleanSetting(SHOW_EOL, false),
                booleanSetting(VISIBLE_WHITESPACE, false),
            )
            .build()
        panel = built
        api.userInterface().registerSettingsPanel(built)
    }

    fun unregister() { panel = null }

    private fun bool(name: String, default: Boolean) = panel?.let { runCatching { it.getBoolean(name) }.getOrNull() } ?: default
    private fun int(name: String, default: Int) = panel?.let { runCatching { it.getInteger(name) }.getOrNull() } ?: default

    val learnWords get() = bool(LEARN_WORDS, false)
    val desyncAgent get() = bool(DESYNC_AGENT, false)
    val allowMcpRuns get() = bool(ALLOW_MCP_RUNS, false)
    val fontSize get() = int(FONT_SIZE, 14).let { if (it > 0) it else 14 }
    val lineNumbers get() = bool(LINE_NUMBERS, true)
    val showEol get() = bool(SHOW_EOL, false)
    val visibleWhitespace get() = bool(VISIBLE_WHITESPACE, false)
}
