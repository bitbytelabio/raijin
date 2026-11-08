package io.bitbytelab.raijin.turbo.mcp

data class NormalizedScript(val script: String, val warning: String? = null)

fun hasMixedLineEndings(text: String): Boolean {
    val hasCRLF = text.contains("\r\n")
    val withoutCRLF = text.replace("\r\n", "")
    val hasStandaloneLF = withoutCRLF.contains("\n")
    return hasCRLF && hasStandaloneLF
}

fun normalizeScriptLineEndings(script: String, normalize: Boolean = true): NormalizedScript {
    if (!normalize || !hasMixedLineEndings(script)) {
        return NormalizedScript(script)
    }
    val normalized = script.replace("\r\n", "\n").replace("\n", "\r\n")
    return NormalizedScript(
        normalized,
        "Script had mixed line endings (\\n and \\r\\n). Normalized to \\r\\n. " +
        "Set normalize_line_endings=false to disable."
    )
}
