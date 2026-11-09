package io.bitbytelab.raijin.core

/** Bundled candidate-name dictionaries for [io.bitbytelab.raijin.bridge.ReconBridge.paramMine], read from the classpath. */
object ParamMinerWordlists {
    const val DEFAULT = "param-miner-params"

    private val cache = mutableMapOf<String, List<String>>()

    fun names(): Set<String> = setOf(DEFAULT, "param-miner-headers")

    fun load(name: String): List<String> = cache.getOrPut(name) {
        val resource = ParamMinerWordlists::class.java.getResource("/wordlists/$name.txt") ?: return@getOrPut emptyList()
        resource.readText().lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .toList()
    }

    sealed class Resolved {
        data class Error(val message: String) : Resolved()
        data class Ok(val candidates: List<String>) : Resolved()
    }

    /**
     * Resolves the candidate list for [io.bitbytelab.raijin.bridge.ReconBridge.paramMine]: when
     * [candidates] is supplied, uses it as-is; otherwise validates [wordlistName] and loads it.
     * An unknown name and a known name that loaded zero entries are distinct errors — without
     * this, a typo'd wordlist (e.g. "param-miner-param") silently looks identical to a clean scan
     * that found nothing (`tested: 0, interesting_count: 0`, no error).
     */
    fun resolve(candidates: List<String>?, wordlistName: String): Resolved {
        if (candidates != null) return Resolved.Ok(candidates)
        if (wordlistName !in names()) {
            return Resolved.Error("Unknown wordlist '$wordlistName'. Valid values: ${names().sorted()}")
        }
        val loaded = load(wordlistName)
        if (loaded.isEmpty()) {
            return Resolved.Error("Wordlist '$wordlistName' loaded 0 candidates (bundled resource missing or empty).")
        }
        return Resolved.Ok(loaded)
    }
}
