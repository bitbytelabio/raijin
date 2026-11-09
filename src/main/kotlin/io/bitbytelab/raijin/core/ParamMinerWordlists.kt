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
}
