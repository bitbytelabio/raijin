package io.bitbytelab.raijin.core

import java.util.concurrent.ConcurrentHashMap

/** Bundled candidate-name dictionaries for [io.bitbytelab.raijin.bridge.ReconBridge.paramMine], read from the classpath. */
object ParamMinerWordlists {
    const val DEFAULT = "param-miner-params"
    const val HEADERS = "param-miner-headers"

    /** In a `name~value` template: replaced by the probe's unique canary. */
    const val CANARY_PLACEHOLDER = "%s"

    /** In a `name~value` template: replaced by the target host. */
    const val HOST_PLACEHOLDER = "%h"

    /**
     * One candidate. Param Miner's lists give some names a value to send after a `~`
     * (`host~%h:%s`, `origin~https://%s.%h`, `x-original-url~/%s`): the header only does something
     * when its value has that shape. Sending the whole line as a name would test a header no
     * server knows.
     */
    data class Entry(val name: String, val valueTemplate: String? = null) {
        /** The value to send: the template with its placeholders filled in, or just [canary]. */
        fun value(canary: String, host: String): String =
            valueTemplate?.replace(HOST_PLACEHOLDER, host)?.replace(CANARY_PLACEHOLDER, canary) ?: canary
    }

    private val cache = ConcurrentHashMap<String, List<Entry>>()

    fun names(): Set<String> = setOf(DEFAULT, HEADERS)

    /** Splits `name~value` at the first `~`; a candidate without a value part is all name. */
    fun entryOf(candidate: String): Entry {
        val sep = candidate.indexOf('~')
        if (sep <= 0 || sep == candidate.length - 1) return Entry(candidate)
        return Entry(candidate.substring(0, sep), candidate.substring(sep + 1))
    }

    /** One wordlist line as an [Entry]; null for a blank line or a `#` comment. */
    fun parseLine(line: String): Entry? {
        val trimmed = line.trim()
        if (trimmed.isEmpty() || trimmed.startsWith("#")) return null
        return entryOf(trimmed)
    }

    /** Entries of a wordlist text, in order, without repeated lines. */
    fun parse(text: String): List<Entry> = text.lineSequence().mapNotNull(::parseLine).distinct().toList()

    /** Entries of the bundled wordlist [name]; empty when there is no such resource. */
    fun entries(name: String): List<Entry> = cache.computeIfAbsent(name) {
        ParamMinerWordlists::class.java.getResource("/wordlists/$name.txt")?.readText()?.let(::parse) ?: emptyList()
    }

    /** Candidate names of the bundled wordlist [name], without value templates. */
    fun load(name: String): List<String> = entries(name).map { it.name }.distinct()

    sealed class Resolved {
        data class Error(val message: String) : Resolved()

        data class Ok(val entries: List<Entry>) : Resolved() {
            /** Candidate names in list order (a name listed with two value templates appears twice). */
            val candidates: List<String> get() = entries.map { it.name }
        }
    }

    /**
     * Resolves the candidate list for [io.bitbytelab.raijin.bridge.ReconBridge.paramMine]: when
     * [candidates] is supplied, uses it as given (a `name~value` candidate carries its own value
     * template); otherwise validates [wordlistName] and loads it.
     * An unknown name and a known name that loaded zero entries are distinct errors — without
     * this, a typo'd wordlist (e.g. "param-miner-param") silently looks identical to a clean scan
     * that found nothing (`tested: 0, interesting_count: 0`, no error).
     */
    fun resolve(candidates: List<String>?, wordlistName: String): Resolved {
        if (candidates != null) return Resolved.Ok(candidates.filter { it.isNotEmpty() }.map(::entryOf).distinct())
        if (wordlistName !in names()) {
            return Resolved.Error("Unknown wordlist '$wordlistName'. Valid values: ${names().sorted()}")
        }
        val loaded = entries(wordlistName)
        if (loaded.isEmpty()) {
            return Resolved.Error("Wordlist '$wordlistName' loaded 0 candidates (bundled resource missing or empty).")
        }
        return Resolved.Ok(loaded)
    }
}
