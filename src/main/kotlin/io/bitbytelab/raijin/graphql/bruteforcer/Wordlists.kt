package io.bitbytelab.raijin.graphql.bruteforcer

/**
 * Field-name and argument-name guess lists for [SchemaBruteforcer], vendored verbatim from InQL
 * (`resources/wordlist.txt`, `resources/arg_wordlist.txt` — see `resources/graphql/NOTICE.txt`).
 */
object Wordlists {
    private val NAME_REGEX = Regex("^[_A-Za-z][_0-9A-Za-z]*$")

    private fun load(resourcePath: String): List<String> {
        val text = Wordlists::class.java.getResource(resourcePath)?.readText() ?: return emptyList()
        return text.lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() && NAME_REGEX.matches(it) }
            .distinct()
            .toList()
    }

    val fields: List<String> by lazy { load("/graphql/wordlist.txt") }
    val args: List<String> by lazy { load("/graphql/arg_wordlist.txt") }
}
