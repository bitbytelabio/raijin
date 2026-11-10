package io.bitbytelab.raijin.graphql.bruteforcer

/**
 * Regular expressions for parsing GraphQL error messages into schema facts — the technique
 * behind Clairvoyance-style schema reconstruction. Ported from InQL's `bruteforcer.RegexStore`
 * (a subset: only the patterns [SchemaBruteforcer]'s simplified field/argument-name discovery
 * needs — not the full type/enum/union/input-object resolution InQL's version also covers).
 */
object RegexStore {
    val WRONG_TYPENAME = listOf(
        Regex("""Cannot query field ["'`]?(?<field>[_A-Za-z][_0-9A-Za-z]*)["'`]? on type ["'`]?(?<typename>[_A-Za-z][_0-9A-Za-z]*)["'`].(.*)"""),
        Regex("""Field ["'`]?(?<field>[_A-Za-z][_0-9A-Za-z]*)["'`]? is not defined by type ["'`]?(?<typename>[_A-Za-z][_0-9A-Za-z]*)["'`].(.*)"""),
        Regex("""Field ["'`]?(?<field>[_A-Za-z][_0-9A-Za-z]*)["'`]? is not defined by type ["'`]?(?<typename>[_A-Za-z][_0-9A-Za-z]*)["'`].?"""),
        Regex("""Field ["'`]?(?<field>[_A-Za-z][_0-9A-Za-z]*)["'`]? doesn't exist on type ["'`]?(?<typename>[_A-Za-z][_0-9A-Za-z]*)["'`].*"""),
    )

    val FIELD_SUGGESTIONS = listOf(
        Regex("""(?:Did you mean|\G(?!^))[^\w"'`]+["'`]?(?<suggestion>[_A-Za-z][_0-9A-Za-z]*)["'`]"""),
        Regex("""Did you mean["'`]? (?<suggestion1>[_A-Za-z][_0-9A-Za-z]*)["'`]? or ["'`]?(?<suggestion2>[_A-Za-z][_0-9A-Za-z]*)["'`]?\?"""),
        Regex("""Did you mean ["'`]?(?<suggestion>[_A-Za-z][_0-9A-Za-z]*)["'`]?\?"""),
        Regex("""(?:Did you mean|\G(?!^))[^\w`'"]+["'`]?(?<suggestion>[_A-Za-z][_0-9A-Za-z]*)["'`]"""),
        Regex("""Did you mean(?:[^"'`]+)?(?:["'`])(?<suggestion1>[_A-Za-z][_0-9A-Za-z]*)(?:["'`])(?:,\s*(?:["'`])(?<suggestion2>[_A-Za-z][_0-9A-Za-z]*)(?:["'`]))?(?:\s*,?\s*or\s*(?:["'`])(?<suggestion3>[_A-Za-z][_0-9A-Za-z]*)(?:["'`]))?\?"""),
    )

    val NO_SUBFIELDS =
        Regex("""Field ["'`]?(?<field>[_A-Za-z][_0-9A-Za-z]*)["'`]? must not have a selection since type ["'`]?(?<type>.*?)["'`]? has no subfields\.*""")

    val SELECTION_ON_SCALAR =
        Regex("""Selections can't be made on scalars \(field ["'`]?(?<field>[_A-Za-z][_0-9A-Za-z]*)["'`]? returns ["'`]?(?<type>[_A-Za-z!\[\]]+)["'`]? but has selections.*\)""")

    val MISSING_SUBFIELDS =
        Regex("""Field ["'`]?(?<field>[_A-Za-z][_0-9A-Za-z]*)["'`]? of type ["'`]?(?<type>.*?)["'`]? must have a selection of subfields\.*""")

    val MISSING_ARGUMENT =
        Regex("""Field ["'`]?(?<field>[_A-Za-z][_0-9A-Za-z]*)["'`]? argument ["'`]?(?<argument>[_A-Za-z][_0-9A-Za-z]*)["'`]? of type ["'`]?(?<type>.*)["'`]? is required(?:, but it was not provided| but not provided)?\.""")

    val ARGUMENT_SUGGESTIONS = listOf(
        Regex("""Unknown argument ["'`]?(?<argument>[_A-Za-z][_0-9A-Za-z]*)["'`]? on field ["'`]?(?<field>[_A-Za-z][_0-9A-Za-z]*)["'`]?.*Did you mean ["'`]?(?<suggestion>[_A-Za-z][_0-9A-Za-z]*)["'`]?\?"""),
        Regex("""Field ["'`]?(?<field>[_A-Za-z][_0-9A-Za-z]*)["'`]? doesn't accept argument ["'`]?(?<argument>[_A-Za-z][_0-9A-Za-z]*)["'`]?. Did you mean ["'`]?(?<suggestion>[_A-Za-z][_0-9A-Za-z]*)["'`]?\?"""),
    )

    val UNKNOWN_ARGUMENT = listOf(
        Regex("""Unknown argument [`"'](?<argument>[_A-Za-z][_0-9A-Za-z]*)['"'] on field .*"""),
        Regex("""Argument [`"'](?<argument>[_A-Za-z][_0-9A-Za-z]*)['"'] is not defined on field .*"""),
        Regex("""Unknown argument ["'`]?(?<argument>[_A-Za-z][_0-9A-Za-z]*)["'`]? on field '.*'"""),
        Regex("""Field '.*' doesn't accept argument ["'`]?(?<argument>[_A-Za-z][_0-9A-Za-z]*)["'`]?"""),
    )

    /** Fake names guaranteed not to collide with a real field/argument, used to trigger error messages that leak schema facts. */
    const val PROBE_FIELD = "____raijin_bruteforce_probe____"
    const val PROBE_ARG = "____raijin_bruteforce_probe_arg____"

    fun getSuggestions(errorMessage: String, regexList: List<Regex>): List<String> {
        val suggestionGroupNames = listOf("suggestion", "suggestion1", "suggestion2")
        return regexList.flatMap { regex ->
            regex.findAll(errorMessage).flatMap { matchResult ->
                suggestionGroupNames.mapNotNull { groupName ->
                    try { matchResult.groups[groupName]?.value } catch (_: Exception) { null }
                }
            }
        }.distinct()
    }
}
