package io.bitbytelab.raijin.skills

import java.io.File

/**
 * Skills are short markdown guides shipped in `src/main/resources/skills/` that tell an MCP client
 * how to use this server (tool groups, workflows, scope rules). Each file starts with a
 * frontmatter block holding `name` and `description`.
 *
 * Jars cannot list a classpath directory, so [NAMES] is the authoritative list; the catalog test
 * checks every entry resolves and that its frontmatter name matches.
 *
 * Each skill is served two ways: as an MCP prompt named [promptName] (`PromptRegistry`; this is
 * what Claude Code and omp list as slash commands) and as a `skill://burpsuite/<name>` resource
 * (`ResourceRegistry`; this is how a model reads one on its own).
 */
object SkillCatalog {

    data class Skill(val name: String, val description: String, val body: String)

    /** Every shipped skill, in the order [list] reports them. */
    val NAMES: List<String> = listOf(
        "burpsuite-overview",
        "http-testing",
        "proxy-traffic",
        "scanner-audit",
        "recon-and-probes",
        "findings-reporting",
        "collaborator-oob",
        "turbo-scripting",
    )

    /** The skill clients should load first. */
    const val ENTRY_SKILL = "burpsuite-overview"

    /**
     * URI for the resource form of a skill: `skill://<name>/SKILL.md`, the shape the Agent
     * Skills spec / MCP Skills Extension expect (a bare skill name segment, `/SKILL.md` leaf) —
     * not a vendor-namespaced path. [ResourceRegistry] serves [raw] (frontmatter included) at
     * this URI, matching what a client reading an actual `SKILL.md` file would expect.
     */
    fun uri(name: String) = "skill://$name/SKILL.md"

    private val uriPattern = Regex("""^skill://([^/]+)/SKILL\.md$""")

    /** Extracts the skill name from a `skill://<name>/SKILL.md` URI, or null if malformed. */
    fun nameFromUri(uri: String): String? = uriPattern.matchEntire(uri.trim())?.groupValues?.get(1)

    /**
     * Name of the MCP prompt for a skill: `http-testing` -> `http_testing_skill`.
     *
     * Clients show prompts as slash commands (`/mcp__burpsuite__http_testing_skill` in Claude Code,
     * `burpsuite:http_testing_skill` in omp) and their pickers filter on the command name, so users find
     * skills by typing `skill`. Every name therefore ends in `_skill`, as the other MCP servers' skill
     * prompts do (a prompt called just `http-testing` is never listed for that search).
     */
    fun promptName(name: String) = name.replace('-', '_') + "_skill"

    /** All skills (parsed once, they are static resources). */
    val all: List<Skill> by lazy { NAMES.mapNotNull { load(it) } }

    /** Raw file text (frontmatter included) per skill name — read once, same source [load] parses. */
    private val rawByName: Map<String, String> by lazy {
        NAMES.mapNotNull { name ->
            readResource("/skills/$name.md", "src/main/resources/skills/$name.md")?.let { name to it }
        }.toMap()
    }

    fun list(): List<Skill> = all

    fun get(name: String): Skill? = all.firstOrNull { it.name == name }

    /**
     * The skill's original file text, frontmatter included. This is what [uri] should be read
     * as (an actual `SKILL.md`, not markdown with the frontmatter already stripped) — unlike
     * [get]'s [Skill.body], which strips it for use as an MCP *prompt* message (instructions,
     * not a file read — see [ResourceRegistry] / [io.bitbytelab.raijin.transport.PromptRegistry]).
     */
    fun raw(name: String): String? = rawByName[name]

    /** SHA-256 of [raw]'s UTF-8 bytes, hex-encoded. For the skills manifest resource. */
    fun sha256(name: String): String? = raw(name)?.let { text ->
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(text.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }

    /** Byte size of [raw]'s UTF-8 encoding. For the skills manifest resource. */
    fun byteSize(name: String): Int? = raw(name)?.toByteArray(Charsets.UTF_8)?.size

    private fun load(name: String): Skill? {
        val raw = rawByName[name] ?: return null
        return parse(name, raw)
    }

    /** Splits `---` frontmatter from the body; falls back to the file name when keys are missing. */
    internal fun parse(fallbackName: String, raw: String): Skill {
        val text = raw.replace("\r\n", "\n")
        if (!text.startsWith("---\n")) return Skill(fallbackName, "", text.trim())
        val end = text.indexOf("\n---", startIndex = 4)
        if (end < 0) return Skill(fallbackName, "", text.trim())
        val meta = text.substring(4, end).lines()
            .mapNotNull { line ->
                val i = line.indexOf(':')
                if (i <= 0) null else line.substring(0, i).trim() to line.substring(i + 1).trim()
            }.toMap()
        val body = text.substring(end + 4).trim()
        return Skill(meta["name"] ?: fallbackName, meta["description"].orEmpty(), body)
    }

    /** Classpath first (the shipped jar), then the source tree (running from an IDE or tests without resources). */
    private fun readResource(classpath: String, fallbackPath: String): String? {
        SkillCatalog::class.java.getResourceAsStream(classpath)?.use { return it.readBytes().toString(Charsets.UTF_8) }
        val f = File(fallbackPath)
        return if (f.isFile) f.readText() else null
    }
}
