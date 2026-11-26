package io.bitbytelab.raijin.tools

import kotlinx.serialization.json.Json
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

class ToolCatalogTest {
    private val published by lazy { RegisteredTools().use { r -> r.published.tools.values.map { it.tool } } }
    private val catalogFile = File("src/main/resources/catalog/tools.json")
    private val prettyJson = Json { prettyPrint = true; prettyPrintIndent = "  " }

    @Test fun `every published tool is in exactly one domain`() {
        val names = published.map { it.name }
        for (name in names) {
            val owners = ToolDomains.DOMAINS.filter { name in it.tools }.map { it.name }
            assertEquals(1, owners.size, "$name must be in exactly one domain, is in $owners")
        }
    }

    @Test fun `every domain tool is published`() {
        val names = published.map { it.name }.toSet()
        val missing = ToolDomains.DOMAINS.flatMap { d -> d.tools.filter { it !in names }.map { "${d.name}/$it" } }
        assertTrue(missing.isEmpty(), "domain tools not published: $missing")
    }

    @Test fun `every domain skill ships`() {
        ToolDomains.DOMAINS.forEach {
            assertTrue(File("cli/crates/raijin-cli/src/skills/${it.skill}/SKILL.md").isFile, "${it.name}: unknown skill ${it.skill}")
        }
    }

    @Test fun `every published tool carries annotations from consistent hint sets`() {
        published.forEach { assertTrue(it.annotations != null, "${it.name} has no annotations") }
        val names = published.map { it.name }.toSet()
        for (set in listOf(ToolHints.READ_ONLY, ToolHints.DESTRUCTIVE, ToolHints.OPEN_WORLD)) {
            assertEquals(emptySet(), set - names, "hints name unpublished tools")
        }
        assertEquals(emptySet(), ToolHints.READ_ONLY intersect ToolHints.DESTRUCTIVE)
        assertEquals(emptySet(), ToolHints.READ_ONLY intersect ToolHints.OPEN_WORLD)
    }

    @Test fun `the committed catalog matches the published tools`() {
        val expected = ToolDomains.catalogJson(published)
        if (System.getenv("RAIJIN_UPDATE_CATALOG") == "1") {
            catalogFile.parentFile.mkdirs()
            catalogFile.writeText(prettyJson.encodeToString(expected) + "\n")
            return
        }
        val committed = if (catalogFile.isFile) Json.parseToJsonElement(catalogFile.readText()) else null
        if (committed != expected) {
            fail("catalog/tools.json is stale: run RAIJIN_UPDATE_CATALOG=1 ./gradlew test --tests '*ToolCatalogTest'")
        }
    }
}
