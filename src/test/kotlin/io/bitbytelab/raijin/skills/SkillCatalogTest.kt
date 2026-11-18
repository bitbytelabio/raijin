package io.bitbytelab.raijin.skills

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SkillCatalogTest {

    @Test
    fun `every listed skill loads with matching frontmatter`() {
        assertEquals(SkillCatalog.NAMES, SkillCatalog.list().map { it.name })
        SkillCatalog.list().forEach {
            assertTrue(it.description.isNotBlank(), "${it.name} needs a description")
            assertTrue(it.description.length <= 80, "${it.name} description too long (${it.description.length}): ${it.description}")
            assertTrue(it.body.isNotBlank(), "${it.name} needs a body")
            assertFalse("<name>_skill" in it.body, "${it.name} body still references <name>_skill")
            SkillCatalog.NAMES.forEach { skillName ->
                assertFalse("${skillName.replace('-', '_')}_skill" in it.body, "${it.name} body still references ${skillName}_skill")
            }
            assertFalse("read_skill_file" in it.body, "${it.name} body still references read_skill_file")
        }
    }

    @Test
    fun `skill names are clean kebab-case without _skill suffix and fit omp picker width`() {
        val kebabCase = Regex("[a-z0-9]+(-[a-z0-9]+)*")
        SkillCatalog.NAMES.forEach { name ->
            assertTrue(kebabCase.matches(name), "'$name' must be lowercase kebab-case")
            assertFalse(name.endsWith("_skill") || name.endsWith("-skill"), "'$name' must not carry a skill suffix")
            assertTrue("burpsuite:$name".length <= 28, "'burpsuite:$name' exceeds 28 chars and risks truncation in omp")
        }
    }

    @Test
    fun `resource directory has no unlisted skill files`() {
        val dir = File("src/main/resources/skills")
        val files = dir.listFiles { f -> f.isFile && f.extension == "md" }?.map { it.nameWithoutExtension }?.sorted()
        assertEquals(SkillCatalog.NAMES.sorted(), files)
    }

    @Test
    fun `entry skill exists`() {
        assertNotNull(SkillCatalog.get(SkillCatalog.ENTRY_SKILL))
    }

    @Test
    fun `unknown skill is null`() {
        assertNull(SkillCatalog.get("nope"))
    }

    @Test
    fun `uri and nameFromUri round-trip`() {
        SkillCatalog.NAMES.forEach { name ->
            assertEquals(name, SkillCatalog.nameFromUri(SkillCatalog.uri(name)))
        }
        assertNull(SkillCatalog.nameFromUri("skill://overview"))
        assertNull(SkillCatalog.nameFromUri("https://example.com/overview/SKILL.md"))
    }

    @Test
    fun `parse reads frontmatter and falls back without it`() {
        val s = SkillCatalog.parse("x", "---\nname: foo\ndescription: bar baz\n---\n# Body\n")
        assertEquals("foo", s.name)
        assertEquals("bar baz", s.description)
        assertEquals("# Body", s.body)
        assertEquals("x", SkillCatalog.parse("x", "plain").name)
    }
}
