package io.bitbytelab.raijin.skills

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SkillCatalogTest {

    @Test
    fun `every listed skill loads with matching frontmatter`() {
        assertEquals(SkillCatalog.NAMES, SkillCatalog.list().map { it.name })
        SkillCatalog.list().forEach {
            assertTrue(it.description.isNotBlank(), "${it.name} needs a description")
            assertTrue(it.body.isNotBlank(), "${it.name} needs a body")
        }
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
    fun `promptName is snake case with a _skill suffix`() {
        assertEquals("http_testing_skill", SkillCatalog.promptName("http-testing"))
        assertEquals("burpsuite_overview_skill", SkillCatalog.promptName(SkillCatalog.ENTRY_SKILL))
        assertEquals("recon_and_probes_skill", SkillCatalog.promptName("recon-and-probes"))
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
