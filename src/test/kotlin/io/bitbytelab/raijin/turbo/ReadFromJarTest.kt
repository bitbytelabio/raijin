package io.bitbytelab.raijin.turbo

import java.io.File
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ReadFromJarTest {

    @Test fun `lists the examples when running from exploded classes`() {
        // Tests run from build/classes and build/resources, not from a jar.
        val entries = ReadFromJar().getFiles("examples")

        assertTrue("examples/basic.py" in entries, "entries: $entries")
        assertTrue("basic.py" in exampleScriptNames(entries).map { it.substringAfterLast('/') })
    }

    @Test fun `directory entries look like jar entry names`() {
        val root = createTempDirectory("readfromjar").toFile()
        try {
            File(root, "sub").mkdirs()
            File(root, "a.py").writeText("a")
            File(root, "sub/b.py").writeText("b")

            assertEquals(
                listOf("examples/a.py", "examples/sub/", "examples/sub/b.py"),
                ReadFromJar.directoryEntries(root, "examples"),
            )
        } finally {
            root.deleteRecursively()
        }
    }
}
