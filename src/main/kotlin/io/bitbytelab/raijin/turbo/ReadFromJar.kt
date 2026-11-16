package io.bitbytelab.raijin.turbo

import java.io.File
import java.util.jar.JarFile

/**
 * Lists resource entries under a folder, from the extension jar or, when running from exploded
 * classes during development, from the resources directory on the classpath. Entries look like
 * jar entry names either way: `folder/sub/name.py`, directories ending in `/`.
 */
class ReadFromJar {
    fun getFiles(folder: String): ArrayList<String> {
        val codeSource = File(javaClass.protectionDomain.codeSource.location.toURI())
        if (codeSource.isFile) {
            JarFile(codeSource).use { jar ->
                return jar.entries().asSequence()
                    .map { it.name }
                    .filter { it.startsWith("$folder/") }
                    .toCollection(ArrayList())
            }
        }
        // Exploded: Gradle keeps resources apart from classes, so find the folder on the classpath.
        val url = javaClass.getResource("/$folder")?.takeIf { it.protocol == "file" } ?: return ArrayList()
        return directoryEntries(File(url.toURI()), folder)
    }

    internal companion object {
        /** [dir]'s contents as jar-style entry names rooted at [folder]. */
        fun directoryEntries(dir: File, folder: String): ArrayList<String> =
            dir.walkTopDown()
                .filter { it != dir }
                .map { file ->
                    val path = "$folder/${file.relativeTo(dir).invariantSeparatorsPath}"
                    if (file.isDirectory) "$path/" else path
                }
                .sorted()
                .toCollection(ArrayList())
    }
}
