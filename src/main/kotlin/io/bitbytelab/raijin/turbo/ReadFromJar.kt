package io.bitbytelab.raijin.turbo

import java.io.File
import java.util.jar.JarFile

/** Lists entries under a folder of the jar this class was loaded from. */
class ReadFromJar {
    fun getFiles(folder: String): ArrayList<String> {
        val jarFile = File(javaClass.protectionDomain.codeSource.location.toURI())
        JarFile(jarFile).use { jar ->
            return jar.entries().asSequence()
                .map { it.name }
                .filter { it.startsWith("$folder/") }
                .toCollection(ArrayList())
        }
    }
}
