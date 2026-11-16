package io.bitbytelab.raijin.turbo

import java.io.File

class Scripts() {
    companion object {
        val SCRIPTENVIRONMENT = Scripts::class.java.getResource("/ScriptEnvironment.py").readText()
        val SAMPLEBURPSCRIPT = Scripts::class.java.getResource("/examples/default.py").readText()

         val DEFAULT_RAW_REQUEST: String = listOf(
            "GET / HTTP/1.1",
            "Host: example.com",
            "Cache-Control: max-age=0",
            "Sec-Ch-Ua: \"Google Chrome\";v=\"139\", \"Not=A?Brand\";v=\"8\", \"Chromium\";v=\"139\"",
            "Sec-Ch-Ua-Mobile: ?0",
            "Sec-Ch-Ua-Platform: \"macOS\"",
            "Accept-Language: en-US;q=0.9,en;q=0.8",
            "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Sec-Fetch-Site: none",
            "Sec-Fetch-Mode: navigate",
            "Sec-Fetch-User: ?1",
            "Sec-Fetch-Dest: document",
            "Accept-Encoding: gzip, deflate, br",
            "Connection: close",
            "",
            ""
        ).joinToString("\r\n")
    }
}

/** Scripts in the user's scripts directory, sorted by name; hidden files are skipped. Empty when [folder] is not a directory. */
internal fun userScriptItems(folder: File): List<DirectoryItem> {
    if (!folder.isDirectory) return emptyList()
    return (folder.listFiles() ?: return emptyList())
        .filter { !it.name.startsWith(".") }
        .sortedBy { it.name }
        .map { DirectoryItem(File(folder, it.name).absolutePath, it.name) }
}

/**
 * Bundled example entries (jar paths such as `examples/basic.py`) worth showing in the picker:
 * no directory entries, hidden files or `__init__.py`, sorted.
 */
internal fun exampleScriptNames(jarEntries: List<String>): List<String> =
    jarEntries.filter { entry ->
        val name = entry.substringAfterLast('/')
        !entry.endsWith("/") && name.isNotEmpty() && !name.startsWith(".") && name != "__init__.py"
    }.sorted()
