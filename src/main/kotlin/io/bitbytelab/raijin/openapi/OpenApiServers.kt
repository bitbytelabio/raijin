package io.bitbytelab.raijin.openapi

import kotlinx.serialization.json.*
import java.net.URI

/** Where an operation is sent: scheme, host and port, plus the base path its own path is appended to. */
data class ServerUrl(val scheme: String, val host: String, val port: Int, val basePath: String) {
    val secure: Boolean get() = scheme == "https"

    /** `scheme://host`, with the port only when it is not the scheme's default. */
    val origin: String get() = if (port == (if (secure) 443 else 80)) "$scheme://$host" else "$scheme://$host:$port"

    val url: String get() = origin + basePath
}

/** Works out the server an import targets: OpenAPI 3 `servers`, or Swagger 2 `host` / `basePath` / `schemes`. */
internal object OpenApiServers {
    private val HOST = Regex("[A-Za-z0-9._-]+")
    private val VARIABLE = Regex("\\{([^{}]+)\\}")

    /**
     * Joins a base path and an operation path with exactly one slash between them, so a base path of
     * `/` (or a server URL ending in `/`) does not produce `//pets`.
     */
    fun joinPaths(basePath: String, path: String): String =
        basePath.trimEnd('/') + if (path.startsWith("/")) path else "/$path"

    /**
     * Splits an absolute `http(s)` URL into a [ServerUrl]. Null (so that a malformed host never reaches
     * scope or the site map) unless the host is `localhost` or a dotted name / IPv4 address and the port,
     * when given, is a valid one. Query and fragment are dropped.
     */
    fun parse(url: String): ServerUrl? {
        val scheme = url.substringBefore("://", "").lowercase()
        if (scheme != "http" && scheme != "https") return null
        val rest = url.substring(scheme.length + 3)
        val end = rest.indexOfFirst { it == '/' || it == '?' || it == '#' }.let { if (it < 0) rest.length else it }
        val authority = rest.substring(0, end)
        val host = authority.substringBefore(':')
        if (host != "localhost" && !(HOST.matches(host) && '.' in host)) return null
        val port = when {
            ':' !in authority -> if (scheme == "https") 443 else 80
            else -> authority.substringAfter(':').toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
        }
        return ServerUrl(scheme, host, port, rest.substring(end).substringBefore('?').substringBefore('#'))
    }

    /** The first entry of an OpenAPI 3 `servers` array that yields a usable URL. */
    fun fromServers(servers: JsonElement?, documentUrl: String?): ServerUrl? =
        (servers as? JsonArray)?.firstNotNullOfOrNull { entry ->
            (entry as? JsonObject)?.let {
                absolute(substitute(it["url"].asText().orEmpty(), it["variables"] as? JsonObject), documentUrl)
            }
        }

    /** Root server of an OpenAPI 3 document; without usable `servers` it is `/` on the document's own host. */
    fun openApi3(root: JsonObject, documentUrl: String?): ServerUrl? =
        fromServers(root["servers"], documentUrl) ?: absolute("/", documentUrl)

    /** Swagger 2 `host`, `basePath` and `schemes`, each falling back to where the document itself was served from. */
    fun swagger2(root: JsonObject, documentUrl: String?): ServerUrl? {
        val document = documentUrl?.let { parse(it.trim()) }
        val schemes = (root["schemes"] as? JsonArray)?.mapNotNull { it.asText()?.lowercase() }.orEmpty()
        val scheme = listOf("https", "http").firstOrNull { it in schemes } ?: document?.scheme ?: "https"
        val authority = root["host"].asText()?.trim()?.takeIf { it.isNotEmpty() }
            ?: document?.origin?.substringAfter("://")
            ?: return null
        val basePath = root["basePath"].asText().orEmpty().trim()
        return parse("$scheme://$authority" + if (basePath.isEmpty() || basePath.startsWith("/")) basePath else "/$basePath")
    }

    /** [url] as a [ServerUrl], resolved against the URL the document came from when it is relative. */
    private fun absolute(url: String, documentUrl: String?): ServerUrl? {
        val reference = url.trim().ifEmpty { "/" }
        return parse(reference) ?: resolve(reference, documentUrl)?.let { parse(it) }
    }

    /** RFC 3986 reference resolution; null when there is no document URL or either part is not a URI. */
    private fun resolve(reference: String, documentUrl: String?): String? {
        if (documentUrl.isNullOrBlank()) return null
        return try {
            URI(documentUrl.trim()).resolve(reference).toString()
        } catch (_: Exception) {
            null
        }
    }

    /** Fills `{name}` templates with the variable's `default`, else its first `enum` value; unknown ones stay. */
    private fun substitute(url: String, variables: JsonObject?): String = VARIABLE.replace(url) { match ->
        val variable = variables?.get(match.groupValues[1]) as? JsonObject
        variable?.get("default").asText() ?: (variable?.get("enum") as? JsonArray)?.firstOrNull().asText() ?: match.value
    }
}
