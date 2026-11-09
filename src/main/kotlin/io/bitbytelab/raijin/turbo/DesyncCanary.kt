package io.bitbytelab.raijin.turbo

/**
 * Canary generation and response correlation for HTTP request-smuggling confirmation — ported
 * from HTTP Request Smuggler's `CanaryUtils`. A canary encodes which technique/batch/position
 * produced it, so a later response containing an EARLIER canary (lower batch, or same batch and
 * lower position) confirms a smuggled follow-up request actually landed on someone else's
 * response ("response-queue poisoning"), rather than the current request just reflecting its
 * own canary back. Exposed to Jython Turbo scripts as `turbo.DesyncCanary` (see [TurboPython.types]).
 */
object DesyncCanary {
    const val PREFIX = "wrtzllsk"

    private val pattern = Regex("$PREFIX(\\d+)x(\\d+)x(\\d+)")
    private val specialPaths = setOf("/", "/favicon.ico")

    data class Parsed(val techniqueId: Int, val batch: Int, val position: Int)

    /** A canary tagged with which technique/batch/position produced it, for later correlation via [findCanary]. */
    @JvmStatic
    fun generate(techniqueId: Int, batch: Int, position: Int): String = "$PREFIX${techniqueId}x${batch}x$position"

    /** Cheap pre-check before the regex parse in [findCanary]. */
    @JvmStatic
    fun containsCanaryPrefix(text: String?): Boolean = text != null && text.contains(PREFIX)

    /** The first tagged canary found in [text], or null. */
    @JvmStatic
    fun findCanary(text: String?): Parsed? {
        if (text == null || !containsCanaryPrefix(text)) return null
        val m = pattern.find(text) ?: return null
        return Parsed(m.groupValues[1].toInt(), m.groupValues[2].toInt(), m.groupValues[3].toInt())
    }

    /**
     * True when [found] (from a later response) is the SAME technique but from an earlier batch,
     * or the same batch at an earlier position — i.e. it's an earlier, still-queued request's
     * canary leaking into a response that wasn't meant for it (desync confirmed), not just the
     * current request's own canary reflecting back.
     */
    @JvmStatic
    fun isReflectionOfEarlierRequest(found: Parsed, currentTechniqueId: Int, currentBatch: Int, currentPosition: Int): Boolean {
        if (found.techniqueId != currentTechniqueId) return false
        if (found.batch < currentBatch) return true
        return found.batch == currentBatch && found.position < currentPosition
    }

    @JvmStatic
    fun isCrossTechniqueReflection(found: Parsed, currentTechniqueId: Int): Boolean = found.techniqueId != currentTechniqueId

    /**
     * Injects a tagged canary into a raw request's path (or a `xyz=` query parameter when the
     * path is `/`, a well-known file, or already URL-encoded) so its presence in a later
     * response can be correlated back to this exact request. Returns [request] unchanged if its
     * first line doesn't look like `METHOD /path ...`.
     */
    @JvmStatic
    fun injectIntoRequestLine(request: String, techniqueId: Int, batch: Int, position: Int): String {
        if (request.isEmpty()) return request
        val firstSpace = request.indexOf(' ')
        if (firstSpace < 0) return request
        var secondSpace = request.indexOf(' ', firstSpace + 1)
        if (secondSpace < 0) {
            secondSpace = request.indexOf('\r').let { if (it < 0) request.length else it }
        }

        val method = request.substring(0, firstSpace)
        val pathPart = request.substring(firstSpace + 1, secondSpace)
        val rest = request.substring(secondSpace)
        if (!pathPart.startsWith("/")) return request

        val canary = generate(techniqueId, batch, position)
        val newPath = when {
            pathPart.contains('?') -> "$pathPart&xyz=$canary"
            isSpecialPath(pathPart) -> "$pathPart?xyz=$canary"
            else -> "/$canary"
        }
        return "$method $newPath$rest"
    }

    private fun isSpecialPath(path: String): Boolean = path in specialPaths || path.contains('%')
}
