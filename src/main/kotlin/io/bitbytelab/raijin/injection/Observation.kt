package io.bitbytelab.raijin.injection

/**
 * One HTTP exchange reduced to what the injection oracles compare. [status] `0` means the request
 * got no response (timeout, refused or reset connection); such an observation is never evidence.
 */
data class Observation(
    val status: Int,
    val headers: List<Pair<String, String>> = emptyList(),
    val body: String = "",
    val elapsedMs: Long = 0,
) {
    val answered: Boolean get() = status > 0

    /** First value of header [name] (case-insensitive), or null. */
    fun header(name: String): String? = headers.firstOrNull { it.first.equals(name, ignoreCase = true) }?.second

    companion object {
        val NO_RESPONSE = Observation(status = 0)
    }
}
