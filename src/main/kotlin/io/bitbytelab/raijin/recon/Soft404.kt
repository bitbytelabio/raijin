package io.bitbytelab.raijin.recon

import io.bitbytelab.raijin.core.ProbeResult
import java.net.URLEncoder
import kotlin.math.abs
import kotlin.math.max
import kotlin.random.Random

/** What the response to one requested path looked like, in the terms a not-found page keeps constant. */
class PathFingerprint(
    val path: String,
    val status: Int,
    val length: Int,
    val lines: Int,
    val words: Int,
    /** Redirect target with the requested path replaced by a placeholder; null without a Location header. */
    val location: String?,
) {
    /**
     * True when [other] is the same page for another path: same status, same redirect target
     * (path aside), same line and word counts give or take a token, and a length that differs by
     * no more than the two paths can explain.
     */
    fun sameAs(other: PathFingerprint): Boolean =
        status == other.status && location == other.location &&
            abs(lines - other.lines) <= 1 && abs(words - other.words) <= 2 &&
            abs(length - other.length) <= Soft404.LENGTH_TOLERANCE + Soft404.MAX_REFLECTIONS * abs(path.length - other.path.length)
}

/** Fingerprints responses and picks the made-up paths a target's not-found behaviour is learned from. */
object Soft404 {
    /** Scope of what the target answers for any path that does not exist. */
    const val SITE = "/"

    const val PLAIN = "plain"
    const val DIRECTORY = "dir"
    const val DOTFILE = "dot"
    private const val EXTENSION = "ext:"

    /** Length difference two not-found pages may have beyond what the requested path explains. */
    internal const val LENGTH_TOLERANCE = 32

    /** How many times a not-found page is assumed to repeat the requested path at most. */
    internal const val MAX_REFLECTIONS = 6

    /** Shapes of the wordlist that get their own calibration requests. */
    private const val MAX_SHAPES = 6

    /**
     * The kind of path, as servers route them: a directory, a dotfile, a file with an extension
     * (per extension), or a plain name. Each kind can have its own not-found behaviour: a handler
     * that answers every `.php`, a rule that forbids every dotfile, a redirect for every directory.
     */
    fun shapeOf(path: String): String {
        val bare = path.substringBefore('?').substringBefore('#')
        if (bare.endsWith("/")) return DIRECTORY
        val name = bare.substringAfterLast('/')
        if (name.startsWith(".")) return DOTFILE
        val dot = name.lastIndexOf('.')
        if (dot > 0 && dot < name.length - 1) {
            val extension = name.substring(dot + 1).lowercase()
            if (extension.length <= 8 && extension.all { it.isLetterOrDigit() }) return EXTENSION + extension
        }
        return PLAIN
    }

    /** Directory of [path], ending in `/`. */
    fun directoryOf(path: String): String {
        val bare = path.substringBefore('?')
        return bare.substring(0, bare.lastIndexOf('/') + 1).ifEmpty { "/" }
    }

    /** A path that does not exist, in the directory of [path] and of the same shape. */
    fun madeUpSibling(path: String, random: Random): String {
        val directory = directoryOf(path)
        val shape = shapeOf(path)
        return when {
            shape == DIRECTORY -> directoryOf(path.substringBefore('?').trimEnd('/')) + ProbeText.token(random, 12) + "/"
            shape == DOTFILE -> directory + "." + ProbeText.token(random, 12)
            shape.startsWith(EXTENSION) -> directory + ProbeText.token(random, 12) + "." + shape.removePrefix(EXTENSION)
            else -> directory + ProbeText.token(random, 12)
        }
    }

    /**
     * Made-up paths to learn the not-found behaviour from before scanning [paths]: without an
     * extension in two lengths and nested, a directory, `.json` and `.php`, then three lengths
     * for each of the commonest shapes in [paths]. Different lengths show a page that repeats
     * the requested path; different shapes show per-extension handlers.
     */
    fun calibrationPaths(paths: List<String>, random: Random): List<String> {
        fun token(length: Int) = ProbeText.token(random, length)
        val out = LinkedHashSet<String>()
        out.add("/" + token(8))
        out.add("/" + token(24))
        out.add("/" + token(8) + "/" + token(8))
        out.add("/" + token(12) + "/")
        out.add("/" + token(12) + ".json")
        out.add("/" + token(12) + ".php")
        val shapes = paths.groupingBy(::shapeOf).eachCount().entries.sortedByDescending { it.value }.map { it.key }
        for (shape in shapes.take(MAX_SHAPES)) {
            for (length in SHAPE_SAMPLE_LENGTHS) {
                when (shape) {
                    PLAIN -> {}
                    DIRECTORY -> out.add("/" + token(length) + "/")
                    DOTFILE -> out.add("/." + token(length))
                    else -> out.add("/" + token(length) + "." + shape.removePrefix(EXTENSION))
                }
            }
        }
        return out.toList()
    }

    /** Name lengths sampled per shape: three, so a page that repeats the path shows as a straight line. */
    private val SHAPE_SAMPLE_LENGTHS = listOf(8, 14, 20)

    fun fingerprint(path: String, response: ProbeResult): PathFingerprint {
        var lines = 0
        var words = 0
        var inWord = false
        for (ch in response.body) {
            if (ch == '\n') lines++
            if (ch.isWhitespace()) {
                inWord = false
            } else if (!inWord) {
                inWord = true
                words++
            }
        }
        val location = response.header("location")?.let { normalizeLocation(it, path) }
        return PathFingerprint(path, response.status, response.body.length, lines, words, location)
    }

    /** [location] without scheme and host, and with the requested [path] (plain or percent-encoded) replaced by [PATH_MARK]. */
    internal fun normalizeLocation(location: String, path: String): String {
        var target = location.trim()
        if (target.startsWith("http://", ignoreCase = true) || target.startsWith("https://", ignoreCase = true) || target.startsWith("//")) {
            val slash = target.indexOf('/', target.indexOf("//") + 2)
            target = if (slash < 0) "/" else target.substring(slash)
        }
        val bare = path.substringBefore('?')
        val forms = listOf(bare, URLEncoder.encode(bare, Charsets.UTF_8), bare.removePrefix("/"))
        for (form in forms) {
            if (form.length >= 2) target = target.replace(form, PATH_MARK, ignoreCase = true)
        }
        return target
    }

    /** Stands in for the requested path in a normalized Location; a character no URL contains. */
    internal const val PATH_MARK = "\u0001"
}

/**
 * What a target answers for paths that do not exist, learned from made-up paths. A candidate path
 * is worth reporting only when its response is not one of these.
 */
class Soft404Profile {

    /** Responses of one status to made-up paths of one shape in one scope. */
    private class Group(val status: Int) {
        private val samples = ArrayList<PathFingerprint>()
        private val locations = HashSet<String?>()

        /** How many times the page repeats the requested path, judged from samples of different path lengths. */
        private var reflections = 0
        private var minAdjusted = 0
        private var maxAdjusted = 0
        private var minLines = 0
        private var maxLines = 0
        private var minWords = 0
        private var maxWords = 0

        fun add(sample: PathFingerprint) {
            samples.add(sample)
            locations.add(sample.location)
            minLines = samples.minOf { it.lines }
            maxLines = samples.maxOf { it.lines }
            minWords = samples.minOf { it.words }
            maxWords = samples.maxOf { it.words }
            // The page repeats the path k times when taking k path lengths off makes samples of
            // three or more path lengths agree. Otherwise the lengths simply vary, and the spread
            // is the tolerance: two samples alone would make any difference look like a pattern.
            reflections = 0
            if (samples.map { it.path.substringBefore('?').length }.toSet().size >= 3) {
                for (k in 1..Soft404.MAX_REFLECTIONS) {
                    if (spread(k) <= REFLECTION_TOLERANCE && spread(k) < spread(reflections)) reflections = k
                }
            }
            minAdjusted = samples.minOf { adjusted(it, reflections) }
            maxAdjusted = samples.maxOf { adjusted(it, reflections) }
        }

        fun matches(candidate: PathFingerprint): Boolean {
            if (candidate.status != status) return false
            // A redirect is the same answer when it leads to the same place, whatever its body.
            if (status in 300..399 && locations.any { it != null }) return candidate.location in locations
            val tolerance = max(Soft404.LENGTH_TOLERANCE, 2 * (maxAdjusted - minAdjusted))
            val length = adjusted(candidate, reflections)
            if (length < minAdjusted - tolerance || length > maxAdjusted + tolerance) return false
            val lineTolerance = max(1, maxLines - minLines)
            if (candidate.lines < minLines - lineTolerance || candidate.lines > maxLines + lineTolerance) return false
            val wordTolerance = max(3, 2 * (maxWords - minWords))
            return candidate.words >= minWords - wordTolerance && candidate.words <= maxWords + wordTolerance
        }

        private fun spread(k: Int): Int = samples.maxOf { adjusted(it, k) } - samples.minOf { adjusted(it, k) }

        private fun adjusted(sample: PathFingerprint, k: Int): Int = sample.length - k * sample.path.substringBefore('?').length

        private companion object {
            /** Length difference left between samples once the repeated path is taken off. */
            const val REFLECTION_TOLERANCE = 4
        }
    }

    private val groups = LinkedHashMap<String, MutableList<Group>>()
    private val scopes = LinkedHashSet<String>()

    /** True when the target answered a made-up path with a success status: every path "exists". */
    var wildcard: Boolean = false
        private set

    /** Records [sample], the response to a made-up path, as not-found behaviour under [scope] (a directory, or [Soft404.SITE]). */
    fun add(scope: String, sample: PathFingerprint) {
        val sameShape = groups.getOrPut(key(scope, Soft404.shapeOf(sample.path))) { ArrayList() }
        val group = sameShape.firstOrNull { it.status == sample.status } ?: Group(sample.status).also { sameShape.add(it) }
        group.add(sample)
        scopes.add(scope)
        if (scope == Soft404.SITE && sample.status in 200..299) wildcard = true
    }

    /**
     * True when [candidate] is what the target answers for a path that does not exist: it matches
     * the made-up paths of its own shape in a scope it lies under, or, where that shape was never
     * sampled, any made-up path of that scope.
     */
    fun matches(candidate: PathFingerprint): Boolean {
        val shape = Soft404.shapeOf(candidate.path)
        val bare = candidate.path.substringBefore('?')
        for (scope in scopes) {
            if (!bare.startsWith(scope)) continue
            val pool = groups[key(scope, shape)]
                ?: groups.filterKeys { it.startsWith(scope + SEPARATOR) }.values.flatten()
            if (pool.any { it.matches(candidate) }) return true
        }
        return false
    }

    private fun key(scope: String, shape: String): String = scope + SEPARATOR + shape

    private companion object {
        const val SEPARATOR = "\u0000"
    }
}
