package io.bitbytelab.raijin.core

/**
 * Pure character-bigram Dice-coefficient similarity (0..100). Extracted from
 * [io.bitbytelab.raijin.bridge.AnalysisBridge]'s private `calculateSimilarity` (which now
 * delegates here) so the exact same "how similar are these two response bodies" metric is
 * reusable outside that bridge — e.g. by [io.bitbytelab.raijin.injection.InjectionOracle]'s
 * boolean-differential oracle, instead of reimplementing it.
 */
object TextSimilarity {
    fun dice(s1: String, s2: String): Double {
        if (s1 == s2) return 100.0
        if (s1.isEmpty() && s2.isEmpty()) return 100.0
        if (s1.isEmpty() || s2.isEmpty()) return 0.0

        val bigrams1 = s1.zipWithNext().toSet()
        val bigrams2 = s2.zipWithNext().toSet()
        val intersection = bigrams1.intersect(bigrams2).size
        val total = bigrams1.size + bigrams2.size

        if (total == 0) return 100.0
        return Math.round((2.0 * intersection / total) * 10000.0) / 100.0
    }
}
