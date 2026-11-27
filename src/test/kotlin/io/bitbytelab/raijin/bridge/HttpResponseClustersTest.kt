package io.bitbytelab.raijin.bridge

import io.bitbytelab.raijin.bridge.HttpResponseClusters.Sample
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class HttpResponseClustersTest {

    /** A long, varied page so a changed token moves only a few of its bigrams. */
    private fun page(token: String) =
        "Welcome back to the customer portal. Your account overview lists recent orders, invoices, saved " +
            "addresses, payment methods and loyalty points earned this quarter. Contact our support desk if " +
            "anything looks wrong, or browse the help centre for answers about shipping, returns, warranties, " +
            "gift cards and subscriptions. Session token: $token. Thank you for shopping with us today; new " +
            "arrivals in kitchenware, gardening tools and outdoor furniture are waiting for you on the homepage."

    private fun clusterJson(summary: HttpResponseClusters.Summary, id: Int) =
        summary.json.getValue("clusters").jsonArray[id].jsonObject

    @Test
    fun `identical responses form one uniform cluster`() {
        val summary = HttpResponseClusters.cluster((0 until 5).map { Sample(it, 200, 2, "ok") })
        assertEquals(1, summary.clusterCount)
        assertTrue(summary.json.getValue("uniform").jsonPrimitive.boolean)
        assertEquals(5, clusterJson(summary, 0).getValue("count").jsonPrimitive.int)
        assertEquals((0 until 5).associateWith { 0 }, summary.clusterOf)
    }

    @Test
    fun `status codes never share a cluster and the largest cluster comes first`() {
        val samples =
            listOf(Sample(0, 200, 2, "ok"), Sample(1, 409, 2, "ok"), Sample(2, 409, 2, "ok"))
        val summary = HttpResponseClusters.cluster(samples)
        assertEquals(2, summary.clusterCount)
        assertEquals(409, clusterJson(summary, 0).getValue("status_code").jsonPrimitive.int)
        assertEquals(mapOf(0 to 1, 1 to 0, 2 to 0), summary.clusterOf)
        assertEquals(
            1,
            summary.json
                .getValue("status_code_distribution")
                .jsonObject
                .getValue("200")
                .jsonPrimitive
                .int,
        )
    }

    @Test
    fun `a rotating token keeps a cluster while another message or length splits it`() {
        val a = page("a1b2c3d4e5")
        val b = page("z9y8x7w6v5")
        assertTrue(
            HttpResponseClusters.dice(
                HttpResponseClusters.bigrams(a),
                HttpResponseClusters.bigrams(b),
            ) >= 90.0,
        )
        val summary =
            HttpResponseClusters.cluster(
                listOf(
                    Sample(0, 200, a.length, a),
                    Sample(1, 200, b.length, b),
                    Sample(2, 200, 25, "Error: insufficient funds"),
                    Sample(3, 200, 28, "Payment accepted for order 1"),
                    Sample(4, 200, 28, "Payment refused: try again!!"),
                ),
            )
        assertEquals(summary.clusterOf[0], summary.clusterOf[1])
        assertEquals(4, summary.clusterCount)
        assertTrue(summary.clusterOf[3] != summary.clusterOf[4])
        // At 100 % only identical bodies share a cluster.
        assertEquals(
            2,
            HttpResponseClusters.cluster(
                    listOf(Sample(0, 200, a.length, a), Sample(1, 200, b.length, b)),
                    100.0,
                )
                .clusterCount,
        )
    }

    @Test
    fun `unanswered requests are their own cluster and not counted as variation`() {
        val summary =
            HttpResponseClusters.cluster(
                listOf(Sample(0, 200, 2, "ok"), Sample(1, 0, 0, ""), Sample(2, 200, 2, "ok")),
            )
        assertEquals(1, summary.clusterCount)
        assertEquals(1, summary.unanswered)
        val noResponse = clusterJson(summary, 1)
        assertTrue(noResponse.getValue("no_response").jsonPrimitive.boolean)

        val analysis = HttpResponseClusters.raceAnalysis(summary, identicalRequests = true)
        assertFalse(analysis.getValue("race_condition_likely").jsonPrimitive.boolean)
        assertEquals(1, analysis.getValue("unanswered").jsonPrimitive.int)
    }

    @Test
    fun `race analysis only claims a race for identical requests answered in several ways`() {
        val split =
            HttpResponseClusters.cluster(
                listOf(
                    Sample(0, 200, 7, "applied"),
                    Sample(1, 200, 7, "applied"),
                    Sample(2, 400, 4, "used"),
                ),
            )
        val identical = HttpResponseClusters.raceAnalysis(split, identicalRequests = true)
        assertTrue(identical.getValue("race_condition_likely").jsonPrimitive.boolean)
        assertTrue("success cluster" in identical.getValue("verdict").jsonPrimitive.content)
        val withPayloads = HttpResponseClusters.raceAnalysis(split, identicalRequests = false)
        assertFalse(withPayloads.getValue("race_condition_likely").jsonPrimitive.boolean)
        assertTrue(withPayloads.getValue("variation").jsonPrimitive.boolean)

        val uniform =
            HttpResponseClusters.raceAnalysis(
                HttpResponseClusters.cluster(listOf(Sample(0, 200, 2, "ok"))),
                identicalRequests = true,
            )
        assertFalse(uniform.getValue("race_condition_likely").jsonPrimitive.boolean)
        assertTrue("application state" in uniform.getValue("verdict").jsonPrimitive.content)
    }

    @Test
    fun `beyond the cluster cap responses share one overflow cluster`() {
        val samples =
            (0 until HttpResponseClusters.MAX_CLUSTERS + 6).map { Sample(it, 100 + it, 1, "x") }
        val summary = HttpResponseClusters.cluster(samples)
        val clusters = summary.json.getValue("clusters").jsonArray
        assertEquals(HttpResponseClusters.MAX_CLUSTERS + 1, clusters.size)
        val overflow = clusters.last().jsonObject
        assertTrue(overflow.getValue("overflow").jsonPrimitive.boolean)
        assertEquals(6, overflow.getValue("count").jsonPrimitive.int)
        assertEquals(6, overflow.getValue("status_codes").jsonObject.size)
    }

    @Test
    fun `timing is summarised and slow responses are outliers`() {
        val times = listOf(100.0, 102.0, 98.0, 101.0, 99.0, 900.0)
        val summary =
            HttpResponseClusters.cluster(times.mapIndexed { i, t -> Sample(i, 200, 2, "ok", t) })
        val timing = summary.json.getValue("timing").jsonObject
        assertEquals(98.0, timing.getValue("min_ms").jsonPrimitive.content.toDouble())
        val outliers = timing.getValue("outliers").jsonArray
        assertEquals(listOf(5), outliers.map { it.jsonObject.getValue("index").jsonPrimitive.int })
        assertNull(HttpResponseClusters.outlierLimit(listOf(1.0, 2.0, 3.0), 2.0))
    }

    @Test
    fun `dice compares bigram sets`() {
        val abc = HttpResponseClusters.bigrams("abcd")
        assertEquals(100.0, HttpResponseClusters.dice(abc, HttpResponseClusters.bigrams("abcd")))
        assertEquals(0.0, HttpResponseClusters.dice(abc, HttpResponseClusters.bigrams("wxyz")))
        assertEquals(0.0, HttpResponseClusters.dice(emptySet(), emptySet()))
    }
}
