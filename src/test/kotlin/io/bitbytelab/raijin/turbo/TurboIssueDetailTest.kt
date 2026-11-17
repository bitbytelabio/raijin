package io.bitbytelab.raijin.turbo

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TurboIssueDetailTest {

    @Test
    fun `every value is escaped and rows keep their order`() {
        val html = TurboIssueDetail.html(
            comment = "<b>x</b>",
            status = "Done",
            script = "a<b && \$x",
            rows = listOf(
                TurboIssueDetail.Row("\"><img src=x>", 200, 1, 2, 3, "lbl", 0, "c1"),
                TurboIssueDetail.Row("p2", 404, 4, 5, 6, "", 1, ""),
            ),
        )

        assertTrue("Comment: &lt;b&gt;x&lt;/b&gt;" in html, html)
        assertTrue("<pre>a&lt;b &amp;&amp; \$x</pre>" in html, html)
        assertTrue("<td>&quot;&gt;&lt;img src=x&gt;</td>" in html, html)
        assertTrue(
            "<tr><td>Payload</td><td>Status</td><td>TTFB</td><td>TTLB</td><td>Arrival</td><td>Label</td><td>Queue ID</td><td>Connection ID</td></tr>" in html,
            html,
        )
        val first = html.indexOf("<td>200</td>")
        val second = html.indexOf("<td>404</td>")
        assertTrue(first in 0 until second, html)
        assertFalse("<img" in html, html)
    }
}
