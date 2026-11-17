package io.bitbytelab.raijin.turbo

import io.bitbytelab.raijin.bridge.PayloadEncoders

/** Issue detail HTML for Turbo's "Report as issue"; markup in `resources/turbo/issue-detail*.html`, every value escaped. */
internal object TurboIssueDetail {
    data class Row(
        val payload: String,
        val status: Int,
        val ttfb: Long,
        val ttlb: Long,
        val arrival: Long,
        val label: String,
        val queueId: Int,
        val connectionId: String,
    )

    private val page by lazy { resource("/turbo/issue-detail.html") }
    private val row by lazy { resource("/turbo/issue-detail-row.html") }
    private val placeholder = Regex("""\{\{\{(\w+)\}\}\}|\{\{(\w+)\}\}""")

    fun html(comment: String, status: String, script: String, rows: List<Row>): String = fill(
        page,
        mapOf("comment" to comment, "status" to status, "script" to script),
        raw = mapOf("rows" to rows.joinToString("") { r ->
            fill(
                row,
                mapOf(
                    "payload" to r.payload, "status" to r.status.toString(), "ttfb" to r.ttfb.toString(),
                    "ttlb" to r.ttlb.toString(), "arrival" to r.arrival.toString(), "label" to r.label,
                    "queue_id" to r.queueId.toString(), "connection_id" to r.connectionId,
                ),
            )
        }),
    )

    // {{key}} is escaped, {{{key}}} is inserted as is; the lambda form of replace inserts literally ($ in scripts is safe).
    private fun fill(template: String, values: Map<String, String>, raw: Map<String, String> = emptyMap()): String =
        placeholder.replace(template) { m ->
            val rawKey = m.groupValues[1]
            if (rawKey.isNotEmpty()) {
                raw[rawKey] ?: error("issue template: no value for {{{$rawKey}}}")
            } else {
                val key = m.groupValues[2]
                PayloadEncoders.htmlEscape(values[key] ?: error("issue template: no value for {{$key}}"))
            }
        }

    private fun resource(path: String): String =
        TurboIssueDetail::class.java.getResource(path)?.readText() ?: error("missing resource $path")
}
