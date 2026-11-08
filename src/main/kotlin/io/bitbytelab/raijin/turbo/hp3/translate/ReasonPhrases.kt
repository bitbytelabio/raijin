package io.bitbytelab.raijin.turbo.hp3.translate

/**
 * Standard reason phrases, from the IANA HTTP Status Code Registry.
 *
 * <p>Needed because neither HTTP/2 nor HTTP/3 carries a reason phrase — RFC 9114 section 4.1.2 and
 * RFC 9113 section 8.3.2 define only {@code :status} — yet Burp writes one anyway when it renders
 * an HTTP/2 response, emitting {@code HTTP/2 200 OK}. Matching that convention is what makes an
 * adapted response indistinguishable from one Burp produced itself.
 *
 * <p>It also matters more than cosmetically. Turbo Intruder derives its Status column with
 * {@code response.split(" ", limit = 3)[1]}, splitting on spaces alone, so a status line ending
 * immediately after the code leaves it parsing {@code "200\r\ncontent-type:"} and falling into a
 * {@code catch} that returns 0. A status line without a reason phrase silently breaks other
 * people's tools.
 *
 * <p>Generated from the registry rather than transcribed. DO NOT EDIT BY HAND.
 */
object ReasonPhrases {

    private val REASONS: MutableMap<Int, String> = HashMap()

    init {
        REASONS[100] = "Continue"
        REASONS[101] = "Switching Protocols"
        REASONS[102] = "Processing"
        REASONS[103] = "Early Hints"
        REASONS[104] = "Upload Resumption Supported"
        REASONS[200] = "OK"
        REASONS[201] = "Created"
        REASONS[202] = "Accepted"
        REASONS[203] = "Non-Authoritative Information"
        REASONS[204] = "No Content"
        REASONS[205] = "Reset Content"
        REASONS[206] = "Partial Content"
        REASONS[207] = "Multi-Status"
        REASONS[208] = "Already Reported"
        REASONS[226] = "IM Used"
        REASONS[300] = "Multiple Choices"
        REASONS[301] = "Moved Permanently"
        REASONS[302] = "Found"
        REASONS[303] = "See Other"
        REASONS[304] = "Not Modified"
        REASONS[305] = "Use Proxy"
        REASONS[307] = "Temporary Redirect"
        REASONS[308] = "Permanent Redirect"
        REASONS[400] = "Bad Request"
        REASONS[401] = "Unauthorized"
        REASONS[402] = "Payment Required"
        REASONS[403] = "Forbidden"
        REASONS[404] = "Not Found"
        REASONS[405] = "Method Not Allowed"
        REASONS[406] = "Not Acceptable"
        REASONS[407] = "Proxy Authentication Required"
        REASONS[408] = "Request Timeout"
        REASONS[409] = "Conflict"
        REASONS[410] = "Gone"
        REASONS[411] = "Length Required"
        REASONS[412] = "Precondition Failed"
        REASONS[413] = "Content Too Large"
        REASONS[414] = "URI Too Long"
        REASONS[415] = "Unsupported Media Type"
        REASONS[416] = "Range Not Satisfiable"
        REASONS[417] = "Expectation Failed"
        REASONS[421] = "Misdirected Request"
        REASONS[422] = "Unprocessable Content"
        REASONS[423] = "Locked"
        REASONS[424] = "Failed Dependency"
        REASONS[425] = "Too Early"
        REASONS[426] = "Upgrade Required"
        REASONS[428] = "Precondition Required"
        REASONS[429] = "Too Many Requests"
        REASONS[431] = "Request Header Fields Too Large"
        REASONS[451] = "Unavailable For Legal Reasons"
        REASONS[500] = "Internal Server Error"
        REASONS[501] = "Not Implemented"
        REASONS[502] = "Bad Gateway"
        REASONS[503] = "Service Unavailable"
        REASONS[504] = "Gateway Timeout"
        REASONS[505] = "HTTP Version Not Supported"
        REASONS[506] = "Variant Also Negotiates"
        REASONS[507] = "Insufficient Storage"
        REASONS[508] = "Loop Detected"
        REASONS[510] = "Not Extended"
        REASONS[511] = "Network Authentication Required"
    }

    /** The standard phrase for {@code status}, or an empty string if the registry has none. */
    @JvmStatic
    fun forStatus(status: Int): String {
        return REASONS.getOrDefault(status, "")
    }
}
