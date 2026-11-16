package io.bitbytelab.raijin.injection

/** Vulnerability classes `injection_probe` tests; [id] is the value the `classes` parameter takes. */
enum class InjectionClass(val id: String) {
    SQLI("sqli"),
    NOSQLI("nosqli"),
    CMDI("cmdi"),
    SSTI("ssti"),
    LFI("lfi"),
    XXE("xxe"),
    SSRF("ssrf"),
    XSS("xss"),
    OPEN_REDIRECT("open_redirect"),
    CRLF("crlf");

    /** The classes to run, or [error] naming the rejected values and the accepted ones. */
    data class Selection(val classes: List<InjectionClass>, val error: String? = null)

    companion object {
        /** The `http_fuzz` payload library calls the file-read class `traversal`; accepted for [LFI]. */
        private const val LFI_ALIAS = "traversal"

        /** Every value `classes` accepts. */
        val accepted: List<String> = InjectionClass.entries.map { it.id } + LFI_ALIAS

        /** Resolves the `classes` parameter; null or empty selects every class. Result is in declaration order. */
        fun select(names: List<String>?): Selection {
            if (names.isNullOrEmpty()) return Selection(InjectionClass.entries.toList())
            val chosen = HashSet<InjectionClass>()
            val unknown = ArrayList<String>()
            for (name in names) {
                val key = name.trim().lowercase()
                val cls = if (key == LFI_ALIAS) LFI else InjectionClass.entries.firstOrNull { it.id == key }
                if (cls == null) unknown += name else chosen += cls
            }
            if (unknown.isNotEmpty()) {
                return Selection(
                    emptyList(),
                    "Unknown injection class(es): ${unknown.joinToString(", ") { "'$it'" }}. Allowed: ${accepted.joinToString(", ")}",
                )
            }
            return Selection(InjectionClass.entries.filter { it in chosen })
        }
    }
}
