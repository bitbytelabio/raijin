package io.bitbytelab.raijin.transport

import java.net.InetAddress

/**
 * Source-address allowlist for remote access ([RemoteAccess.Config.allowedIps]): single IPs and CIDR
 * ranges, IPv4 and IPv6. Loopback always passes. Only the socket peer address is checked; forwarding
 * headers such as `X-Forwarded-For` are never consulted.
 *
 * Parsing never touches DNS: only IP literals are accepted.
 */
internal object SourceAddressPolicy {

    private val IPV4 = Regex("""\d{1,3}(\.\d{1,3}){3}""")

    /** An address block: [network] bytes (4 or 16) whose first [prefixLength] bits must match. */
    class IpRange(private val network: ByteArray, val prefixLength: Int) {
        fun contains(address: InetAddress): Boolean {
            val bytes = address.address
            if (bytes.size != network.size) return false
            val fullBytes = prefixLength / 8
            for (i in 0 until fullBytes) if (bytes[i] != network[i]) return false
            val remainingBits = prefixLength % 8
            if (remainingBits == 0) return true
            val mask = (0xFF shl (8 - remainingBits)) and 0xFF
            return (bytes[fullBytes].toInt() and mask) == (network[fullBytes].toInt() and mask)
        }
    }

    /**
     * Parses an IP literal (brackets and an IPv6 zone id are tolerated); null for anything else,
     * host names included. IPv4-mapped IPv6 addresses come back as IPv4.
     */
    fun parseAddress(raw: String): InetAddress? {
        val s = raw.trim().removePrefix("[").removeSuffix("]").substringBefore('%')
        if (s.isEmpty()) return null
        return when {
            IPV4.matches(s) -> {
                val parts = s.split('.').map { it.toInt() }
                if (parts.any { it > 255 }) null else InetAddress.getByAddress(ByteArray(4) { parts[it].toByte() })
            }
            // Only hex digits, colons and dots: the JDK then parses it as a literal and never resolves it.
            ':' in s && s.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' } ->
                runCatching { InetAddress.getByName(s) }.getOrNull()
            else -> null
        }
    }

    /** Parses `ip` or `ip/prefix`; null when [raw] is not an IP literal or the prefix is out of range. */
    fun parseRange(raw: String): IpRange? {
        val entry = raw.trim()
        val slash = entry.indexOf('/')
        val address = parseAddress(if (slash >= 0) entry.substring(0, slash) else entry) ?: return null
        val bits = address.address.size * 8
        val prefix = if (slash >= 0) entry.substring(slash + 1).trim().toIntOrNull() ?: return null else bits
        if (prefix !in 0..bits) return null
        return IpRange(address.address, prefix)
    }

    /** The entries of a configured allowlist that are neither an IP nor a CIDR range. */
    fun invalidEntries(entries: List<String>): List<String> = entries.filter { parseRange(it) == null }

    /**
     * Whether a peer at [remoteAddress] may connect. [ranges] null means no allowlist is configured,
     * so every source passes. Otherwise loopback always passes and any other peer must fall inside a
     * range; a peer that is not an IP literal is refused (the Ktor test engine reports `localhost`,
     * which counts as loopback).
     */
    fun isAllowed(remoteAddress: String, ranges: List<IpRange>?): Boolean {
        if (ranges == null) return true
        if (remoteAddress.trim().equals("localhost", ignoreCase = true)) return true
        val address = parseAddress(remoteAddress) ?: return false
        if (address.isLoopbackAddress) return true
        return ranges.any { it.contains(address) }
    }

    /** RFC 5952 text for a 16-byte IPv6 address: lowercase, no leading zeros, longest zero run as `::`. */
    fun formatIpv6(bytes: ByteArray): String {
        require(bytes.size == 16) { "an IPv6 address has 16 bytes" }
        val groups = IntArray(8) { ((bytes[2 * it].toInt() and 0xFF) shl 8) or (bytes[2 * it + 1].toInt() and 0xFF) }
        var bestStart = -1
        var bestLen = 0
        var i = 0
        while (i < 8) {
            if (groups[i] != 0) { i++; continue }
            val start = i
            while (i < 8 && groups[i] == 0) i++
            if (i - start > bestLen) { bestStart = start; bestLen = i - start }
        }
        if (bestLen < 2) bestStart = -1
        val sb = StringBuilder()
        var g = 0
        while (g < 8) {
            if (g == bestStart) {
                sb.append("::")
                g += bestLen
                continue
            }
            if (sb.isNotEmpty() && !sb.endsWith(":")) sb.append(':')
            sb.append(Integer.toHexString(groups[g]))
            g++
        }
        return sb.toString()
    }
}
