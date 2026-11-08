package io.bitbytelab.raijin.turbo

import burp.api.montoya.http.HttpService
import java.net.URL

/**
 * Target host/port/scheme. A plain value type so engines and tests can build one without a
 * running Burp; [toMontoya] needs Burp's runtime and is only called when actually sending.
 */
data class TurboService(val host: String, val port: Int, val secure: Boolean) {
    fun toMontoya(): HttpService = HttpService.httpService(host, port, secure)

    companion object {
        fun fromUrl(url: URL): TurboService =
            TurboService(url.host, getEffectivePort(url), url.protocol == "https")

        fun fromMontoya(service: HttpService): TurboService =
            TurboService(service.host(), service.port(), service.secure())
    }
}
