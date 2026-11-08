package io.bitbytelab.raijin.turbo.http3

import io.bitbytelab.raijin.turbo.hp3.h3.Http3Request
import io.bitbytelab.raijin.turbo.http.BinaryHttpRequestTranslator

object TurboHttp3RequestTranslator {
    @JvmStatic
    fun translate(raw: String, scheme: String, defaultAuthority: String): TurboHttp3Request =
        translate(raw, scheme, defaultAuthority, false)

    @JvmStatic
    fun translate(
        raw: String,
        scheme: String,
        defaultAuthority: String,
        kettled: Boolean,
    ): TurboHttp3Request {
        val translated = BinaryHttpRequestTranslator.translate(raw, scheme, defaultAuthority, kettled)
        return TurboHttp3Request(
            Http3Request(translated.fields, translated.body),
            translated.authoredVersion,
        )
    }
}
