package io.bitbytelab.raijin.turbo.http3

import io.bitbytelab.raijin.turbo.hp3.h3.Http3Request

data class TurboHttp3Request(
    val request: Http3Request,
    val authoredVersion: String,
)
