package io.bitbytelab.raijin.turbo.hp3.h3.qpack

import io.bitbytelab.raijin.turbo.hp3.h3.Http3Exception

/** A QPACK decoding failure. Carries {@code QPACK_DECOMPRESSION_FAILED} by default. */
open class QpackException : Http3Exception {

    constructor(message: String) : super(QPACK_DECOMPRESSION_FAILED, message)

    constructor(errorCode: Long, message: String) : super(errorCode, message)
}
