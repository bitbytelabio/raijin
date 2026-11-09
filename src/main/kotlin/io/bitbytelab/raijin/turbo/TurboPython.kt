package io.bitbytelab.raijin.turbo

import org.python.core.PyType

/**
 * The Turbo classes that `ScriptEnvironment.py` needs, exposed to Jython as types. Jython
 * cannot `import io.bitbytelab...` (it resolves `io` to Python's stdlib module), so they are
 * injected under the name `turbo` instead.
 */
object TurboPython {
    fun types(): Map<String, PyType> = listOf(
        AdaptiveController::class.java,
        AdaptivePolicy::class.java,
        AutoProtocol::class.java,
        AutoProtocolProber::class.java,
        BurpRequestEngine::class.java,
        HTTP2RequestEngine::class.java,
        HTTP3RequestEngine::class.java,
        ThreadedRequestEngine::class.java,
        Utils::class.java,
        DesyncTechniques::class.java,
        DesyncProbePayloads::class.java,
        DesyncCanary::class.java,
    ).associate { it.simpleName to PyType.fromClass(it) }
}
