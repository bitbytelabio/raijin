package io.bitbytelab.raijin

import io.modelcontextprotocol.kotlin.sdk.server.ClientConnection
import java.lang.reflect.Proxy

/** Receiver for calling a registered SDK handler directly; any call back to the client fails the test. */
val testClientConnection: ClientConnection = Proxy.newProxyInstance(
    ClientConnection::class.java.classLoader,
    arrayOf(ClientConnection::class.java)
) { proxy, method, args ->
    when (method.name) {
        "getSessionId" -> "test"
        "toString" -> "testClientConnection"
        "hashCode" -> System.identityHashCode(proxy)
        "equals" -> proxy === args?.firstOrNull()
        else -> error("handler called ClientConnection.${method.name}, which this test does not support")
    }
} as ClientConnection
