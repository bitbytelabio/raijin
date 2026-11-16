package io.bitbytelab.raijin.bridge

import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import java.lang.reflect.Proxy

/**
 * An immutable HTTP message behind the fake Montoya requests and responses of the proxy tests
 * ([fakeRequest], [fakeResponse]). Every `with*` call returns a fake over a changed copy.
 */
internal data class FakeMessage(
    val method: String = "GET",
    val url: String = "https://app.test/",
    val path: String = "/",
    val status: Int = 200,
    val headers: List<Pair<String, String>> = emptyList(),
    val body: String = "",
) {
    val requestText: String
        get() = "$method $path HTTP/1.1\r\n" + headers.joinToString("") { (n, v) -> "$n: $v\r\n" } + "\r\n" + body

    val responseText: String
        get() = "HTTP/1.1 $status X\r\n" + headers.joinToString("") { (n, v) -> "$n: $v\r\n" } + "\r\n" + body
}

/** A [type] whose calls go to [answer] (method name, arguments). */
internal fun <T> stubOf(type: Class<T>, answer: (String, Array<out Any?>) -> Any?): T =
    type.cast(Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { self, m, args ->
        when (m.name) {
            "hashCode" -> System.identityHashCode(self)
            "equals" -> self === args?.get(0)
            else -> answer(m.name, args ?: emptyArray())
        }
    })

internal fun fakeHeader(name: String, value: String): HttpHeader = stubOf(HttpHeader::class.java) { m, _ ->
    when (m) {
        "name" -> name
        "value" -> value
        "toString" -> "$name: $value"
        else -> error("HttpHeader.$m")
    }
}

internal fun fakeService(host: String): HttpService = stubOf(HttpService::class.java) { m, _ ->
    when (m) {
        "host" -> host
        "port" -> 443
        "secure" -> true
        "toString" -> "https://$host"
        else -> error("HttpService.$m")
    }
}

/**
 * Header edits shared by both message kinds. An update or a removal touches only the FIRST header
 * written exactly as named, the strictest behaviour Burp could have, so callers must not rely on more.
 */
private fun FakeMessage.headerEdit(m: String, a: Array<out Any?>): FakeMessage? = when (m) {
    "withAddedHeader" -> copy(headers = headers + (a[0] as String to a[1] as String))
    "withUpdatedHeader" -> {
        val i = headers.indexOfFirst { it.first == a[0] }
        if (i < 0) this else copy(headers = headers.toMutableList().also { it[i] = it[i].first to a[1] as String })
    }
    "withRemovedHeader" -> {
        val i = headers.indexOfFirst { it.first == a[0] }
        if (i < 0) this else copy(headers = headers.toMutableList().also { it.removeAt(i) })
    }
    "withBody" -> copy(body = a[0] as String)
    else -> null
}

internal fun fakeRequest(msg: FakeMessage, service: HttpService = fakeService("app.test")): HttpRequest =
    stubOf(HttpRequest::class.java) { m, a ->
        msg.headerEdit(m, a)?.let { return@stubOf fakeRequest(it, service) }
        when (m) {
            "method" -> msg.method
            "url" -> msg.url
            "path" -> msg.path
            "httpService" -> service
            "headers" -> msg.headers.map { (n, v) -> fakeHeader(n, v) }
            "bodyToString" -> msg.body
            "isInScope" -> true
            "withMethod" -> fakeRequest(msg.copy(method = a[0] as String), service)
            "withPath" -> fakeRequest(msg.copy(path = a[0] as String), service)
            "toString" -> msg.requestText
            else -> error("HttpRequest.$m")
        }
    }

internal fun fakeResponse(msg: FakeMessage): HttpResponse = stubOf(HttpResponse::class.java) { m, a ->
    msg.headerEdit(m, a)?.let { return@stubOf fakeResponse(it) }
    when (m) {
        "statusCode" -> msg.status.toShort()
        "headers" -> msg.headers.map { (n, v) -> fakeHeader(n, v) }
        "bodyToString" -> msg.body
        "withStatusCode" -> fakeResponse(msg.copy(status = (a[0] as Short).toInt()))
        "toString" -> msg.responseText
        else -> error("HttpResponse.$m")
    }
}

internal fun HttpRequest.headerPairs(): List<Pair<String, String>> = headers().map { it.name() to it.value() }

internal fun HttpResponse.headerPairs(): List<Pair<String, String>> = headers().map { it.name() to it.value() }
