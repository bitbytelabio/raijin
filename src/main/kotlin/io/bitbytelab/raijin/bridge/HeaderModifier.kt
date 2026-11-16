package io.bitbytelab.raijin.bridge

import burp.api.montoya.http.message.HttpMessage
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse

/**
 * Header edits that apply to a name as a whole: every occurrence, with its name compared ignoring
 * case. Names and values are written as given, CR/LF and any other character included.
 *
 * Burp's `withUpdatedHeader` / `withRemovedHeader` are relied on only for the first header written
 * exactly as named, so each occurrence is edited under the name it is written with. Montoya's
 * requests and responses share no interface for their edits, hence an overload for each.
 */
internal object HeaderModifier {

    /** [request] without any [name] header: one removal per occurrence, each by the name it is written with. */
    fun remove(request: HttpRequest, name: String): HttpRequest = remove(request, writtenNames(request, name))

    /** [remove] for a response. */
    fun remove(response: HttpResponse, name: String): HttpResponse = remove(response, writtenNames(response, name))

    /**
     * [request] with exactly one [name] header carrying [value]: a single existing one is updated
     * in place, none is added, and several are replaced by one, so the header is never sent twice.
     */
    fun set(request: HttpRequest, name: String, value: String): HttpRequest =
        set(request, name, value, writtenNames(request, name))

    /** [set] for a response. */
    fun set(response: HttpResponse, name: String, value: String): HttpResponse =
        set(response, name, value, writtenNames(response, name))

    /** [set] when [request] has a [name] header; otherwise [request] itself. */
    fun replace(request: HttpRequest, name: String, value: String): HttpRequest {
        val written = writtenNames(request, name)
        return if (written.isEmpty()) request else set(request, name, value, written)
    }

    /** [replace] for a response. */
    fun replace(response: HttpResponse, name: String, value: String): HttpResponse {
        val written = writtenNames(response, name)
        return if (written.isEmpty()) response else set(response, name, value, written)
    }

    /** [set], given the names [request]'s [name] headers are written with. */
    private fun set(request: HttpRequest, name: String, value: String, written: List<String>): HttpRequest =
        when (written.size) {
            0 -> request.withAddedHeader(name, value)
            1 -> request.withUpdatedHeader(written[0], value)
            else -> remove(request, written).withAddedHeader(name, value)
        }

    private fun set(response: HttpResponse, name: String, value: String, written: List<String>): HttpResponse =
        when (written.size) {
            0 -> response.withAddedHeader(name, value)
            1 -> response.withUpdatedHeader(written[0], value)
            else -> remove(response, written).withAddedHeader(name, value)
        }

    private fun remove(request: HttpRequest, written: List<String>): HttpRequest =
        written.fold(request) { out, each -> out.withRemovedHeader(each) }

    private fun remove(response: HttpResponse, written: List<String>): HttpResponse =
        written.fold(response) { out, each -> out.withRemovedHeader(each) }

    /** The names [message]'s [name] headers are written with, in order. */
    private fun writtenNames(message: HttpMessage, name: String): List<String> =
        message.headers().mapNotNull { header -> header.name().takeIf { it.equals(name, ignoreCase = true) } }
}
