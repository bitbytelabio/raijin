package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.bitbytelab.raijin.core.BodyText
import io.bitbytelab.raijin.graphql.ReachabilityGuard
import io.bitbytelab.raijin.graphql.TargetUnreachableException
import io.bitbytelab.raijin.openapi.OpenApiDocument
import io.bitbytelab.raijin.openapi.OpenApiImport
import io.bitbytelab.raijin.openapi.PlannedRequest
import io.bitbytelab.raijin.openapi.ServerUrl
import io.bitbytelab.raijin.safety.BoundedHttp
import io.bitbytelab.raijin.safety.ScopeGate
import io.bitbytelab.raijin.state.StateManager
import kotlinx.serialization.json.*

/**
 * Brings an OpenAPI / Swagger document into Burp. Reading the document and working out the requests is
 * [OpenApiImport]'s; this class turns them into Montoya requests and puts them in the site map.
 */
class ApiImportBridge(
    private val api: MontoyaApi,
    private val stateManager: StateManager
) {
    private val scopeGate = ScopeGate(api)

    /**
     * Parses an OpenAPI 3.x / Swagger 2.0 document and generates a request for every operation.
     * Adds them to Burp's site map and optionally to scope.
     *
     * @param specJson The document text, JSON or YAML
     * @param baseUrl Replaces the server URL(s) of the document (to test a different host)
     * @param authHeader Optional auth header to include in all generated requests
     * @param authValue Auth header value
     * @param addToScope Whether to add the base URL to Burp's target scope
     * @param addToSitemap Whether to add generated requests to the site map
     * @param sendRequests Whether to actually send the requests (adds responses to the site map)
     * @param specUrl Where the document was downloaded from; relative server URLs resolve against it
     */
    fun importOpenApi(
        specJson: String,
        baseUrl: String?,
        authHeader: String?,
        authValue: String?,
        addToScope: Boolean,
        addToSitemap: Boolean,
        sendRequests: Boolean,
        specUrl: String? = null
    ): JsonObject {
        return try {
            // Planning touches nothing in Burp: an unusable document or server URL fails before any
            // scope or site map change.
            val plan = OpenApiImport.plan(OpenApiDocument.parse(specJson), baseUrl, specUrl)

            // Every operation's server, not only the document's first: an operation-level server
            // would otherwise be sent (and blocked under enforce) outside the scope just added.
            val addedToScope = ArrayList<String>()
            val addToScopeErrors = LinkedHashMap<String, String>()
            if (addToScope) {
                val servers = (listOf(plan.server.url) + plan.requests.map { it.server.url }).distinct()
                for (url in servers) {
                    try {
                        api.scope().includeInScope(url)
                        addedToScope += url
                    } catch (e: Exception) {
                        addToScopeErrors[url] = e.message ?: e.javaClass.simpleName
                    }
                }
            }

            var requestsSent = 0
            var addedToSitemap = 0
            var skippedOutOfScope = 0
            var sentOutOfScope = 0
            var stoppedAt: Int? = null
            val reachability = ReachabilityGuard()
            val endpoints = buildJsonArray {
                for ((index, planned) in plan.requests.withIndex()) {
                    if (stoppedAt != null) break
                    var failure: String? = null
                    var scope: ScopeGate.Check? = null
                    // With nothing to send or store, the request is only described and Burp is left alone.
                    if (sendRequests || addToSitemap) {
                        try {
                            val httpRequest = toHttpRequest(planned, authHeader, authValue)
                            if (!sendRequests) {
                                api.siteMap().add(
                                    HttpRequestResponse.httpRequestResponse(httpRequest, HttpResponse.httpResponse())
                                )
                                addedToSitemap++
                            } else {
                                scope = scopeGate.checkHttpRequest(httpRequest)
                                if (scope.blocked) {
                                    skippedOutOfScope++
                                } else {
                                    if (scope.warning != null) sentOutOfScope++
                                    val result = BoundedHttp.send(api, httpRequest)
                                    val status = result?.takeIf { it.hasResponse() }?.response()?.statusCode()?.toInt() ?: 0
                                    if (result == null) {
                                        failure = "No response: the request timed out or the connection failed"
                                    } else {
                                        requestsSent++
                                        if (addToSitemap) {
                                            api.siteMap().add(result)
                                            addedToSitemap++
                                        }
                                    }
                                    try {
                                        reachability.record(status)
                                    } catch (_: TargetUnreachableException) {
                                        stoppedAt = index + 1
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            // One request Burp will not build, send or store does not take the others down with it.
                            failure = e.message ?: e.javaClass.simpleName
                        }
                    }
                    var entry = describe(planned, plan.server, failure)
                    if (scope?.blocked == true) entry = JsonObject(entry + ("skipped" to JsonPrimitive("out_of_scope")))
                    add(scope?.annotate(entry) ?: entry)
                }
            }

            buildJsonObject {
                if (skippedOutOfScope > 0 && skippedOutOfScope == plan.requests.size) {
                    put("error", "Not sent: all $skippedOutOfScope requests are outside Burp's target scope (mcp_scope_mode=enforce).")
                }
                put("spec_version", plan.version)
                put("base_url", plan.server.url)
                put("total_endpoints", plan.requests.size)
                put("requests_sent", requestsSent)
                if (skippedOutOfScope > 0) put(ScopeGate.SKIPPED, skippedOutOfScope)
                if (sentOutOfScope > 0) put(ScopeGate.SENT, sentOutOfScope)
                stoppedAt?.let {
                    put("stopped", "target_unreachable")
                    put("not_sent", plan.requests.size - it)
                }
                put("added_to_sitemap", addedToSitemap)
                put("added_to_scope", addToScope && addedToScope.isNotEmpty())
                if (addedToScope.isNotEmpty()) putJsonArray("added_to_scope_urls") { addedToScope.forEach { add(it) } }
                if (addToScopeErrors.isNotEmpty()) {
                    putJsonObject("add_to_scope_errors") { addToScopeErrors.forEach { (url, msg) -> put(url, msg) } }
                }
                put("security_schemes", plan.securitySchemes)
                if (plan.warnings.isNotEmpty()) putJsonArray("warnings") { plan.warnings.forEach { add(it) } }
                put("endpoints", endpoints)
            }
        } catch (e: IllegalArgumentException) {
            buildJsonObject { put("error", e.message ?: "Not a usable OpenAPI/Swagger document") }
        } catch (e: Exception) {
            buildJsonObject { put("error", "Failed to import OpenAPI spec: ${e.message}") }
        }
    }

    private fun toHttpRequest(planned: PlannedRequest, authHeader: String?, authValue: String?): HttpRequest {
        var httpRequest = HttpRequest.httpRequestFromUrl(planned.url).withMethod(planned.method)
        for ((name, value) in planned.headers) {
            httpRequest = httpRequest.withHeader(name, value)
        }
        if (authHeader != null && authValue != null) {
            httpRequest = httpRequest.withHeader(authHeader, authValue)
        }
        val body = planned.body ?: return httpRequest
        // As bytes, so a non-ASCII example goes out as UTF-8 and Content-Length counts those bytes.
        return httpRequest.withHeader("Content-Type", body.contentType)
            .withBody(BurpByteArray.byteArray(*body.text.toByteArray(Charsets.UTF_8)))
    }

    companion object {
        private const val BODY_PREVIEW_LENGTH = 200

        /**
         * The result entry for one planned request. `server` is given only when it differs from [base],
         * the import's own server; [failure] is why the request could not be built, sent or stored.
         */
        internal fun describe(request: PlannedRequest, base: ServerUrl, failure: String? = null): JsonObject =
            buildJsonObject {
                put("method", request.method)
                put("path", request.target)
                put("operation_id", request.operationId)
                put("summary", request.summary)
                putJsonArray("tags") { request.tags.forEach { add(it) } }
                put("query_params", request.queryParameters)
                put("has_body", request.body != null)
                request.body?.let {
                    put("content_type", it.contentType)
                    put("body_preview", BodyText.render(it.text, BODY_PREVIEW_LENGTH, label = "body").text)
                }
                if (request.server != base) put("server", request.server.url)
                request.security?.let { put("security", it) }
                if (failure != null) put("error", failure)
            }
    }
}
