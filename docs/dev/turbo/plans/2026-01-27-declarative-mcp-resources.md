# Declarative MCP Resource Definitions

## Problem

Parameter passing bugs keep recurring in MCP resource handlers. The root cause is scattered definitions:
1. URI pattern in `.uri()`
2. Parameters manually documented in `.description()`
3. Parameter parsing in handler code
4. Default values in handler code
5. Duplicate definitions for stateless vs stateful modes

When these get out of sync, resources fail silently (e.g., `turbo://organizer?domain=foo` returns "Resource not found" because the SDK does exact URI matching for non-template URIs).

## Solution

A declarative DSL that defines resources once and generates:
1. SDK resource specs (both stateless and stateful)
2. URI matching that handles query params correctly
3. Typed parameter parsing with defaults
4. Auto-generated descriptions

## Design

### Core Types

```kotlin
// src/mcp/resource/ResourceParam.kt

enum class ParamType { STRING, INT, BOOL }

sealed class ResourceParam(
    val name: String,
    val type: ParamType,
    val description: String,
    val required: Boolean
) {
    class PathParam(
        name: String,
        description: String = ""
    ) : ResourceParam(name, ParamType.STRING, description, required = true)

    class QueryParam<T>(
        name: String,
        type: ParamType,
        val default: T?,
        description: String
    ) : ResourceParam(name, type, description, required = default == null)
}
```

### Parsed Parameters

```kotlin
// src/mcp/resource/ParsedParams.kt

class ParsedParams(
    private val pathParams: Map<String, String>,
    private val queryParams: Map<String, String>,
    private val definitions: List<ResourceParam>
) {
    fun string(name: String): String? = queryParams[name] ?: findDefault(name)
    fun stringRequired(name: String): String = string(name) ?: error("Missing required param: $name")

    fun int(name: String): Int? = queryParams[name]?.toIntOrNull() ?: findDefault(name)
    fun intRequired(name: String): Int = int(name) ?: error("Missing required param: $name")

    fun bool(name: String): Boolean? = queryParams[name]?.toBooleanStrictOrNull() ?: findDefault(name)
    fun boolRequired(name: String): Boolean = bool(name) ?: error("Missing required param: $name")

    fun path(name: String): String = pathParams[name] ?: error("Missing path param: $name")

    private inline fun <reified T> findDefault(name: String): T? {
        val param = definitions.find { it.name == name } as? ResourceParam.QueryParam<*>
        return param?.default as? T
    }
}
```

### Resource Definition

```kotlin
// src/mcp/resource/ResourceDefinition.kt

class ResourceDefinition(
    val uriPattern: String,        // e.g., "turbo://organizer" or "turbo://runs/{run_id}/summary"
    val name: String,
    val baseDescription: String,
    val mimeType: String = "application/json",
    val pathParams: List<ResourceParam.PathParam>,
    val queryParams: List<ResourceParam.QueryParam<*>>,
    val handler: (sessionId: String, params: ParsedParams) -> Map<String, Any?>
) {
    /** Base URI without query params, used for SDK registration */
    val baseUri: String get() = uriPattern

    /** Auto-generated full description including query params */
    val fullDescription: String get() = buildString {
        append(baseDescription)
        if (queryParams.isNotEmpty()) {
            append(". Query params: ")
            append(queryParams.joinToString(", ") { param ->
                buildString {
                    append(param.name)
                    if (param.description.isNotEmpty()) {
                        append(" (")
                        append(param.description)
                        param.default?.let { append(", default: $it") }
                        append(")")
                    } else {
                        param.default?.let { append(" (default: $it)") }
                    }
                }
            })
        }
    }

    /** Check if a request URI matches this resource */
    fun matches(requestUri: String): Boolean {
        val baseRequestUri = requestUri.substringBefore('?')
        return if (pathParams.isEmpty()) {
            baseRequestUri == uriPattern
        } else {
            val regex = uriPattern.replace(Regex("\\{[^}]+\\}"), "[^/]+")
            baseRequestUri.matches(Regex(regex))
        }
    }

    /** Parse parameters from a request URI */
    fun parseParams(requestUri: String): ParsedParams {
        val pathValues = extractPathParams(requestUri)
        val queryValues = extractQueryParams(requestUri)
        return ParsedParams(pathValues, queryValues, pathParams + queryParams)
    }

    private fun extractPathParams(requestUri: String): Map<String, String> {
        // Extract path variable values using regex
        val baseUri = requestUri.substringBefore('?')
        val patternParts = uriPattern.split("/")
        val uriParts = baseUri.split("/")

        return pathParams.associate { param ->
            val index = patternParts.indexOfFirst { it == "{${param.name}}" }
            param.name to (uriParts.getOrNull(index) ?: "")
        }
    }

    private fun extractQueryParams(requestUri: String): Map<String, String> {
        val queryStart = requestUri.indexOf('?')
        if (queryStart == -1) return emptyMap()

        return requestUri.substring(queryStart + 1)
            .split('&')
            .mapNotNull { param ->
                val parts = param.split('=', limit = 2)
                if (parts.size == 2) parts[0] to parts[1] else null
            }
            .toMap()
    }
}
```

### Kotlin DSL

```kotlin
// src/mcp/resource/ResourceDsl.kt

@DslMarker
annotation class ResourceDslMarker

@ResourceDslMarker
class ResourceBuilder(private val uriPattern: String) {
    var name: String = ""
    var description: String = ""
    var mimeType: String = "application/json"

    private val pathParams = mutableListOf<ResourceParam.PathParam>()
    private val queryParams = mutableListOf<ResourceParam.QueryParam<*>>()
    private var handlerFn: ((String, ParsedParams) -> Map<String, Any?>)? = null

    init {
        // Auto-extract path params from URI pattern
        Regex("\\{([^}]+)\\}").findAll(uriPattern).forEach { match ->
            pathParams.add(ResourceParam.PathParam(match.groupValues[1]))
        }
    }

    fun query(name: String, type: ParamType, default: Any? = null, description: String = "") {
        queryParams.add(ResourceParam.QueryParam(name, type, default, description))
    }

    // Convenience methods
    fun queryString(name: String, default: String? = null, description: String = "") =
        query(name, ParamType.STRING, default, description)

    fun queryInt(name: String, default: Int? = null, description: String = "") =
        query(name, ParamType.INT, default, description)

    fun queryBool(name: String, default: Boolean? = null, description: String = "") =
        query(name, ParamType.BOOL, default, description)

    fun handle(handler: (sessionId: String, params: ParsedParams) -> Map<String, Any?>) {
        handlerFn = handler
    }

    fun build(): ResourceDefinition {
        require(name.isNotEmpty()) { "Resource name is required" }
        require(description.isNotEmpty()) { "Resource description is required" }
        require(handlerFn != null) { "Resource handler is required" }

        return ResourceDefinition(
            uriPattern = uriPattern,
            name = name,
            baseDescription = description,
            mimeType = mimeType,
            pathParams = pathParams.toList(),
            queryParams = queryParams.toList(),
            handler = handlerFn!!
        )
    }
}

fun resource(uriPattern: String, init: ResourceBuilder.() -> Unit): ResourceDefinition {
    return ResourceBuilder(uriPattern).apply(init).build()
}
```

### Resource Registry

```kotlin
// src/mcp/resource/ResourceRegistry.kt

class ResourceRegistry(
    private val jsonMapper: ObjectMapper = ObjectMapper()
) {
    private val resources = mutableListOf<ResourceDefinition>()

    fun register(resource: ResourceDefinition) {
        resources.add(resource)
    }

    fun register(vararg definitions: ResourceDefinition) {
        resources.addAll(definitions)
    }

    /** Find matching resource for a request URI */
    fun findResource(requestUri: String): ResourceDefinition? {
        return resources.find { it.matches(requestUri) }
    }

    /** Generate stateless SDK resource specs */
    fun buildStatelessSpecs(): List<McpStatelessServerFeatures.SyncResourceSpecification> {
        return resources.map { def ->
            val resource = McpSchema.Resource.builder()
                .uri(def.baseUri)
                .name(def.name)
                .description(def.fullDescription)
                .mimeType(def.mimeType)
                .build()

            McpStatelessServerFeatures.SyncResourceSpecification(resource) { _, request ->
                val params = def.parseParams(request.uri())
                val result = def.handler(STATELESS_SESSION_ID, params)
                McpSchema.ReadResourceResult(
                    listOf(McpSchema.TextResourceContents(
                        request.uri(),
                        def.mimeType,
                        jsonMapper.writeValueAsString(result)
                    ))
                )
            }
        }
    }

    /** Generate stateful SDK resource specs */
    fun buildStatefulSpecs(): List<McpServerFeatures.SyncResourceSpecification> {
        return resources.map { def ->
            val resource = McpSchema.Resource.builder()
                .uri(def.baseUri)
                .name(def.name)
                .description(def.fullDescription)
                .mimeType(def.mimeType)
                .build()

            McpServerFeatures.SyncResourceSpecification(resource) { exchange, request ->
                val params = def.parseParams(request.uri())
                val result = def.handler(exchange.sessionId(), params)
                McpSchema.ReadResourceResult(
                    listOf(McpSchema.TextResourceContents(
                        request.uri(),
                        def.mimeType,
                        jsonMapper.writeValueAsString(result)
                    ))
                )
            }
        }
    }

    companion object {
        private const val STATELESS_SESSION_ID = "stateless"
    }
}
```

### Resource Definitions

```kotlin
// src/mcp/resource/McpResourceDefinitions.kt

fun createResourceDefinitions(handlers: McpResourceHandlers): List<ResourceDefinition> = listOf(

    // === Run Resources ===

    resource("turbo://runs") {
        name = "List of all runs"
        description = "List all runs with their status and result counts"
        handle { sessionId, _ ->
            handlers.listRuns(sessionId)
        }
    },

    resource("turbo://runs/{run_id}") {
        name = "Status of a specific run"
        description = "Get detailed status of a specific run including running state, result count, and status message. Use 'current' for the most recent run"
        handle { sessionId, params ->
            handlers.getRunStatus(sessionId, params.path("run_id"))
        }
    },

    resource("turbo://runs/{run_id}/summary") {
        name = "Summary from a run"
        description = "Get paginated summary from a run"
        queryString("sort_by", default = "id", description = "id|status|length|time|wordcount")
        queryBool("descending", default = true)
        queryInt("limit", default = 100)
        queryInt("offset", default = 0)
        handle { sessionId, params ->
            handlers.getResults(
                sessionId = sessionId,
                runId = params.path("run_id"),
                sortBy = params.string("sort_by")!!,
                descending = params.bool("descending")!!,
                limit = params.int("limit")!!,
                offset = params.int("offset")!!
            )
        }
    },

    resource("turbo://runs/{run_id}/{id}") {
        name = "Details of a specific result"
        description = "Get request and response details for a result"
        queryInt("body_limit", default = 100, description = "chars of body to include")
        queryString("export", description = "set to 'file' to write to temp files")
        handle { sessionId, params ->
            handlers.getRequestDetail(
                sessionId = sessionId,
                runId = params.path("run_id"),
                requestId = params.path("id").toInt(),
                bodyLimit = params.int("body_limit")!!,
                exportFile = params.string("export") == "file"
            )
        }
    },

    // === Organizer Resources ===

    resource("turbo://organizer") {
        name = "List of all Organizer items"
        description = "List all items in Burp's Organizer with their IDs"
        queryString("domain", description = "filter by host")
        queryInt("page", default = 1)
        handle { _, params ->
            handlers.listOrganizerItems(
                domain = params.string("domain"),
                page = params.int("page")!!
            )
        }
    },

    resource("turbo://organizer/{id}") {
        name = "Details of an Organizer item"
        description = "Get the full request, response, and notes for an Organizer item by ID"
        queryInt("body_limit", default = 100)
        handle { _, params ->
            handlers.getOrganizerItem(
                id = params.path("id").toInt(),
                bodyLimit = params.int("body_limit")!!
            )
        }
    },

    // === Documentation Resources ===

    resource("turbo://docs") {
        name = "Documentation topics"
        description = "List available documentation topics for scripting reference"
        handle { _, _ ->
            handlers.listDocs()
        }
    },

    resource("turbo://docs/{topic}") {
        name = "Documentation for a specific topic"
        description = "Get documentation content. Topics: api-quickstart, engines, settings, race-conditions, response-processing, decorators, misc"
        mimeType = "text/markdown"
        handle { _, params ->
            handlers.getDoc(params.path("topic"))
        }
    }
)
```

### Integration with TurboMcpServer

```kotlin
// In TurboMcpServer.kt

class TurboMcpServer(...) {
    private val resourceRegistry = ResourceRegistry(jsonMapper).apply {
        register(*createResourceDefinitions(resourceHandlers).toTypedArray())
    }

    // Replace individual buildStateless* methods with:
    private fun buildStatelessResourceSpecs() = resourceRegistry.buildStatelessSpecs()
    private fun buildStatefulResourceSpecs() = resourceRegistry.buildStatefulSpecs()

    // In server setup:
    // .resources(buildStatelessResourceSpecs())
}
```

## Custom URI Matching (Verified)

The SDK supports custom URI template managers. Both `SyncSpecification<S>` (stateful) and `StatelessSyncSpecification` builders expose `.uriTemplateManagerFactory()`.

The `McpUriTemplateManager` interface requires 4 methods:
- `getVariableNames()` - list of `{var}` names from template
- `extractVariableValues(uri)` - extract var values from request URI
- `matches(uri)` - checks if URI matches template (**key method**)
- `isUriTemplate(uri)` - checks if template has variables

Our fix: create a custom manager where `matches()` strips query params before comparing.

## Custom URI Template Manager

```kotlin
// src/mcp/resource/QueryParamAwareMcpUriTemplateManager.kt

class QueryParamAwareUriTemplateManager(private val uriTemplate: String) : McpUriTemplateManager {
    private val delegate = DefaultMcpUriTemplateManager(uriTemplate)

    override fun getVariableNames(): List<String> = delegate.variableNames

    override fun extractVariableValues(requestUri: String): Map<String, String> {
        // Strip query params before extracting
        return delegate.extractVariableValues(requestUri.substringBefore('?'))
    }

    override fun matches(uri: String): Boolean {
        // Strip query params before matching
        val baseUri = uri.substringBefore('?')

        // For non-template URIs, do prefix match to allow query params
        if (!isUriTemplate(uriTemplate)) {
            return baseUri == uriTemplate
        }

        return delegate.matches(baseUri)
    }

    override fun isUriTemplate(uri: String): Boolean = delegate.isUriTemplate(uri)
}

class QueryParamAwareUriTemplateManagerFactory : McpUriTemplateManagerFactory {
    override fun create(uriTemplate: String) = QueryParamAwareUriTemplateManager(uriTemplate)
}
```

Then in `TurboMcpServer`, pass this factory when building the server:

```kotlin
statelessServer = McpServer.sync(transport)
    .serverInfo("turbo-simulator", "1.0.0")
    .uriTemplateManagerFactory(QueryParamAwareUriTemplateManagerFactory())  // <-- ADD THIS
    .capabilities(...)
    .tools(...)
    .resources(...)
    .build()
```

## Implementation Plan

1. **Create `src/mcp/resource/` package** with:
   - `ResourceParam.kt` - Parameter types
   - `ParsedParams.kt` - Typed parameter access
   - `ResourceDefinition.kt` - Resource definition class
   - `ResourceDsl.kt` - Kotlin DSL
   - `ResourceRegistry.kt` - Registry and spec generation
   - `QueryParamAwareUriTemplateManager.kt` - Custom URI matching
   - `McpResourceDefinitions.kt` - All resource definitions

2. **Update `TurboMcpServer.kt`**:
   - Use `ResourceRegistry` instead of individual `build*` methods
   - Pass custom `McpUriTemplateManagerFactory` to SDK
   - Remove ~400 lines of duplicate resource building code

3. **Update `McpResourceHandlers.kt`**:
   - Remove `handleResourceRead()` (no longer needed - registry handles routing)
   - Keep handler methods (`listRuns`, `getResults`, etc.)

4. **Add tests**:
   - Test each resource definition with query params
   - Test URI matching with various query param combinations
   - Test parameter parsing and defaults

## Benefits

1. **Single source of truth** - Each resource defined once
2. **Auto-generated descriptions** - Query params automatically documented
3. **Type-safe parameter access** - `params.int("limit")` instead of manual parsing
4. **No more URI matching bugs** - Query params handled correctly by custom matcher
5. **~50% less code** - Remove duplicate stateless/stateful definitions
6. **Easier to add resources** - Just add a `resource { }` block

## Verification Status

**Verified:** The MCP Java SDK supports custom `McpUriTemplateManagerFactory`:
- Both `SyncSpecification<S>` and `StatelessSyncSpecification` builders expose `.uriTemplateManagerFactory()`
- Interface is simple: `create(uriTemplate: String): McpUriTemplateManager`
- Custom matcher can strip query params in `matches()` method

## File Changes Summary

| File | Action |
|------|--------|
| `src/mcp/resource/ResourceParam.kt` | **Create** - Parameter types |
| `src/mcp/resource/ParsedParams.kt` | **Create** - Typed param access |
| `src/mcp/resource/ResourceDefinition.kt` | **Create** - Resource definition |
| `src/mcp/resource/ResourceDsl.kt` | **Create** - Kotlin DSL |
| `src/mcp/resource/ResourceRegistry.kt` | **Create** - Registry + spec generation |
| `src/mcp/resource/QueryParamAwareUriTemplateManager.kt` | **Create** - Custom URI matching |
| `src/mcp/resource/McpResourceDefinitions.kt` | **Create** - All resource definitions |
| `src/mcp/TurboMcpServer.kt` | **Modify** - Use registry, remove ~400 lines |
| `src/mcp/McpResourceHandlers.kt` | **Modify** - Remove `handleResourceRead()` |
| `test/kotlin/mcp/ResourceRegistryTest.kt` | **Create** - Tests for new system |
