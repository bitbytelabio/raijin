# HTTP Entry Abstraction

## Problem

Run results and organizer items are both lists of HTTP request/response pairs with metadata, but they have completely separate listing, filtering, pagination, and rendering logic. The organizer list view only returns item IDs with no summary fields, requiring individual fetches to see any context.

## Design

### Thin, Composable Abstraction

The shared code provides reusable building blocks — not a monolithic framework. Each source composes its own resource handlers using these building blocks, adding source-specific behaviour (aggregations, export modes, extra query params) as plain code rather than through extension points.

This avoids the leaky abstraction problem where every new feature requires a new hook in the generic code.

### Why Composition Over Inheritance

Composition (single `HttpEntry` with extra maps) chosen over inheritance (typed subclasses) because:
- Rendering is inherently dynamic (JSON output), so typed fields don't add value
- Sorting by arbitrary field name is a natural map lookup with composition; with inheritance it requires reflection or a `toMap()` method that defeats the purpose
- Keeps shared logic truly generic without needing to know about subclasses

### Core Data Model

A single `HttpEntry` type represents any HTTP request/response with metadata:

```kotlin
data class HttpEntry(
    val id: Int,
    val request: String,
    val response: String,
    val host: String,
    val port: Int,
    val secure: Boolean,
    // Common metadata
    val status: Int?,
    val length: Int?,
    val path: String?,
    val notes: String?,
    // Source-specific fields
    val extraSummary: Map<String, Any?> = emptyMap(),  // list + detail views
    val extraDetail: Map<String, Any?> = emptyMap()    // detail view only
)
```

### Provider Interface

Each data source implements:

```kotlin
interface HttpEntryProvider {
    fun query(
        sort: String, descending: Boolean,
        offset: Int, limit: Int,
        filters: Map<String, String>
    ): HttpEntryPage

    fun getByIds(ids: Set<Int>): List<HttpEntry>
}

data class HttpEntryPage(
    val entries: List<HttpEntry>,
    val totalCount: Int
)
```

The provider owns its own query strategy. Large-dataset providers (run results with millions of entries) delegate to native storage sorting/pagination. Small-dataset providers (organizer) can use a shared in-memory helper that loads, filters, sorts, and paginates a list.

Two initial implementations: `RunResultsEntryProvider` and `OrganizerEntryProvider`.

### Shared Building Blocks

#### Summary rendering

```kotlin
fun HttpEntry.toSummaryMap(): Map<String, Any?> = mapOf(
    "id" to id,
    "status" to status,
    "host" to host,
    "path" to path,
    "length" to length,
    "notes" to notes?.take(80)
) + extraSummary
```

#### Detail rendering

```kotlin
fun HttpEntry.toDetailMap(bodyLimit: Int): Map<String, Any?> {
    val (headers, body) = splitResponse(response)
    val truncated = TruncatedHttpBody(body, bodyLimit)
    return mapOf(
        "id" to id,
        "request" to request,
        "response_headers" to filterHeaders(headers),
        "host" to host,
        "port" to port,
        "secure" to secure,
        "status" to status,
        "length" to length,
        "notes" to notes
    ) + extraSummary + extraDetail + truncated.toResponseFields()
}
```

#### Listing utility

`listEntries()` takes a provider and query parameters, delegates to the provider for efficient querying, and formats the standard response shape:

```kotlin
fun listEntries(
    provider: HttpEntryProvider,
    sort: String, descending: Boolean,
    offset: Int, limit: Int,
    filters: Map<String, String>
): Map<String, Any> {
    val page = provider.query(sort, descending, offset, limit, filters)
    return mapOf(
        "total_count" to page.totalCount,
        "offset" to offset,
        "limit" to limit,
        "items" to page.entries.map { it.toSummaryMap() }
    )
}
```

#### In-memory query helper

A shared utility for providers with small datasets that don't need native query pushdown:

```kotlin
fun inMemoryQuery(
    entries: List<HttpEntry>,
    sort: String, descending: Boolean,
    offset: Int, limit: Int,
    filters: Map<String, String>
): HttpEntryPage
```

Handles common filters (host, searchNotes, searchRequest, searchResponse — case-insensitive substring), sorts by any summary field (common fields or extraSummary via map lookup), and applies offset/limit pagination.

### How Sources Compose

Each source writes its own resource handler using the building blocks. This is a few lines of glue code per source, but gives full control over source-specific behaviour.

**Organizer** — small dataset, uses in-memory query helper via provider:

```kotlin
resource("turbo://organizer") {
    // ... query params ...
    handle { params ->
        listEntries(organizerProvider, sort = "id", descending = true, ...)
    }
}
```

**Run results** — large dataset, provider delegates to ResultStore natively. Adds status code aggregation on top:

```kotlin
resource("turbo://runs/{run_id}/summary") {
    // ... query params ...
    handle { params ->
        val listing = listEntries(runResultsProvider, sort = "anomaly_rank", descending = true, ...)
        listing + mapOf("status_codes" to runResultsProvider.getUniqueStatusCodes())
    }
}
```

**Run result detail** — adds export-to-file mode on top:

```kotlin
resource("turbo://runs/{run_id}/{id}") {
    // ... query params including export ...
    handle { params ->
        val entry = runResultsProvider.getByIds(setOf(id)).first()
        if (params.string("export") == "file") {
            exportToFiles(entry, runId)
        } else {
            entry.toDetailMap(bodyLimit)
        }
    }
}
```

### What Stays Source-Specific

These features are not part of the shared abstraction:

- **Status code aggregation** — run results adds `status_codes` to list response
- **Export to file** — run results detail supports `export=file` query param
- **Mutation tools** — `set_organizer_notes`, `save_to_organizer` remain as separate tools
- **Run status embedding** — `getRunStatus()` includes top 20 results when finished
- **Source-specific filters** — each source adds its own query params (label, domain, etc.)
- **Source-specific extra fields** — run results: `label`, `time`, `wordcount`, `anomaly_rank` in extraSummary; `words` in extraDetail. Organizer: none currently.

## Key Design Decisions

- **Composition over inheritance** — extra maps over typed subclasses, because output is dynamic JSON and sorting needs map lookup
- **Provider owns query strategy** — large datasets (run results) use native storage sorting; small datasets (organizer) use shared in-memory helper. The `listEntries()` function is agnostic.
- **`label` is not `notes`** — `notes` is a common field for user-editable annotations (nullable). Run results' `label` is a programmatic tag, stored in `extraSummary`.
- **Thin abstraction** — shared code is four things: data model, provider interface, rendering extensions, listing utility. Source-specific features are plain code in each handler.

## Migration

### Replaced
- `Request.toSummaryMap()` — replaced by `HttpEntry.toSummaryMap()`
- `listOrganizerItems()` — replaced by `listEntries()` + `OrganizerEntryProvider`
- `getOrganizerItem()` / `getOrganizerItems()` — replaced by `HttpEntry.toDetailMap()`
- `getResults()` — replaced by `listEntries()` + `RunResultsEntryProvider`
- Run result detail rendering — replaced by `HttpEntry.toDetailMap()` + source-specific export

### Preserved
- Status code aggregation (source-specific code in run results handler)
- Export to file (source-specific code in run results detail handler)
- Mutation tools (unchanged, separate from read abstraction)
- Run status summary with embedded top results (calls `toSummaryMap()`)
- Batch fetch (via `HttpEntryProvider.getByIds()`)
- Desync mode connection header filtering (in shared `filterHeaders()`)
- Body truncation (in shared `toDetailMap()`)
- Script appending in save_to_organizer (unchanged)
- Native ResultStore sorting/pagination for large datasets

### Breaking Changes
- Organizer pagination changes from page-based to offset/limit
- Organizer list response shape changes to include summary fields
- Run results response shape may change slightly to match unified format
