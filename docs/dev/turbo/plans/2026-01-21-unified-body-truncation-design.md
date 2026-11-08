# Unified HTTP Body Truncation for MCP Resources

## Problem

HTTP response bodies returned via MCP resources are inconsistently handled:
- Run results have `body_limit` parameter (default 100 chars) but no truncation metadata
- Organizer items return full responses with no truncation option
- This causes token waste for AI consumers and inconsistent behavior across endpoints

## Goals

1. **Token efficiency** - Truncate response bodies by default for AI consumption
2. **Bandwidth/performance** - Reduce payload sizes over MCP transport
3. **Consistency** - Same truncation behavior across all HTTP response resources
4. **Future-proofing** - Single mechanism for efficiency improvements

## Design

### Core Data Class

New file: `src/mcp/TruncatedHttpBody.kt`

```kotlin
data class TruncatedHttpBody(
    val fullBody: String,
    val limit: Int
) {
    val content: String
        get() = if (limit > 0 && fullBody.length > limit) fullBody.take(limit) else fullBody

    val truncated: Boolean
        get() = limit > 0 && fullBody.length > limit

    val totalLength: Int
        get() = fullBody.length

    fun toResponseFields(): Map<String, Any> = mapOf(
        "response_body" to content,
        "response_body_truncated" to truncated,
        "response_body_total_length" to totalLength
    )
}
```

### Behavior

- Default `body_limit`: 100 characters
- `body_limit=0` disables truncation (returns full body)
- Truncation indicated via metadata fields, body content unmodified (no suffix markers)
- Headers always returned in full, only body is truncated

### Endpoint Changes

#### Organizer Items (`turbo://organizer/{id}`)

Before:
```json
{
  "id": 123,
  "request": "GET /...",
  "response": "<full headers + body blob>",
  "notes": "...",
  "host": "example.com",
  "port": 443,
  "secure": true
}
```

After:
```json
{
  "id": 123,
  "request": "GET /...",
  "response_headers": "HTTP/1.1 200 OK\r\n...",
  "response_body": "<truncated to 100 chars>",
  "response_body_truncated": true,
  "response_body_total_length": 24531,
  "notes": "...",
  "host": "example.com",
  "port": 443,
  "secure": true
}
```

Supports `?body_limit=N` query parameter.

#### Run Results (`turbo://results/{id}`, `turbo://runs/{id}/results/{id}`)

Before:
```json
{
  "request": "GET /...",
  "response_headers": "HTTP/1.1 200 OK\r\n...",
  "response_body": "<truncated>",
  "status": 200,
  "length": 24531,
  "time": 142,
  "words": 1523
}
```

After:
```json
{
  "request": "GET /...",
  "response_headers": "HTTP/1.1 200 OK\r\n...",
  "response_body": "<truncated>",
  "response_body_truncated": true,
  "response_body_total_length": 24531,
  "status": 200,
  "length": 24531,
  "time": 142,
  "words": 1523
}
```

`body_limit` parameter already supported, now adds truncation metadata.

## Implementation Changes

1. **New file**: `src/mcp/TruncatedHttpBody.kt`
2. **`McpResourceHandlers.kt`**:
   - `getOrganizerItem()`: Add `bodyLimit` parameter, split response using existing `splitResponse()`, use `TruncatedHttpBody`
   - `getRequestDetail()`: Replace inline truncation logic with `TruncatedHttpBody`
   - `handleResourceRead()`: Parse `body_limit` query param for organizer URIs
3. **Tests**: Update `McpResourceHandlersTest.kt` for new fields and organizer truncation

## Breaking Changes

- Organizer items: `response` field replaced by `response_headers` + `response_body` + metadata fields
- Run results: Adds new fields (`response_body_truncated`, `response_body_total_length`) - non-breaking
