# HTTP Stateless Mode Implementation Plan

## Goal
Add stateless HTTP mode (default) to avoid session drop issues. Single-user design using global `currentRun` pointer with a fixed sentinel session ID.

## Approach
Use MCP SDK's built-in `HttpServletStatelessServerTransport` which provides plain HTTP POST/response (no SSE, no sessions). Pass `"stateless"` as sessionId to all handlers so existing session-scoped logic works unchanged.

## Files to Modify

### `src/mcp/TurboMcpServer.kt`

1. **Add constant at top:**
   ```kotlin
   companion object {
       const val STATELESS_MODE = true
   }
   ```

2. **Modify `startInternal()`:**
   - Add conditional transport creation
   - Stateless: `HttpServletStatelessServerTransport.builder().jsonMapper(jsonMapper).messageEndpoint("/").build()`
   - SSE: existing `HttpServletStreamableServerTransportProvider` code (preserve in else branch)

3. **Modify each tool builder method (`buildStartRunTool()`, etc.):**
   - Return `Any` type (or use a sealed interface)
   - Conditionally create either `McpStatelessServerFeatures.SyncToolSpecification` or `McpServerFeatures.SyncToolSpecification`
   - In stateless mode, pass `"stateless"` instead of `exchange.sessionId()`

4. **Modify `buildToolSpecifications()` return type:**
   - Change from `List<McpServerFeatures.SyncToolSpecification>` to handle both types

5. **Modify resource builders similarly** for `buildResourceSpecifications()`

## Key Changes

### Tool Handler Pattern

**Current (SSE mode):**
```kotlin
McpServerFeatures.SyncToolSpecification.builder()
    .tool(tool)
    .callHandler { exchange, request ->
        toolHandlers.foo(sessionId = exchange.sessionId(), ...)
    }
    .build()
```

**Stateless mode:**
```kotlin
McpStatelessServerFeatures.SyncToolSpecification(tool) { ctx, request ->
    toolHandlers.foo(sessionId = "stateless", ...)
}
```

### Transport Creation

**Current:**
```kotlin
val transportProvider = HttpServletStreamableServerTransportProvider.builder()
    .jsonMapper(jsonMapper)
    .mcpEndpoint("/")
    .keepAliveInterval(Duration.ofSeconds(30))
    .build()
```

**Stateless:**
```kotlin
val transport = HttpServletStatelessServerTransport.builder()
    .jsonMapper(jsonMapper)
    .messageEndpoint("/")
    .build()
```

## What Stays Unchanged
- `McpToolHandlers.kt` - receives sessionId parameter, works with `"stateless"` value
- `McpResourceHandlers.kt` - same
- `RunManager.kt` - uses sessionId for currentRunBySession map, `"stateless"` acts as single shared session
- All business logic in handlers

## Verification

1. Build: `./gradlew jar`
2. Run standalone: `java -jar build/libs/turbo-intruder.jar --mcp`
3. Test with Claude Code MCP client:
   - Start a run
   - Check status via resource
   - Verify no session loss errors
4. Verify session-scoped operations work (all use same `"stateless"` session)
