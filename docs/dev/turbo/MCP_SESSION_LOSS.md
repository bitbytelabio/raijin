# MCP Session Loss Issue

## Summary

The MCP server can lose sessions unexpectedly, causing "Session not found" errors for clients. This is a known limitation in the MCP Java SDK.

## Symptoms

- Client receives `Session not found: <session-id>` errors
- All subsequent tool calls fail with the same error
- The session cannot be recovered without reconnecting

## Root Cause

The MCP Java SDK's `HttpServletStreamableServerTransportProvider` removes sessions from its internal map when **any** send error occurs:

```java
// mcp-core/.../HttpServletStreamableServerTransportProvider.java, line 696
catch (Exception e) {
    logger.error("Failed to send message to session {}: {}", this.sessionId, e.getMessage());
    sessions.remove(this.sessionId);  // Aggressive removal
    this.asyncContext.complete();
}
```

This means transient network issues, client disconnects, or failed keep-alive pings permanently destroy the session.

## Impact

- **Runs are preserved**: The `RunManager` stores runs independently of MCP sessions
- **Session data is lost**: The SSE stream and session state in the SDK are gone
- **No automatic recovery**: The client must manually reconnect

## Workarounds

1. **Reconnect**: If you encounter "Session not found", restart the MCP client connection
2. **Use explicit run IDs**: Access runs via `turbo://runs/{run-id}` which works across sessions
3. **Shorter sessions**: For long-running work, consider periodic reconnection

## Future Fixes

Options under consideration:
- Patch the MCP SDK to implement retry logic before session removal
- Implement a custom transport provider
- Contribute a fix upstream to the MCP Java SDK

## Debugging

To enable verbose debug logging for investigating session loss:

**Standalone MCP server:**
```bash
java -Dlogback.configurationFile=./logback.xml -jar build/libs/turbo-intruder.jar --mcp
```

**Burp Suite extension:**
```bash
java -Dlogback.configurationFile=/path/to/logback.xml -jar burpsuite_pro.jar
```

Note: The Burp flag only works if logback is on Burp's classpath. For reliable debugging, use standalone mode.

Logs are written to `mcp-debug.log` and console. See `logback.xml` in the project root.

## Related

- MCP Java SDK: `mcp-guidance/java-sdk/`
- Session-scoped runs: commit `67eec3e`
- Keep-alive configuration: `TurboMcpServer.kt` line 98
