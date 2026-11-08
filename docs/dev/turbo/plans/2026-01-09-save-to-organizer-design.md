# Save to Organizer MCP Tool

## Overview

Add MCP tool to save request/responses from a run into Burp's Organizer with custom notes.

## API

**Tool:** `save_to_organizer`

**Parameters:**
- `run_id` (optional string) - Which run to pull requests from. Defaults to current run.
- `items` (required string) - JSON array of objects with `request_id` (int) and `notes` (string)

**Example call:**
```json
{
  "run_id": "abc-123",
  "items": "[{\"request_id\": 5, \"notes\": \"Interesting 403 bypass\"}, {\"request_id\": 12, \"notes\": \"Possible SQLi\"}]"
}
```

**Returns:**
```json
{
  "saved": [5, 12],
  "errors": [
    {"request_id": 99, "error": "Request not found"}
  ]
}
```

## Implementation

| File | Change |
|------|--------|
| `src/mcp/OrganizerProvider.kt` | Add `sendToOrganizer(request, notes)` method |
| `src/mcp/McpToolHandlers.kt` | Add `saveToOrganizer()` handler |
| `src/mcp/TurboMcpServer.kt` | Add tool definition and registration |
| `test/kotlin/mcp/McpToolHandlersTest.kt` | Add tests for new tool |
