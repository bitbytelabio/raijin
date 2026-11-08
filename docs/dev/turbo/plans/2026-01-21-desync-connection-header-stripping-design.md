# Strip Connection Header in Desync Mode

## Problem

When `desync-agent-mode` is enabled, the `Connection:` header in HTTP responses can mislead LLMs analyzing desync/smuggling attack results. The header's value (e.g., `Connection: close`) doesn't reflect actual connection behavior in smuggling scenarios, causing confusion during analysis.

## Solution

Strip the `Connection:` header from response headers when returning data via MCP, only when `desync-agent-mode` is enabled.

## Implementation

**Location:** `src/mcp/McpResourceHandlers.kt`

**Approach:** Add a filtering step after `splitResponse()` that removes `Connection:` header lines when the setting is active.

**Affected MCP outputs:**
- `getRequestDetail()` — run results
- `getOrganizerItem()` — single Organizer item
- `getOrganizerItems()` — multiple Organizer items

**Not affected:**
- Stored responses (kept intact)
- Burp UI display
- Exported files (`export=file` parameter)

## Scope

- Strip only `Connection:` header (not `Keep-Alive:`)
- Case-insensitive matching
- MCP output only
