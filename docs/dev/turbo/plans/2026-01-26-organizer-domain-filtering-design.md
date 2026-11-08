# Organizer Domain Filtering

## Overview

Add domain filtering and pagination to the organizer items MCP resource.

## API

```
turbo://organizer                              # all items (no pagination)
turbo://organizer/by-domain/example.com        # page 1
turbo://organizer/by-domain/example.com?page=2 # page 2
```

Note: Path-based filtering is used because the MCP Java SDK doesn't support
RFC 6570 query param templates like `{?domain,page}`.

## Behavior

- Domain matching: exact match on host
- When filtering: paginated (10 per page), sorted by timestamp desc (nulls last), then ID desc
- Without filter: returns all IDs, no pagination

## Response Format (when filtered)

```json
{
  "count": 47,
  "page": 1,
  "page_size": 10,
  "total_pages": 5,
  "items": [{"id": 45}, {"id": 42}, ...]
}
```

## Implementation

1. Add `timeRequestSent: ZonedDateTime?` to `OrganizerItemData`
2. Update `BurpOrganizerProvider` to populate timestamp from `timingData()`
3. Add sorting and pagination in `McpResourceHandlers.listOrganizerItems()`
4. Register separate MCP resources for base list and domain-filtered list
