# MCP Query Tool Design

## Problem

Turbo-intruder runs can produce 10K-100K results. Claude needs to:
- Filter by criteria (status code, response content, length)
- Get statistical summaries
- Find top-N / anomalies

Pagination is tedious and inefficient for this scale.

## Solution: Query Tool

Expose a `query_results` tool that accepts filter parameters and returns matching results.

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `status_code` | int | Filter by HTTP status |
| `contains` | string | Filter responses containing text |
| `min_length` | int | Minimum response length |
| `max_length` | int | Maximum response length |
| `sort_by` | string | Field to sort by (e.g., `length`, `time`) |
| `sort_order` | string | `asc` or `desc` |
| `limit` | int | Max results to return (default/cap: 100) |

### Response

Returns:
- `total_matches`: Count of all matching results
- `results`: Array of matching results (up to limit)
- Each result includes: request summary, status, length, timing, response excerpt

### Usage Pattern

Claude iteratively refines queries:
1. Query with broad filter, see total matches
2. Narrow down with additional filters
3. Sort to find extremes/anomalies
4. Request specific results for detailed analysis

### Future Enhancement

Add `get_results_summary` tool for statistical overview (status distribution, timing histogram) before drilling down.
