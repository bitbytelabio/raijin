# MCP URI Consistency Design

Date: 2026-01-26

## Problem

The MCP resource URIs have inconsistent patterns that cause confusion:

1. `turbo://runs/{run_id}/results/{id}` requires `/results/` but `turbo://organizer/{id}` doesn't
2. `turbo://results/{id}` shorthand teaches a misleading flat-collection mental model
3. Domain filtering uses both paths (`/by-domain/`) and query params (`?domain=`)

Users naturally expect `turbo://runs/{run_id}/{id}` to work (it doesn't).

## Design Principles

1. **Predictability** - Patterns should be guessable
2. **Paths identify resources** - Use paths for resource hierarchy
3. **Query params filter/modify** - Use params for filtering, pagination, presentation
4. **Numeric = ID, Named = endpoint** - Within a run, numbers are result IDs, words are special endpoints

## Proposed URI Scheme

### Runs

```
turbo://runs                         → List all runs
turbo://runs/{run_id}                → Run status
turbo://runs/{run_id}/summary        → Aggregated results
turbo://runs/{run_id}/{id}           → Individual result detail
```

Where `{run_id}` can be a UUID or `current`.

Query params:
- `/summary` supports `?sort_by=`, `?limit=`, `?offset=`
- `/{id}` supports `?body_limit=`, `?export=`

### Organizer

```
turbo://organizer                    → List all items
turbo://organizer/{id}               → Individual item
turbo://organizer/{id},{id},...      → Multiple items (batch)
```

Query params:
- List supports `?domain=`, `?page=`
- Item supports `?body_limit=`

### Docs

```
turbo://docs                         → List available topics
turbo://docs/{topic}                 → Individual doc
```

No changes needed.

## Breaking Changes

| Old | New |
|-----|-----|
| `turbo://runs/{run_id}/results/{id}` | `turbo://runs/{run_id}/{id}` |
| `turbo://results/{id}` | `turbo://runs/current/{id}` |
| `turbo://organizer/by-domain/{domain}` | `turbo://organizer?domain={domain}` |

## Implementation

### Files to modify

1. `src/mcp/TurboMcpServer.kt` - Resource templates and descriptions
2. `src/mcp/McpResourceHandlers.kt` - URI parsing and routing
3. `test/kotlin/mcp/McpResourceHandlersTest.kt` - Update tests
4. `docs/MCP-SERVER.md` - Update documentation

### Changes required

1. Remove `/results/` from URI patterns and parsing regexes
2. Remove `turbo://results/{id}` resource template entirely
3. Remove `turbo://organizer/by-domain/{domain}` resource template
4. Update all references in docs and tool descriptions
