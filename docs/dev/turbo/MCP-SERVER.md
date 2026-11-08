# MCP Server Quick Reference

## Starting the Server

**Standalone mode:**
```bash
java -jar build/libs/turbo-intruder.jar --mcp
```

**Burp extension:** Auto-starts when extension loads.

Server listens on `localhost:31337` using streaming HTTP transport.

---

## Available Tools

| Tool | Description |
|------|-------------|
| `start_run` | Start run (clears previous) |
| `start_concurrent_run` | Start parallel run |
| `stop_run` | Stop the active run |
| `delete_run` | Remove run and results |
| `delete_all_runs` | Clean up all runs |

**Tool parameters for start_run / start_concurrent_run:**
- `script` - Python script with `queueRequests(target, wordlists)` and `completed(results)` functions
- `base_request` - HTTP request template with `%s` injection points
- `endpoint` - Target URL (e.g., `https://example.com:443`)
- `base_input` - Optional input data for the script

---

## Available Resources

| URI | Description |
|-----|-------------|
| `turbo://runs` | List all runs |
| `turbo://runs/{id}` | Run status |
| `turbo://runs/{id}/summary` | Query summary (supports `?sort_by=`, `?limit=`, `?offset=`) |
| `turbo://runs/{id}/{n}` | Full request/response detail (supports `?body_limit=`, `?export=file`) |

Use `current` as the run ID to reference the most recent run.

### Documentation Resources

| URI | Description |
|-----|-------------|
| `turbo://docs` | List available documentation topics |
| `turbo://docs/api-quickstart` | Quick reference for scripting |
| `turbo://docs/engines` | Engine types (THREADED, BURP, BURP2) |
| `turbo://docs/settings` | Complete parameter reference |
| `turbo://docs/race-conditions` | Race condition testing with gates |
| `turbo://docs/response-processing` | Handling and filtering responses |
| `turbo://docs/decorators` | Response decorator reference |
| `turbo://docs/misc` | Wordlists and utilities |
