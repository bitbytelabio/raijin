# MCP URI Consistency Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Simplify MCP resource URIs for predictability by removing `/results/` from paths, removing the `turbo://results/{id}` shorthand, and removing `turbo://organizer/by-domain/{domain}` path-based filtering.

**Architecture:** Update URI parsing regexes in McpResourceHandlers, remove resource templates from TurboMcpServer, and update tests/docs. Breaking changes - no backwards compatibility.

**Tech Stack:** Kotlin, JUnit 5

---

### Task 1: Update parseRequestId regex

**Files:**
- Modify: `src/mcp/McpResourceHandlers.kt:291-294`
- Test: `test/kotlin/mcp/McpResourceHandlersTest.kt`

**Step 1: Update the failing test**

In `McpResourceHandlersTest.kt`, find the test at line 84-87:

```kotlin
@Test
fun `parseUri extracts request_id correctly`() {
    assertEquals(42, handlers.parseRequestId("turbo://runs/abc123/results/42"))
    assertNull(handlers.parseRequestId("turbo://runs/abc123/summary"))
}
```

Change to:

```kotlin
@Test
fun `parseUri extracts request_id correctly`() {
    assertEquals(42, handlers.parseRequestId("turbo://runs/abc123/42"))
    assertNull(handlers.parseRequestId("turbo://runs/abc123/summary"))
}
```

**Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest.parseUri extracts request_id correctly"`
Expected: FAIL (regex doesn't match new pattern)

**Step 3: Update parseRequestId implementation**

In `McpResourceHandlers.kt` line 291-294, change:

```kotlin
fun parseRequestId(uri: String): Int? {
    val match = Regex("turbo://runs/[^/]+/results/(\\d+)").find(uri)
    return match?.groupValues?.get(1)?.toIntOrNull()
}
```

To:

```kotlin
fun parseRequestId(uri: String): Int? {
    val match = Regex("turbo://runs/[^/]+/(\\d+)").find(uri)
    return match?.groupValues?.get(1)?.toIntOrNull()
}
```

**Step 4: Run test to verify it passes**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest.parseUri extracts request_id correctly"`
Expected: PASS

**Step 5: Commit**

```bash
git add src/mcp/McpResourceHandlers.kt test/kotlin/mcp/McpResourceHandlersTest.kt
git commit -m "refactor: update parseRequestId for new URI pattern"
```

---

### Task 2: Update handleResourceRead routing for run results

**Files:**
- Modify: `src/mcp/McpResourceHandlers.kt:328-396`
- Test: `test/kotlin/mcp/McpResourceHandlersTest.kt`

**Step 1: Update tests that use old URI pattern**

Find and update these tests:

Line 210: Change `"turbo://runs/current/results/1?body_limit=50"` to `"turbo://runs/current/1?body_limit=50"`

Line 223: Change `"turbo://runs/current/results/1?export=file"` to `"turbo://runs/current/1?export=file"`

**Step 2: Run tests to verify they fail**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest"`
Expected: FAIL (old regex still matches `/results/` pattern)

**Step 3: Update handleResourceRead routing**

In `McpResourceHandlers.kt`, in the `handleResourceRead` function, change line 366:

```kotlin
uri.matches(Regex("turbo://runs/[^/]+/results/\\d+.*")) -> {
```

To:

```kotlin
uri.matches(Regex("turbo://runs/[^/]+/\\d+.*")) -> {
```

**Step 4: Run tests to verify they pass**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest"`
Expected: PASS

**Step 5: Commit**

```bash
git add src/mcp/McpResourceHandlers.kt test/kotlin/mcp/McpResourceHandlersTest.kt
git commit -m "refactor: update run result routing for new URI pattern"
```

---

### Task 3: Remove turbo://results/{id} shorthand

**Files:**
- Modify: `src/mcp/McpResourceHandlers.kt:354-365`
- Modify: `src/mcp/TurboMcpServer.kt`
- Test: `test/kotlin/mcp/McpResourceHandlersTest.kt`

**Step 1: Update test to use new URI pattern**

Find line 253 test `handleResourceRead supports shorthand turbo requests id for current run`:

```kotlin
val result = handlers.handleResourceRead(testSessionId, "turbo://results/36")
```

Change to:

```kotlin
val result = handlers.handleResourceRead(testSessionId, "turbo://runs/current/36")
```

Update test name to `handleResourceRead routes result by id for current run`.

**Step 2: Remove shorthand routing from handleResourceRead**

In `McpResourceHandlers.kt`, delete lines 354-365 (the `turbo://results/\\d+.*` case):

```kotlin
uri.matches(Regex("turbo://results/\\d+.*")) -> {
    val requestId = Regex("turbo://results/(\\d+)").find(uri)?.groupValues?.get(1)?.toIntOrNull()
        ?: return mapOf("error" to "invalid_request_id")
    val params = parseQueryParams(uri)
    getRequestDetail(
        sessionId = sessionId,
        runId = null,
        requestId = requestId,
        bodyLimit = params["body_limit"]?.toIntOrNull() ?: 100,
        exportFile = params["export"] == "file"
    )
}
```

**Step 3: Remove shorthand resource templates from TurboMcpServer**

In `TurboMcpServer.kt`:

1. Remove `buildStatelessShorthandRequestDetailResourceTemplate()` function (lines 1050-1068)
2. Remove `buildShorthandRequestDetailResourceTemplate()` function (lines 1311-1329)
3. Remove references from `buildStatelessResourceSpecifications()` (line 940)
4. Remove references from `buildResourceSpecifications()` (line 1201)

**Step 4: Run tests to verify they pass**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest"`
Expected: PASS

**Step 5: Commit**

```bash
git add src/mcp/McpResourceHandlers.kt src/mcp/TurboMcpServer.kt test/kotlin/mcp/McpResourceHandlersTest.kt
git commit -m "refactor: remove turbo://results/{id} shorthand"
```

---

### Task 4: Remove turbo://organizer/by-domain/{domain} path

**Files:**
- Modify: `src/mcp/TurboMcpServer.kt`

**Step 1: Remove by-domain resource templates from TurboMcpServer**

In `TurboMcpServer.kt`:

1. Remove `buildStatelessOrganizerByDomainResourceTemplate()` function (lines 1090-1113)
2. Remove `buildOrganizerByDomainResourceTemplate()` function (lines 1351-1374)
3. Remove references from `buildStatelessResourceSpecifications()` (line 942)
4. Remove references from `buildResourceSpecifications()` (line 1203)

**Step 2: Run tests to verify nothing breaks**

Run: `./gradlew test`
Expected: PASS (query param filtering still works via `?domain=`)

**Step 3: Commit**

```bash
git add src/mcp/TurboMcpServer.kt
git commit -m "refactor: remove turbo://organizer/by-domain path, use ?domain= query param"
```

---

### Task 5: Update resource templates in TurboMcpServer

**Files:**
- Modify: `src/mcp/TurboMcpServer.kt`

**Step 1: Update stateless request detail resource template**

In `buildStatelessRequestDetailResourceTemplate()` (around line 1020), change:

```kotlin
.uri("turbo://runs/{run_id}/results/{id}")
```

To:

```kotlin
.uri("turbo://runs/{run_id}/{id}")
```

**Step 2: Update stateful request detail resource template**

In `buildRequestDetailResourceTemplate()` (around line 1281), change:

```kotlin
.uri("turbo://runs/{run_id}/results/{id}")
```

To:

```kotlin
.uri("turbo://runs/{run_id}/{id}")
```

**Step 3: Run tests**

Run: `./gradlew test`
Expected: PASS

**Step 4: Commit**

```bash
git add src/mcp/TurboMcpServer.kt
git commit -m "refactor: update resource template URIs to new pattern"
```

---

### Task 6: Update documentation

**Files:**
- Modify: `docs/MCP-SERVER.md`

**Step 1: Update resource table**

Change line 41:

```markdown
| `turbo://runs/{id}/requests/{n}` | Full request/response detail |
```

To:

```markdown
| `turbo://runs/{id}/{n}` | Full request/response detail (supports `?body_limit=`, `?export=file`) |
```

**Step 2: Commit**

```bash
git add docs/MCP-SERVER.md
git commit -m "docs: update MCP resource URIs for new pattern"
```

---

### Task 7: Update tool descriptions in TurboMcpServer

**Files:**
- Modify: `src/mcp/TurboMcpServer.kt`

**Step 1: Update start_run_async description**

Find the two occurrences of:

```kotlin
.description("Start a new run and return immediately. This clears any previous runs. Use turbo://runs/{run_id} resource to poll for status and results.")
```

These are fine - they don't mention the `/results/` path.

**Step 2: Run full test suite**

Run: `./gradlew test`
Expected: PASS

**Step 3: Build and verify**

Run: `./gradlew jar`
Expected: BUILD SUCCESSFUL

**Step 4: Final commit**

```bash
git add -A
git commit -m "chore: final cleanup for MCP URI consistency"
```

---

### Summary of changes

| Old URI | New URI |
|---------|---------|
| `turbo://runs/{run_id}/results/{id}` | `turbo://runs/{run_id}/{id}` |
| `turbo://results/{id}` | `turbo://runs/current/{id}` |
| `turbo://organizer/by-domain/{domain}` | `turbo://organizer?domain={domain}` |
