# Unified HTTP Body Truncation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Centralize HTTP response body truncation across all MCP resources with consistent field names and truncation metadata.

**Architecture:** Create a `TruncatedHttpBody` data class that handles truncation logic and outputs consistent response fields. Both `getOrganizerItem()` and `getRequestDetail()` will use this class. Organizer items will be split into headers/body to match run results.

**Tech Stack:** Kotlin, JUnit 5

---

## Task 1: Create TruncatedHttpBody Data Class

**Files:**
- Create: `src/mcp/TruncatedHttpBody.kt`
- Test: `test/kotlin/mcp/TruncatedHttpBodyTest.kt`

**Step 1: Write the failing tests**

Create `test/kotlin/mcp/TruncatedHttpBodyTest.kt`:

```kotlin
package mcp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*

class TruncatedHttpBodyTest {

    @Test
    fun `truncates body when longer than limit`() {
        val body = TruncatedHttpBody("A".repeat(500), limit = 100)

        assertEquals("A".repeat(100), body.content)
        assertTrue(body.truncated)
        assertEquals(500, body.totalLength)
    }

    @Test
    fun `returns full body when shorter than limit`() {
        val body = TruncatedHttpBody("short", limit = 100)

        assertEquals("short", body.content)
        assertFalse(body.truncated)
        assertEquals(5, body.totalLength)
    }

    @Test
    fun `returns full body when limit is zero`() {
        val body = TruncatedHttpBody("A".repeat(500), limit = 0)

        assertEquals("A".repeat(500), body.content)
        assertFalse(body.truncated)
        assertEquals(500, body.totalLength)
    }

    @Test
    fun `toResponseFields returns all three fields`() {
        val body = TruncatedHttpBody("A".repeat(200), limit = 50)
        val fields = body.toResponseFields()

        assertEquals("A".repeat(50), fields["response_body"])
        assertEquals(true, fields["response_body_truncated"])
        assertEquals(200, fields["response_body_total_length"])
    }

    @Test
    fun `handles empty body`() {
        val body = TruncatedHttpBody("", limit = 100)

        assertEquals("", body.content)
        assertFalse(body.truncated)
        assertEquals(0, body.totalLength)
    }

    @Test
    fun `handles exact limit match`() {
        val body = TruncatedHttpBody("A".repeat(100), limit = 100)

        assertEquals("A".repeat(100), body.content)
        assertFalse(body.truncated)
        assertEquals(100, body.totalLength)
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `./gradlew test --tests "mcp.TruncatedHttpBodyTest" 2>&1 | tail -10`

Expected: FAIL - class not found

**Step 3: Write minimal implementation**

Create `src/mcp/TruncatedHttpBody.kt`:

```kotlin
package mcp

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

**Step 4: Run tests to verify they pass**

Run: `./gradlew test --tests "mcp.TruncatedHttpBodyTest"`

Expected: BUILD SUCCESSFUL

**Step 5: Commit**

```bash
git add src/mcp/TruncatedHttpBody.kt test/kotlin/mcp/TruncatedHttpBodyTest.kt
git commit -m "feat(mcp): add TruncatedHttpBody data class"
```

---

## Task 2: Add Truncation Metadata to Run Results

**Files:**
- Modify: `src/mcp/McpResourceHandlers.kt` - `getRequestDetail()` function (lines 85-133)
- Modify: `test/kotlin/mcp/McpResourceHandlersTest.kt` - add new tests, update existing

**Step 1: Write the failing tests**

Add to `test/kotlin/mcp/McpResourceHandlersTest.kt` after line 137:

```kotlin
@Test
fun `getRequestDetail includes truncation metadata when truncated`() {
    val run = manager.startRun(testSessionId)
    val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    request.id = 1
    request.response = "HTTP/1.1 200 OK\r\n\r\n" + "A".repeat(500)
    run.store.add(request)

    val result = handlers.getRequestDetail(testSessionId, null, 1, bodyLimit = 100)

    assertEquals(true, result["response_body_truncated"])
    assertEquals(500, result["response_body_total_length"])
}

@Test
fun `getRequestDetail truncation metadata shows false when not truncated`() {
    val run = manager.startRun(testSessionId)
    val request = burp.Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    request.id = 1
    request.response = "HTTP/1.1 200 OK\r\n\r\nshort"
    run.store.add(request)

    val result = handlers.getRequestDetail(testSessionId, null, 1, bodyLimit = 100)

    assertEquals(false, result["response_body_truncated"])
    assertEquals(5, result["response_body_total_length"])
}
```

**Step 2: Run tests to verify they fail**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest.getRequestDetail includes truncation metadata when truncated"`

Expected: FAIL - key not found

**Step 3: Update implementation**

In `src/mcp/McpResourceHandlers.kt`, replace lines 116-132 (the inline truncation and return):

```kotlin
        val response = request.response
        val (headers, body) = splitResponse(response)
        val truncatedBody = TruncatedHttpBody(body, bodyLimit)

        return mapOf(
            "request" to request.getRequest(),
            "response_headers" to headers,
            "status" to request.code,
            "length" to request.length,
            "time" to request.time,
            "words" to request.words
        ) + truncatedBody.toResponseFields()
```

**Step 4: Run all tests to verify they pass**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest"`

Expected: BUILD SUCCESSFUL

**Step 5: Commit**

```bash
git add src/mcp/McpResourceHandlers.kt test/kotlin/mcp/McpResourceHandlersTest.kt
git commit -m "feat(mcp): add truncation metadata to run results"
```

---

## Task 3: Add body_limit and Response Splitting to Organizer Items

**Files:**
- Modify: `src/mcp/McpResourceHandlers.kt` - `getOrganizerItem()` function (lines 159-173)
- Modify: `test/kotlin/mcp/McpResourceHandlersTest.kt` - update organizer tests

**Step 1: Write the failing tests**

Add to `test/kotlin/mcp/McpResourceHandlersTest.kt` after the existing organizer tests (after line 372):

```kotlin
@Test
fun `getOrganizerItem splits response into headers and body`() {
    val fakeOrganizer = FakeOrganizerProvider(listOf(
        FakeOrganizerItem(
            id = 100,
            request = "GET /page HTTP/1.1",
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>body</html>"
        )
    ))
    val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

    val result = handlersWithOrganizer.getOrganizerItem(100)

    assertEquals("HTTP/1.1 200 OK\r\nContent-Type: text/html", result["response_headers"])
    assertEquals("<html>body</html>", result["response_body"])
    assertNull(result["response"])  // Old field should be gone
}

@Test
fun `getOrganizerItem truncates body by default`() {
    val fakeOrganizer = FakeOrganizerProvider(listOf(
        FakeOrganizerItem(
            id = 100,
            request = "GET /page HTTP/1.1",
            response = "HTTP/1.1 200 OK\r\n\r\n" + "X".repeat(500)
        )
    ))
    val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

    val result = handlersWithOrganizer.getOrganizerItem(100)

    assertEquals("X".repeat(100), result["response_body"])
    assertEquals(true, result["response_body_truncated"])
    assertEquals(500, result["response_body_total_length"])
}

@Test
fun `getOrganizerItem respects custom body_limit`() {
    val fakeOrganizer = FakeOrganizerProvider(listOf(
        FakeOrganizerItem(
            id = 100,
            request = "GET /page HTTP/1.1",
            response = "HTTP/1.1 200 OK\r\n\r\n" + "Y".repeat(500)
        )
    ))
    val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

    val result = handlersWithOrganizer.getOrganizerItem(100, bodyLimit = 200)

    assertEquals("Y".repeat(200), result["response_body"])
    assertEquals(true, result["response_body_truncated"])
}

@Test
fun `getOrganizerItem returns full body when limit is zero`() {
    val fakeOrganizer = FakeOrganizerProvider(listOf(
        FakeOrganizerItem(
            id = 100,
            request = "GET /page HTTP/1.1",
            response = "HTTP/1.1 200 OK\r\n\r\n" + "Z".repeat(500)
        )
    ))
    val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

    val result = handlersWithOrganizer.getOrganizerItem(100, bodyLimit = 0)

    assertEquals("Z".repeat(500), result["response_body"])
    assertEquals(false, result["response_body_truncated"])
}
```

**Step 2: Run tests to verify they fail**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest.getOrganizerItem splits response into headers and body"`

Expected: FAIL - unexpected value

**Step 3: Update implementation**

In `src/mcp/McpResourceHandlers.kt`, replace `getOrganizerItem()` (lines 159-173):

```kotlin
fun getOrganizerItem(id: Int, bodyLimit: Int = 100): Map<String, Any?> {
    val items = organizerProvider?.getItemsByIds(setOf(id)) ?: emptyList()
    val item = items.firstOrNull()
        ?: return mapOf("error" to "not_found")

    val (headers, body) = splitResponse(item.response)
    val truncatedBody = TruncatedHttpBody(body, bodyLimit)

    return mapOf(
        "id" to item.id,
        "request" to item.request,
        "response_headers" to headers,
        "notes" to item.notes,
        "host" to item.host,
        "port" to item.port,
        "secure" to item.secure
    ) + truncatedBody.toResponseFields()
}
```

**Step 4: Run tests to verify they pass**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest"`

Expected: BUILD SUCCESSFUL (some existing tests may need updates - see Step 4b)

**Step 4b: Update existing tests if needed**

The test at line 317 expects `response` field - update it:

```kotlin
@Test
fun `getOrganizerItem returns item by id`() {
    val fakeOrganizer = FakeOrganizerProvider(listOf(
        FakeOrganizerItem(100, "GET /page1 HTTP/1.1", "HTTP/1.1 200 OK\r\n\r\nbody", "Test notes")
    ))
    val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

    val result = handlersWithOrganizer.getOrganizerItem(100)

    assertEquals(100, result["id"])
    assertEquals("GET /page1 HTTP/1.1", result["request"])
    assertEquals("HTTP/1.1 200 OK", result["response_headers"])
    assertEquals("body", result["response_body"])
    assertEquals("Test notes", result["notes"])
}
```

**Step 5: Commit**

```bash
git add src/mcp/McpResourceHandlers.kt test/kotlin/mcp/McpResourceHandlersTest.kt
git commit -m "feat(mcp): add body_limit and response splitting to organizer items"
```

---

## Task 4: Wire body_limit Query Parameter for Organizer URIs

**Files:**
- Modify: `src/mcp/McpResourceHandlers.kt` - `handleResourceRead()` function (lines 263-318)
- Modify: `test/kotlin/mcp/McpResourceHandlersTest.kt` - add URI routing test

**Step 1: Write the failing test**

Add to `test/kotlin/mcp/McpResourceHandlersTest.kt`:

```kotlin
@Test
fun `handleResourceRead parses body_limit for organizer items`() {
    val fakeOrganizer = FakeOrganizerProvider(listOf(
        FakeOrganizerItem(
            id = 42,
            request = "GET /test HTTP/1.1",
            response = "HTTP/1.1 200 OK\r\n\r\n" + "Q".repeat(500)
        )
    ))
    val handlersWithOrganizer = McpResourceHandlers(manager, fakeOrganizer)

    val result = handlersWithOrganizer.handleResourceRead(testSessionId, "turbo://organizer/42?body_limit=150")

    assertEquals("Q".repeat(150), result["response_body"])
    assertEquals(true, result["response_body_truncated"])
}
```

**Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "mcp.McpResourceHandlersTest.handleResourceRead parses body_limit for organizer items"`

Expected: FAIL - body not truncated to 150

**Step 3: Update implementation**

In `src/mcp/McpResourceHandlers.kt`, update the organizer routing in `handleResourceRead()` (around line 267):

Change:
```kotlin
uri.matches(Regex("turbo://organizer/\\d+")) -> {
    val organizerId = parseOrganizerId(uri) ?: return mapOf("error" to "invalid_organizer_id")
    getOrganizerItem(organizerId)
}
```

To:
```kotlin
uri.matches(Regex("turbo://organizer/\\d+.*")) -> {
    val organizerId = parseOrganizerId(uri) ?: return mapOf("error" to "invalid_organizer_id")
    val params = parseQueryParams(uri)
    getOrganizerItem(
        id = organizerId,
        bodyLimit = params["body_limit"]?.toIntOrNull() ?: 100
    )
}
```

**Step 4: Run all tests to verify they pass**

Run: `./gradlew test`

Expected: BUILD SUCCESSFUL

**Step 5: Commit**

```bash
git add src/mcp/McpResourceHandlers.kt test/kotlin/mcp/McpResourceHandlersTest.kt
git commit -m "feat(mcp): wire body_limit query param for organizer URIs"
```

---

## Task 5: Final Verification and Cleanup

**Step 1: Run full test suite**

Run: `./gradlew test`

Expected: BUILD SUCCESSFUL with all tests passing

**Step 2: Build the JAR**

Run: `./gradlew jar`

Expected: BUILD SUCCESSFUL

**Step 3: Manual smoke test (optional)**

Run: `java -jar build/libs/turbo-intruder.jar --mcp`

Verify server starts without errors.

**Step 4: Commit any final adjustments**

If any tests needed fixing:
```bash
git add -A
git commit -m "fix: test adjustments for unified body truncation"
```
