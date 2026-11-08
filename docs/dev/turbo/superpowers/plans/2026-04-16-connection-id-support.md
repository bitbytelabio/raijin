# Connection ID Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `connectionId` parameter to `queue()` allowing users to pin requests to named connections via Montoya API.

**Architecture:** Add `connectionId: String?` field to `Request`, pass through from Python API to Kotlin engine, use Montoya's 3-arg `sendRequest(request, httpMode, connectionId)` when specified. Mutual exclusion with gates enforced via validation.

**Tech Stack:** Kotlin, Jython, Montoya API

---

## File Structure

| File | Change | Responsibility |
|------|--------|----------------|
| `src/Request.kt` | Modify | Add `connectionId: String?` field |
| `src/RequestEngine.kt` | Modify | Add param to `queue()`, validate, store on request |
| `resources/ScriptEnvironment.py` | Modify | Add param to Python `queue()`, pass through |
| `src/BurpRequestEngine.kt` | Modify | Use connectionId when calling Montoya |
| `test/kotlin/BurpRequestTest.kt` | Modify | Add tests for connectionId field |
| `test/kotlin/RequestEngineTest.kt` | Create | Test queue() validation |

---

### Task 1: Add connectionId Field to Request

**Files:**
- Modify: `src/Request.kt:26`
- Test: `test/kotlin/BurpRequestTest.kt`

- [ ] **Step 1: Write the failing test**

Add to `test/kotlin/BurpRequestTest.kt`:

```kotlin
@Test
fun `connectionId field defaults to null`() {
    val req = Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    assertNull(req.connectionId)
}

@Test
fun `connectionId field can be set`() {
    val req = Request("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    req.connectionId = "my-connection"
    assertEquals("my-connection", req.connectionId)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "burp.BurpRequestTest.connectionId*" --info`

Expected: FAIL with "Unresolved reference: connectionId"

- [ ] **Step 3: Add connectionId field to Request**

In `src/Request.kt`, add after line 26 (`var connectionID: Int = -1`):

```kotlin
var connectionId: String? = null   // user-specified connection name (input)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew test --tests "burp.BurpRequestTest.connectionId*" --info`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/Request.kt test/kotlin/BurpRequestTest.kt
git commit -m "feat: add connectionId field to Request"
```

---

### Task 2: Add connectionId Parameter to RequestEngine.queue()

**Files:**
- Modify: `src/RequestEngine.kt:99`
- Create: `test/kotlin/RequestEngineTest.kt`

- [ ] **Step 1: Write the failing test for connectionId storage**

Create `test/kotlin/RequestEngineTest.kt`:

```kotlin
package burp

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach

class RequestEngineTest {

    private lateinit var engine: TestRequestEngine

    @BeforeEach
    fun setup() {
        engine = TestRequestEngine()
        engine.start()
    }

    @Test
    fun `queue stores connectionId on request`() {
        engine.queue("GET / HTTP/1.1\r\nHost: test.local\r\n\r\n", emptyList<Any>(), 0, null, null, "", 0, 1000, emptyList(), 0, null, null, true, "my-conn")
        
        val queued = engine.requestQueue.poll()
        assertNotNull(queued)
        assertEquals("my-conn", queued!!.connectionId)
    }

    @Test
    fun `queue allows null connectionId`() {
        engine.queue("GET / HTTP/1.1\r\nHost: test.local\r\n\r\n", emptyList<Any>(), 0, null, null, "", 0, 1000, emptyList(), 0, null, null, true, null)
        
        val queued = engine.requestQueue.poll()
        assertNotNull(queued)
        assertNull(queued!!.connectionId)
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "burp.RequestEngineTest" --info`

Expected: FAIL with "No value passed for parameter 'connectionId'" or similar

- [ ] **Step 3: Add connectionId parameter to queue()**

In `src/RequestEngine.kt`, modify line 99 to add the parameter:

```kotlin
fun queue(template: String, payloads: List<kotlin.Any?> = emptyList<kotlin.Any>(), learnBoring: Int = 0, callback: ((Request, Boolean) -> Boolean)? = null, gateName: String? = null, label: String = "", pauseBefore: Int = 0, pauseTime: Int = 1000, pauseMarkers: List<String> = emptyList(), delay: Long = 0, endpoint: String? = null, pythonEngine: Any? = null, fixContentLength: Boolean = true, connectionId: String? = null) {
```

Then add after line 136 (`request.autoFixContentLength = fixContentLength`):

```kotlin
request.connectionId = connectionId
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew test --tests "burp.RequestEngineTest" --info`

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/RequestEngine.kt test/kotlin/RequestEngineTest.kt
git commit -m "feat: add connectionId parameter to RequestEngine.queue()"
```

---

### Task 3: Add Validation for Gate and ConnectionId Mutual Exclusion

**Files:**
- Modify: `src/RequestEngine.kt:99-138`
- Modify: `test/kotlin/RequestEngineTest.kt`

- [ ] **Step 1: Write the failing test**

Add to `test/kotlin/RequestEngineTest.kt`:

```kotlin
@Test
fun `queue throws when both gate and connectionId specified`() {
    val exception = assertThrows<Exception> {
        engine.queue("GET / HTTP/1.1\r\nHost: test.local\r\n\r\n", emptyList<Any>(), 0, null, "my-gate", "", 0, 1000, emptyList(), 0, null, null, true, "my-conn")
    }
    assertTrue(exception.message!!.contains("mutually exclusive"))
}

@Test
fun `queue allows gate without connectionId`() {
    assertDoesNotThrow {
        engine.queue("GET / HTTP/1.1\r\nHost: test.local\r\n\r\n", emptyList<Any>(), 0, null, "my-gate", "", 0, 1000, emptyList(), 0, null, null, true, null)
    }
}

@Test
fun `queue allows connectionId without gate`() {
    assertDoesNotThrow {
        engine.queue("GET / HTTP/1.1\r\nHost: test.local\r\n\r\n", emptyList<Any>(), 0, null, null, "", 0, 1000, emptyList(), 0, null, null, true, "my-conn")
    }
}
```

Also add this import at the top of the file:

```kotlin
import org.junit.jupiter.api.assertThrows
import org.junit.jupiter.api.assertDoesNotThrow
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew test --tests "burp.RequestEngineTest.queue throws when both*" --info`

Expected: FAIL - no exception thrown

- [ ] **Step 3: Add validation to queue()**

In `src/RequestEngine.kt`, add after line 100 (`updateLastLife()`):

```kotlin
if (gateName != null && connectionId != null) {
    throw Exception("Cannot specify both gate and connectionId - they are mutually exclusive")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./gradlew test --tests "burp.RequestEngineTest" --info`

Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/RequestEngine.kt test/kotlin/RequestEngineTest.kt
git commit -m "feat: validate gate and connectionId are mutually exclusive"
```

---

### Task 4: Add connectionId to Python ScriptEnvironment

**Files:**
- Modify: `resources/ScriptEnvironment.py:314-319`

- [ ] **Step 1: Modify queue() signature**

In `resources/ScriptEnvironment.py`, change line 314 from:

```python
def queue(self, template, payloads=None, learn=0, callback=None, gate=None, label="", pauseBefore=0, pauseTime=1000, pauseMarker=[], delay=0, endpoint=None, fixContentLength=True):
```

to:

```python
def queue(self, template, payloads=None, learn=0, callback=None, gate=None, label="", pauseBefore=0, pauseTime=1000, pauseMarker=[], delay=0, endpoint=None, fixContentLength=True, connectionId=None):
```

- [ ] **Step 2: Pass connectionId to engine**

Change line 319 from:

```python
self.engine.queue(template, payloads, learn, callback, gate, label, pauseBefore, pauseTime, pauseMarker, delay, endpoint, self, fixContentLength)
```

to:

```python
self.engine.queue(template, payloads, learn, callback, gate, label, pauseBefore, pauseTime, pauseMarker, delay, endpoint, self, fixContentLength, connectionId)
```

- [ ] **Step 3: Verify build succeeds**

Run: `./gradlew jar`

Expected: BUILD SUCCESSFUL

- [ ] **Step 4: Commit**

```bash
git add resources/ScriptEnvironment.py
git commit -m "feat: add connectionId parameter to Python queue() API"
```

---

### Task 5: Use connectionId in BurpRequestEngine

**Files:**
- Modify: `src/BurpRequestEngine.kt:64-85`

- [ ] **Step 1: Review current request() method**

Read `src/BurpRequestEngine.kt:64-85` to confirm the current implementation.

- [ ] **Step 2: Update request() method to use connectionId**

Replace the `request()` method (lines 64-85) with:

```kotlin
private fun request(service: IHttpService, req: Request) {
    val montoyaService = HttpService.httpService(service.host, service.port, "https".equals(service.protocol))
    val protocolVersion = if (useHTTP1) HttpMode.HTTP_1 else HttpMode.HTTP_2
    
    val montoyaResp = if (req.connectionId != null) {
        Utils.montoyaApi.http().sendRequest(
            HttpRequest.httpRequest(montoyaService, req.getRequest()), 
            protocolVersion, 
            req.connectionId
        )
    } else {
        Utils.montoyaApi.http().sendRequest(
            HttpRequest.httpRequest(montoyaService, req.getRequest()), 
            protocolVersion
        )
    }
    
    req.ttfb = montoyaResp.timingData().get().timeBetweenRequestSentAndStartOfResponse().toNanos() / 1000
    req.ttlb = montoyaResp.timingData().get().timeBetweenRequestSentAndEndOfResponse().toNanos() / 1000
    req.time = req.ttfb
    if (montoyaResp.response() != null) {
        req.response = montoyaResp.response().toString()
    }
}
```

- [ ] **Step 3: Verify build succeeds**

Run: `./gradlew jar`

Expected: BUILD SUCCESSFUL

- [ ] **Step 4: Run all tests**

Run: `./gradlew test`

Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/BurpRequestEngine.kt
git commit -m "feat: use connectionId when sending requests via Montoya API"
```

---

### Task 6: Final Verification

- [ ] **Step 1: Run full test suite**

Run: `./gradlew test`

Expected: All tests PASS

- [ ] **Step 2: Build JAR**

Run: `./gradlew jar`

Expected: BUILD SUCCESSFUL, JAR at `build/libs/turbo-intruder.jar`

- [ ] **Step 3: Manual smoke test (optional)**

Load extension in Burp, run a script using connectionId:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint)
    engine.queue(target.req, "a", connectionId="conn-1")
    engine.queue(target.req, "b", connectionId="conn-1")
    engine.queue(target.req, "c", connectionId="conn-2")

def handleResponse(req, interesting):
    table.add(req)
```

Verify requests complete without errors.

- [ ] **Step 4: Final commit if any cleanup needed**

```bash
git status
# If clean, done. If changes, commit them.
```
