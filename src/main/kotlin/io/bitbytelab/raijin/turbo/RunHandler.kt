package io.bitbytelab.raijin.turbo

import io.bitbytelab.raijin.bridge.HttpRequestBuilder
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger


/**
 * Control and status of one run. The script thread writes it while the GUI timer and MCP threads
 * read it, so every field is volatile.
 *
 * A script may build several engines in turn: all of them are kept ([engines]), stopped together,
 * share one request id counter, and the newest one speaks for the run's status.
 */
class RunHandler (){
    private val lock = Any()
    private val engines = CopyOnWriteArrayList<RequestEngine>()
    private val engine: RequestEngine? get() = engines.lastOrNull()
    private val requestIds = AtomicInteger(0)
    @Volatile private var scriptThread: Thread? = null
    @Volatile private var stopRequested = false
    @Volatile private var statusOverride: String? = null
    @Volatile private var errorFlag: Boolean = false
    @Volatile private var scriptCompleted = false
    @Volatile var msg: String = ""
    @Volatile var code: String = ""
    @Volatile var baseRequest: String = ""
    @Volatile var rawRequest: ByteArray = "".toByteArray()

    /**
     * Told the target URL of every request the run's engines queue; set before the script starts
     * (MCP-started runs, for scope advice). GUI runs leave it null.
     */
    @Volatile var targetObserver: ((String) -> Unit)? = null

    /** Scope advice gathered by [targetObserver]: one entry per out-of-scope origin, at most [MAX_SCOPE_WARNINGS]. */
    val scopeWarnings: MutableSet<String> = ConcurrentHashMap.newKeySet()

    private val seenOrigins = ConcurrentHashMap.newKeySet<String>()

    /**
     * Adds [advice]'s warning for [url]'s origin the first time that origin is queued. Cheap after
     * the first request per origin, so it can sit on the queue path.
     */
    fun observeTarget(url: String, advice: (String) -> String?) {
        val origin = originOf(url)
        if (!seenOrigins.add(origin) || scopeWarnings.size >= MAX_SCOPE_WARNINGS) return
        advice(origin)?.let { scopeWarnings += it }
    }

    fun hasError(): Boolean = errorFlag

    fun failCount(): Int = engines.sumOf { it.permaFails.get() }

    fun lastError(): String? = engine?.lastError

    /** Exceptions the script's callbacks raised, over every engine of the run. */
    fun callbackFailures(): Int = engines.sumOf { it.callbackFailures.get() }

    fun lastCallbackError(): String? = engines.asReversed().firstNotNullOfOrNull { it.lastCallbackError }

    /** The engine's own account of why the run produced nothing, or null if it has none. */
    fun failureSummary(): String? = engine?.failureSummary()

    /**
     * "running" until the newest engine has finished and been ranked ([RequestEngine.finalized]);
     * "completed" also waits for the script itself (its `completed()` callback, a next engine).
     */
    fun status(): String {
        if (errorFlag) return "failed"
        val eng = engine
        if (eng != null) {
            val state = eng.runState.get()
            return when {
                state >= 4 && eng.finalized && (scriptCompleted || stopRequested) -> "completed"
                state == 3 && eng.finalized -> "exited-early"
                else -> "running"
            }
        }
        if (stopRequested) return "exited-early"
        return if (scriptCompleted) "completed" else "running"
    }

    fun setComplete() {
        engine?.showStats(-1)
    }

    fun markScriptCompleted() {
        scriptCompleted = true
        scriptThread = null
    }

    /**
     * Binds the thread running the user's script, so [abort] can stop a script that has not built
     * its engine yet. A stop requested before the binding interrupts the thread straight away.
     */
    @JvmOverloads
    fun attachScriptThread(thread: Thread = Thread.currentThread()) {
        val interrupt = synchronized(lock) {
            scriptThread = thread
            stopRequested && engines.isEmpty()
        }
        if (interrupt) thread.interrupt()
    }

    fun setRequestEngine(engine: RequestEngine) {
        engine.lastRequestID = requestIds
        engine.targetObserver = targetObserver
        val cancel = synchronized(lock) {
            engines += engine
            stopRequested
        }
        // The stop landed while the script was still building this engine: it applies here too.
        if (cancel) engine.cancel()
    }

    fun statusString(): String {
        statusOverride?.let { return it }

        val eng = engine
        if (eng != null) {
            val engineStatus = eng.statusString()
            val message = msg
            if (message.isBlank()) return engineStatus
            val terminal = listOf(" | Completed", " | Cancelled").firstOrNull(engineStatus::endsWith)
            return if (terminal == null) {
                "$engineStatus | $message"
            } else {
                engineStatus.removeSuffix(terminal) + " | " + message + terminal
            }
        }

        if (stopRequested) return "Stopped before the request engine started"
        return "Engine warming up..."
    }

    /**
     * True once the run was asked to stop. An engine that ended on its own (completed, or failed to
     * start) is not a stop: a script error after that is a real error.
     */
    fun stopping(): Boolean = stopRequested

    /**
     * Replaces the status line. After a stop, an error does not mark the run failed: the stop
     * interrupts the script, and the exception that surfaces is the stop working.
     */
    fun overrideStatus(msg: String, isError: Boolean = true) {
        statusOverride = msg
        errorFlag = isError && !stopRequested
    }

    fun setMessage(msg: String) {
        this.msg = msg
    }

    /**
     * Stops the run: cancels every engine it built, or, while the script has not built one yet,
     * interrupts the script thread so the stop does not wait for the script to get that far.
     */
    fun abort() {
        var interrupt: Thread? = null
        val all = synchronized(lock) {
            stopRequested = true
            engines.toList().also { if (it.isEmpty()) interrupt = scriptThread }
        }
        interrupt?.takeIf { it !== Thread.currentThread() }?.interrupt()
        all.forEach { it.cancel() }
    }

    companion object {
        const val MAX_SCOPE_WARNINGS = 20

        /** `scheme://host:port` of [url], or [url] itself when it does not parse. */
        fun originOf(url: String): String {
            val parts = HttpRequestBuilder.splitUrl(url) ?: return url
            val (host, port) = HttpRequestBuilder.parseHostValue(parts.authority) ?: return url
            val scheme = parts.scheme.lowercase()
            val literal = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
            return "$scheme://$literal:${port ?: if (scheme == "https") 443 else 80}"
        }
    }
}
