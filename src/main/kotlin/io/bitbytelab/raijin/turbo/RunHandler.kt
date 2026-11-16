package io.bitbytelab.raijin.turbo


/**
 * Control and status of one run. The script thread writes it while the GUI timer and MCP threads
 * read it, so every field is volatile.
 */
class RunHandler (){
    private val lock = Any()
    @Volatile private var engine: RequestEngine? = null
    @Volatile private var scriptThread: Thread? = null
    @Volatile private var stopRequested = false
    @Volatile private var statusOverride: String? = null
    @Volatile private var errorFlag: Boolean = false
    @Volatile private var scriptCompleted = false
    @Volatile var msg: String = ""
    @Volatile var code: String = ""
    @Volatile var baseRequest: String = ""
    @Volatile var rawRequest: ByteArray = "".toByteArray()

    fun hasError(): Boolean = errorFlag

    fun failCount(): Int = engine?.permaFails?.get() ?: 0

    fun lastError(): String? = engine?.lastError

    /** The engine's own account of why the run produced nothing, or null if it has none. */
    fun failureSummary(): String? = engine?.failureSummary()

    fun status(): String {
        if (errorFlag) return "failed"
        val eng = engine
        if (eng != null) {
            val state = eng.runState.get()
            return when {
                state >= 4 -> "completed"
                state >= 3 -> "exited-early"
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
            stopRequested && engine == null
        }
        if (interrupt) thread.interrupt()
    }

    fun setRequestEngine(engine: RequestEngine) {
        val cancel = synchronized(lock) {
            this.engine = engine
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
     * Stops the run: cancels its engine, or, while the script has not built one yet, interrupts
     * the script thread so the stop does not wait for the script to get that far.
     */
    fun abort() {
        var interrupt: Thread? = null
        val eng = synchronized(lock) {
            stopRequested = true
            engine.also { if (it == null) interrupt = scriptThread }
        }
        interrupt?.takeIf { it !== Thread.currentThread() }?.interrupt()
        eng?.cancel()
    }
}
