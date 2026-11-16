package io.bitbytelab.raijin.ui

/**
 * The cleanup a UI instance owes on extension unload: timers to stop, subscriptions and listeners to
 * remove, workers to shut down. [dispose] runs every action once, newest first; an action that
 * throws is reported through [onError] and the rest still run, so one failure cannot leave a timer
 * or listener behind.
 */
internal class Disposer(private val onError: (name: String, error: Exception) -> Unit = { _, _ -> }) {
    private val actions = mutableListOf<Pair<String, () -> Unit>>()
    private var disposed = false

    val isDisposed: Boolean
        @Synchronized get() = disposed

    /** Registers [action]; registered after [dispose], it runs immediately. */
    fun add(name: String, action: () -> Unit) {
        val runNow = synchronized(this) {
            if (!disposed) actions += name to action
            disposed
        }
        if (runNow) run(name, action)
    }

    /**
     * Adds [listener] to [listeners] and, on [dispose], removes that instance only. Other entries
     * (e.g. the persistence listener sharing `StateManager.mcpActivityListeners`) stay registered.
     */
    fun <T> listen(name: String, listeners: MutableCollection<T>, listener: T) {
        listeners.add(listener)
        add(name) { listeners.remove(listener) }
    }

    fun dispose() {
        val pending = synchronized(this) {
            if (disposed) return
            disposed = true
            actions.asReversed().toList().also { actions.clear() }
        }
        pending.forEach { (name, action) -> run(name, action) }
    }

    private fun run(name: String, action: () -> Unit) {
        try {
            action()
        } catch (e: Exception) {
            onError(name, e)
        }
    }
}
