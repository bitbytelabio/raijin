package io.bitbytelab.raijin.turbo

import java.net.URI
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue

class TestRequestEngine : RequestEngine() {

    override val callback: (Request, Boolean) -> Boolean? = { _, _ -> true }
    override var readCallback: ((String) -> Boolean)? = null
    override val maxRetriesPerRequest: Int = 0
    override var idleTimeout: Long = 0L

    init {
        target = URI("http://test.local").toURL()
        requestQueue = LinkedBlockingQueue(100)
        completedLatch = CountDownLatch(0)
        outputHandler = ResultStore()
    }

    override fun start(timeout: Int) {
        runState.set(1) // live
    }

    override fun buildRequest(template: String, payloads: List<String?>, learnBoring: Int?, label: String): Request {
        return Request(template, payloads, learnBoring ?: 0, label)
    }

    fun setRunState(state: Int) {
        runState.set(state)
    }
}
