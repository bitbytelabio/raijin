package io.bitbytelab.raijin.turbo

import burp.api.montoya.http.message.HttpRequestResponse
import org.python.core.Py
import org.python.core.PySystemState
import org.python.util.PythonInterpreter
import java.io.PrintWriter
import java.io.StringWriter


class Target(val req: String, val rawreq: ByteArray, val endpoint: String, val baseInput: String)

class Wordlist(val bruteforce: Bruteforce, val observedWords: MutableSet<String>, val clipboard: ArrayList<String>)

fun evalJython(code: String, baseRequest: String, rawRequest: ByteArray, endpoint: String, host: String, baseInput: String, store: ResultStore, handler: RunHandler, reqs: MutableList<HttpRequestResponse>?, requestTable: RequestTable?) {
    // Its own PySystemState: modules, sys.path and globals one run's script changes stay out of the next run.
    var pyInterp: PythonInterpreter? = null
    try {
        pyInterp = try {
            PythonInterpreter(null, PySystemState())
        } catch (e: Throwable) {
            handler.overrideStatus("Run failed to start: ${e.message ?: e.javaClass.simpleName}")
            return
        }
        Utils.out("Starting run...")
        handler.code = code
        handler.baseRequest = baseRequest
        handler.rawRequest = rawRequest
        pyInterp.set("target", Target(baseRequest, rawRequest, endpoint, baseInput))
        // Copy observed words instead of mutating shared Utils.witnessedWords.savedWords with placeholder text
        val observedWords = Utils.witnessedWords.savedWords.toMutableSet()
        if (observedWords.isEmpty()) {
            observedWords.add("To use this wordlist, enable 'learn observed words'")
        }
        pyInterp.set("wordlists", Wordlist(Bruteforce(), observedWords, Utils.getClipboard()))
        pyInterp.set("turboTypes", TurboPython.types())
        pyInterp.exec("class _TurboNamespace(object):\n    pass\nturbo = _TurboNamespace()\nfor _n, _t in turboTypes.items():\n    setattr(turbo, _n, _t)\ndel _n, _t")
        pyInterp.set("handler", handler)
        pyInterp.set("outputHandler", store)
        pyInterp.set("table", store)
        pyInterp.set("store", store)
        pyInterp.set("requestTable", requestTable)
        pyInterp.set("requests", reqs)
        pyInterp.set("host", host)
        pyInterp.set("desyncAgentMode", TurboSettings.desyncAgent)
        if (Utils.gotBurp) {
            pyInterp.set("api", Utils.montoyaApi)
            pyInterp.setOut(Utils.outputStream())
            pyInterp.setErr(Utils.errorStream())
            // Callbacks run on engine worker threads, which Jython gives the default system state,
            // not this run's: point its streams at Burp's output too, so a callback's print shows.
            Py.defaultSystemState?.let { shared ->
                shared.stdout = pyInterp.systemState.stdout
                shared.stderr = pyInterp.systemState.stderr
            }
        }
        pyInterp.exec(Scripts.SCRIPTENVIRONMENT)
        pyInterp.exec(code)
        pyInterp.exec("queueRequests(target, wordlists)")
        handler.setComplete()
        pyInterp.exec("completed(store.getAllRquests())".trimMargin())
    }
    catch (ex: Exception) {
        val interp = pyInterp ?: throw ex
        var error = ex
        var stackTrace = errorToStacktrace(error)
        if (stackTrace.contains("Cannot queue any more items - the run has finished")) {
            Utils.out("Run aborted with items waiting to be queued.")
            try {
                interp.exec("completed(store.getAllRquests())".trimMargin())
                handler.abort()
                return
            } catch (ex2: Exception) {
                error = ex2
                stackTrace = errorToStacktrace(ex2)
            }
        }

        var message = error.cause?.message
        if (message == null) {
            message = error.toString()
        }
        if (handler.stopping()) {
            // Whatever the script raises once the run was stopped is the stop surfacing, not a bug.
            Utils.out("Run stopped: $message")
            handler.abort()
            return
        }
        handler.overrideStatus("User Python error, check extender for full details: $message")
        Utils.out("There was an error executing your Python script. This is probably due to a flaw in your script, rather than a bug in Raijin Turbo :)")
        Utils.out("If you think it is a Raijin Turbo issue, try the 'debug' example script from the script picker.")
        Utils.out("For your convenience, here's the full stack trace:")
        Utils.out(stackTrace)

        handler.abort()
    } finally {
        runCatching { pyInterp?.close() }
    }
}


fun errorToStacktrace(ex: Exception): String {
    val stackTrace = StringWriter()
    ex.printStackTrace(PrintWriter(stackTrace))
    return stackTrace.toString()
}

/** The `target.endpoint` URL for a run: `scheme://host:port`, with an IPv6 literal host bracketed. */
internal fun turboEndpoint(protocol: String, host: String, port: Int): String =
    if (host.contains(":")) "$protocol://[$host]:$port" else "$protocol://$host:$port"

/** Scripts run with CRLF line endings whatever the editor produced (LF, CRLF or a mix). */
internal fun normalizeScriptNewlines(script: String): String =
    script.replace("\r\n", "\n").replace("\n", "\r\n")
