package io.bitbytelab.raijin.turbo

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.scancheck.PassiveScanCheck
import java.util.concurrent.ConcurrentHashMap

/** Passive check that records words seen in traffic, for `wordlists.observedWords`. */
class WordRecorder : PassiveScanCheck {

    val savedWords: MutableSet<String> = ConcurrentHashMap.newKeySet<String>()
    val wordRegex = "[^a-zA-Z]".toRegex()

    override fun checkName(): String = "Raijin Turbo word recorder"

    override fun doCheck(baseRequestResponse: HttpRequestResponse): AuditResult {
        if (TurboSettings.learnWords) {
            savedWords.addAll(Utils.bytesToString(baseRequestResponse.request()?.toByteArray()?.bytes).split(wordRegex))
            if (baseRequestResponse.hasResponse()) {
                savedWords.addAll(Utils.bytesToString(baseRequestResponse.response().toByteArray().bytes).split(wordRegex))
            }
        }
        return AuditResult.auditResult()
    }
}
