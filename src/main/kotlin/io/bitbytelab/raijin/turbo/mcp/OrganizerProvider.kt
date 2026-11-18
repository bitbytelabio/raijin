package io.bitbytelab.raijin.turbo.mcp

import io.bitbytelab.raijin.turbo.Utils

interface OrganizerProvider {
    /** Sends [request] with [notes] to Burp's Organizer; false when there is nothing Burp can store. */
    fun sendToOrganizer(request: io.bitbytelab.raijin.turbo.Request, notes: String): Boolean
}

class BurpOrganizerProvider : OrganizerProvider {
    override fun sendToOrganizer(request: io.bitbytelab.raijin.turbo.Request, notes: String): Boolean {
        val montoyaReq = request.getMontoyaRequest() ?: return false
        val organizer = Utils.montoyaApi?.organizer() ?: return false
        montoyaReq.annotations().setNotes(notes)
        organizer.sendToOrganizer(montoyaReq)
        return true
    }
}
