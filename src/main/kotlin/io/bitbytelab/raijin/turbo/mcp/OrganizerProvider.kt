package io.bitbytelab.raijin.turbo.mcp

import io.bitbytelab.raijin.turbo.Utils

interface OrganizerProvider {
    fun sendToOrganizer(request: io.bitbytelab.raijin.turbo.Request, notes: String)
}

class BurpOrganizerProvider : OrganizerProvider {
    override fun sendToOrganizer(request: io.bitbytelab.raijin.turbo.Request, notes: String) {
        val montoyaReq = request.getMontoyaRequest() ?: return
        montoyaReq.annotations().setNotes(notes)
        Utils.montoyaApi?.organizer()?.sendToOrganizer(montoyaReq)
    }
}
