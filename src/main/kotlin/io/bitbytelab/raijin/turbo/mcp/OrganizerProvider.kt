package io.bitbytelab.raijin.turbo.mcp

import io.bitbytelab.raijin.turbo.Utils
import burp.api.montoya.organizer.OrganizerItemFilter

data class OrganizerItemData(
    val id: Int,
    val request: String,
    val response: String,
    val notes: String,
    val host: String,
    val port: Int,
    val secure: Boolean,
    val timeRequestSent: java.time.ZonedDateTime? = null
)

interface OrganizerProvider {
    fun getItems(): List<OrganizerItemData>
    fun getItemsByIds(ids: Set<Int>): List<OrganizerItemData>
    fun setNotes(id: Int, notes: String): Boolean
    fun sendToOrganizer(request: io.bitbytelab.raijin.turbo.Request, notes: String)
}

class BurpOrganizerProvider : OrganizerProvider {
    override fun getItems(): List<OrganizerItemData> {
        val organizer = Utils.montoyaApi?.organizer() ?: return emptyList()
        return organizer.items().map { item ->
            val httpService = item.request()?.httpService()
            OrganizerItemData(
                id = item.id(),
                request = item.request()?.toString() ?: "",
                response = item.response()?.toString() ?: "",
                notes = item.annotations()?.notes() ?: "",
                host = httpService?.host() ?: "",
                port = httpService?.port() ?: 0,
                secure = httpService?.secure() ?: false,
                timeRequestSent = item.timingData().orElse(null)?.timeRequestSent()
            )
        }
    }

    override fun getItemsByIds(ids: Set<Int>): List<OrganizerItemData> {
        val organizer = Utils.montoyaApi?.organizer() ?: return emptyList()
        val filter = OrganizerItemFilter { item -> item.id() in ids }
        return organizer.items(filter).map { item ->
            val httpService = item.request()?.httpService()
            OrganizerItemData(
                id = item.id(),
                request = item.request()?.toString() ?: "",
                response = item.response()?.toString() ?: "",
                notes = item.annotations()?.notes() ?: "",
                host = httpService?.host() ?: "",
                port = httpService?.port() ?: 0,
                secure = httpService?.secure() ?: false,
                timeRequestSent = item.timingData().orElse(null)?.timeRequestSent()
            )
        }
    }

    override fun setNotes(id: Int, notes: String): Boolean {
        val organizer = Utils.montoyaApi?.organizer() ?: return false
        val filter = OrganizerItemFilter { item -> item.id() == id }
        val item = organizer.items(filter).firstOrNull() ?: return false
        item.annotations()?.setNotes(notes)
        return true
    }

    override fun sendToOrganizer(request: io.bitbytelab.raijin.turbo.Request, notes: String) {
        val montoyaReq = request.getMontoyaRequest() ?: return
        montoyaReq.annotations().setNotes(notes)
        Utils.montoyaApi?.organizer()?.sendToOrganizer(montoyaReq)
    }
}
