package io.bitbytelab.raijin.bridge

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.Collaborator
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.collaborator.CollaboratorPayload
import burp.api.montoya.collaborator.CollaboratorServer
import burp.api.montoya.collaborator.DnsDetails
import burp.api.montoya.collaborator.DnsQueryType
import burp.api.montoya.collaborator.HttpDetails
import burp.api.montoya.collaborator.Interaction
import burp.api.montoya.collaborator.InteractionId
import burp.api.montoya.collaborator.InteractionType
import burp.api.montoya.collaborator.SecretKey
import burp.api.montoya.collaborator.SmtpDetails
import burp.api.montoya.collaborator.SmtpProtocol
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.HttpProtocol
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.MimeType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.logging.Logging
import burp.api.montoya.organizer.Organizer
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.persistence.Persistence
import io.bitbytelab.raijin.events.EventBus
import io.bitbytelab.raijin.state.StateManager
import io.bitbytelab.raijin.turbo.mcp.BurpCollaboratorProvider
import io.bitbytelab.raijin.turbo.mcp.CollaboratorHistory
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.lang.reflect.Proxy
import java.net.InetAddress
import java.time.ZonedDateTime
import java.util.Optional
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A [T] whose calls go to [handler] (method name, arguments) and whose `toString()` is [text]. */
private inline fun <reified T : Any> fake(
    text: String = "fake ${T::class.simpleName}",
    noinline handler: (String, Array<out Any?>) -> Any?,
): T = Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { proxy, method, args ->
    when (method.name) {
        "toString" -> text
        "hashCode" -> System.identityHashCode(proxy)
        "equals" -> proxy === args?.firstOrNull()
        else -> handler(method.name, args ?: emptyArray<Any?>())
    }
} as T

private fun secretKey(secret: String): SecretKey = fake(text = secret) { m, _ -> error("unexpected SecretKey.$m") }

private fun interactionId(id: String): InteractionId = fake(text = id) { m, _ -> error("unexpected InteractionId.$m") }

/** What Burp's object factory does for the one call the bridge makes: `SecretKey.secretKey(text)`. */
private val factory: MontoyaObjectFactory = fake { m, a ->
    if (m == "secretKey") secretKey(a[0] as String) else error("unexpected MontoyaObjectFactory.$m")
}

/**
 * Stand-in for Burp with a Collaborator server and a project store. Like the real server it hands
 * an interaction out once: what [arrive] queued for a client is gone after that client's next poll.
 */
private class FakeBurp {
    /** `extensionData()` strings. Kept across [CollaboratorBridge] instances, it plays the Burp project. */
    val project = HashMap<String, String>()

    /** Secrets passed to `restoreClient`, in order. */
    val restored = ArrayList<String>()

    /** Notes of what was sent to Organizer. */
    val organized = ArrayList<String>()

    var collaboratorAvailable = true
    var failNextPoll = false
    var polls = 0

    /** Interactions waiting on the server, by client secret. */
    private val waiting = HashMap<String, MutableList<Interaction>>()
    private var secrets = 0
    private var payloads = 0

    fun arrive(secret: String, vararg interactions: Interaction) {
        waiting.getOrPut(secret) { ArrayList() }.addAll(interactions)
    }

    private val server: CollaboratorServer = fake { m, _ ->
        if (m == "address") "oast.test" else error("unexpected CollaboratorServer.$m")
    }

    private fun payload(customData: String?): CollaboratorPayload {
        val id = "p${++payloads}"
        return fake(text = "$id.oast.test") { m, _ ->
            when (m) {
                "id" -> interactionId(id)
                "customData" -> Optional.ofNullable(customData)
                "server" -> Optional.of(server)
                else -> error("unexpected CollaboratorPayload.$m")
            }
        }
    }

    private fun client(secret: String): CollaboratorClient = fake(text = "client $secret") { m, a ->
        when (m) {
            // generatePayload(options...) or generatePayload(customData, options...)
            "generatePayload" -> payload(a.firstOrNull() as? String)
            "getAllInteractions" -> {
                polls++
                if (failNextPoll) {
                    failNextPoll = false
                    throw IllegalStateException("Burp Collaborator is disabled")
                }
                waiting.remove(secret).orEmpty().toList()
            }
            "server" -> server
            "getSecretKey" -> secretKey(secret)
            else -> error("unexpected CollaboratorClient.$m")
        }
    }

    private val collaborator: Collaborator = fake { m, a ->
        when (m) {
            "createClient" -> client("secret-${++secrets}")
            "restoreClient" -> {
                val secret = a[0].toString()
                restored.add(secret)
                client(secret)
            }
            else -> error("unexpected Collaborator.$m")
        }
    }

    private val extensionData: PersistedObject = fake { m, a ->
        when (m) {
            "getString" -> project[a[0] as String]
            "setString" -> {
                project[a[0] as String] = a[1] as String
                null
            }
            else -> error("unexpected PersistedObject.$m")
        }
    }

    private val persistence: Persistence = fake { m, _ ->
        if (m == "extensionData") extensionData else error("unexpected Persistence.$m")
    }

    private val logging: Logging = fake { m, _ ->
        if (m == "logToOutput") null else error("unexpected Logging.$m")
    }

    private val organizer: Organizer = fake { m, a ->
        if (m != "sendToOrganizer") error("unexpected Organizer.$m")
        organized.add((a[0] as HttpRequestResponse).annotations().notes())
        null
    }

    val api: MontoyaApi = fake { m, _ ->
        when (m) {
            "collaborator" ->
                if (collaboratorAvailable) collaborator else throw UnsupportedOperationException("Collaborator is a Professional feature")
            "persistence" -> persistence
            "logging" -> logging
            "organizer" -> organizer
            else -> error("unexpected MontoyaApi.$m")
        }
    }
}

private fun interaction(
    payloadId: String,
    type: InteractionType,
    at: String,
    dns: DnsDetails? = null,
    http: HttpDetails? = null,
    smtp: SmtpDetails? = null,
    customData: String? = null,
): Interaction = fake { m, _ ->
    when (m) {
        "id" -> interactionId(payloadId)
        "type" -> type
        "timeStamp" -> ZonedDateTime.parse(at)
        "clientIp" -> InetAddress.getByName("203.0.113.5")
        "clientPort" -> 44321
        "dnsDetails" -> Optional.ofNullable(dns)
        "httpDetails" -> Optional.ofNullable(http)
        "smtpDetails" -> Optional.ofNullable(smtp)
        "customData" -> Optional.ofNullable(customData)
        else -> error("unexpected Interaction.$m")
    }
}

/** DNS details whose raw query is exactly [query]. */
private fun rawDns(query: ByteArray, type: DnsQueryType = DnsQueryType.UNKNOWN): DnsDetails = fake { m, _ ->
    when (m) {
        "queryType" -> type
        "query" -> fake<BurpByteArray> { bm, _ -> if (bm == "getBytes") query else error("unexpected ByteArray.$bm") }
        else -> error("unexpected DnsDetails.$m")
    }
}

/** DNS details of a well-formed A lookup for [name]. */
private fun dnsLookup(name: String): DnsDetails {
    val qname = name.split('.').fold(ByteArray(0)) { wire, label -> wire + byteArrayOf(label.length.toByte()) + label.toByteArray() }
    return rawDns(ByteArray(12) + qname + byteArrayOf(0, 0, 1, 0, 1), DnsQueryType.A)
}

private const val COLLABORATOR_RESPONSE = "HTTP/1.1 200 OK\r\nServer: Burp Collaborator\r\n\r\n<html><body>zq8</body></html>"

/** HTTP details of [request] (raw) as Burp reports it for [url], answered with [response]. */
private fun httpHit(url: String, request: String, response: String? = COLLABORATOR_RESPONSE): HttpDetails {
    var notes = ""
    val annotations: Annotations = fake { m, a ->
        when (m) {
            "setNotes" -> {
                notes = a[0] as String
                null
            }
            "notes" -> notes
            else -> error("unexpected Annotations.$m")
        }
    }
    val burpRequest: HttpRequest = fake(text = request) { m, _ ->
        when (m) {
            "method" -> request.substringBefore(' ')
            "url" -> url
            else -> error("unexpected HttpRequest.$m")
        }
    }
    val burpResponse: HttpResponse? = if (response == null) null else fake<HttpResponse>(text = response) { m, _ ->
        when (m) {
            "statusCode" -> response.split(' ')[1].toShort()
            "mimeType" -> MimeType.HTML
            else -> error("unexpected HttpResponse.$m")
        }
    }
    val exchange: HttpRequestResponse = fake { m, _ ->
        when (m) {
            "request" -> burpRequest
            "response" -> burpResponse
            "annotations" -> annotations
            else -> error("unexpected HttpRequestResponse.$m")
        }
    }
    return fake { m, _ ->
        when (m) {
            "protocol" -> HttpProtocol.HTTP
            "requestResponse" -> exchange
            else -> error("unexpected HttpDetails.$m")
        }
    }
}

private fun mail(conversation: String): SmtpDetails = fake { m, _ ->
    when (m) {
        "protocol" -> SmtpProtocol.SMTP
        "conversation" -> conversation
        else -> error("unexpected SmtpDetails.$m")
    }
}

private fun JsonObject.text(key: String): String? = (this[key] as? JsonPrimitive)?.contentOrNull

private fun JsonObject.int(key: String): Int = getValue(key).jsonPrimitive.int

private fun JsonObject.flag(key: String): Boolean = (this[key] as? JsonPrimitive)?.booleanOrNull == true

private fun JsonObject.interactions(): List<JsonObject> = getValue("interactions").jsonArray.map { it.jsonObject }

private fun JsonObject.types(): List<String?> = interactions().map { it.text("type") }

private fun JsonObject.seqs(): List<Long> = interactions().map { it.getValue("seq").jsonPrimitive.long }

private fun JsonObject.clients(): List<JsonObject> = getValue("clients").jsonArray.map { it.jsonObject }

/**
 * [CollaboratorBridge] against a stand-in Burp: clients across extension reloads, the interaction
 * history behind `collaborator_poll`, payload correlation, and the Turbo side of the shared provider.
 */
class CollaboratorBridgeLifecycleTest {

    private var previousFactory: MontoyaObjectFactory? = null

    @BeforeTest
    fun installFactory() {
        previousFactory = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = factory
    }

    @AfterTest
    fun restoreFactory() {
        ObjectFactoryLocator.FACTORY = previousFactory
    }

    private val burp = FakeBurp()

    /** One load of the extension: new state, event bus and history, over the same Burp project. */
    private inner class Load {
        val state = StateManager()
        val events = EventBus()
        val provider = BurpCollaboratorProvider(BurpCollaboratorProvider.State(CollaboratorHistory(clock = { 0L })))
        val bridge = CollaboratorBridge(burp.api, events, state, provider)

        fun savedClients() = CollaboratorBridge.decodeSavedClients(burp.project[CollaboratorBridge.PERSIST_KEY])

        fun interactionEvents(): List<JsonObject> =
            events.getEventsByType(listOf("collaborator.interaction")).map { it.data }
    }

    private fun dnsAt(payloadId: String, at: String) =
        interaction(payloadId, InteractionType.DNS, at, dns = dnsLookup("$payloadId.oast.test"))

    private fun httpAt(payloadId: String, at: String, customData: String? = null) = interaction(
        payloadId, InteractionType.HTTP, at,
        http = httpHit("http://$payloadId.oast.test/", "GET / HTTP/1.1\r\nHost: $payloadId.oast.test\r\n\r\n"),
        customData = customData,
    )

    private fun smtpAt(payloadId: String, at: String) =
        interaction(payloadId, InteractionType.SMTP, at, smtp = mail("EHLO x\r\nRCPT TO:<a@$payloadId.oast.test>\r\n"))

    // ---------------------------------------------------------------
    // Clients and project persistence
    // ---------------------------------------------------------------

    @Test
    fun `a created client is registered, saved in the project and listed`() {
        val load = Load()
        val created = load.bridge.createClient()

        assertEquals("collab-001", created.text("client_id"))
        assertEquals("oast.test", created.text("server"))
        assertTrue(created.flag("persisted"))
        assertEquals(setOf("collab-001"), load.state.collaboratorClients.keys.toSet())
        assertEquals(
            listOf(CollaboratorBridge.SavedClient("collab-001", "secret-1", "oast.test", created.text("created_at")!!)),
            load.savedClients()
        )

        val listed = load.bridge.listClients()
        assertEquals(1, listed.int("client_count"))
        val client = listed.clients().single()
        assertEquals("collab-001", client.text("client_id"))
        assertEquals("oast.test", client.text("server"))
        assertFalse(client.flag("restored"))
        assertTrue(client.flag("persisted"))
        assertEquals(0, client.int("payloads_generated"))
        assertEquals(0, client.int("interactions_recorded"))
        assertNull(client["label"])
        assertNull(listed["unrestored"])
        assertEquals(0, burp.polls, "listing does not contact the Collaborator server")
    }

    @Test
    fun `clients are back under their ids after a reload and new ids do not collide with them`() {
        val first = Load()
        first.bridge.createClient()
        first.bridge.createClient()
        val createdAt = first.state.collaboratorClients.getValue("collab-002").createdAt

        val second = Load() // a new StateManager: its id counter starts over
        assertEquals(setOf("collab-001", "collab-002"), second.state.collaboratorClients.keys.toSet())
        assertEquals(listOf("secret-1", "secret-2"), burp.restored)
        assertEquals(createdAt, second.state.collaboratorClients.getValue("collab-002").createdAt)
        assertTrue(second.bridge.listClients().clients().all { it.flag("restored") && it.flag("persisted") })
        assertEquals("secret-2", second.bridge.getSecret("collab-002").text("secret_key"))

        assertEquals("collab-003", second.bridge.createClient().text("client_id"), "collab-001 and collab-002 are taken")

        // a restored client is the same Collaborator client: it receives what its old payloads cause
        burp.arrive("secret-2", dnsAt("p1", "2026-11-17T10:00:00Z"))
        val poll = second.bridge.pollInteractions("collab-002", null, null)
        assertEquals(listOf("dns"), poll.types())

        val third = Load()
        assertEquals(setOf("collab-001", "collab-002", "collab-003"), third.state.collaboratorClients.keys.toSet())
    }

    @Test
    fun `restoring a key that is already registered returns its client instead of a rival one`() {
        val load = Load()
        val clientId = load.bridge.createClient().text("client_id")

        val again = load.bridge.restoreClient(" secret-1 ")
        assertEquals(clientId, again.text("client_id"))
        assertTrue(again.flag("already_registered"))
        assertEquals(1, load.state.collaboratorClients.size)
        assertTrue(burp.restored.isEmpty(), "Burp was not asked for a second client on the same key")

        val foreign = load.bridge.restoreClient("foreign-secret")
        assertEquals("collab-002", foreign.text("client_id"))
        assertTrue(foreign.flag("restored"))
        assertTrue(foreign.flag("persisted"))
        assertNull(foreign["already_registered"])
        assertEquals(listOf("foreign-secret"), burp.restored)
        assertEquals(listOf("secret-1", "foreign-secret"), load.savedClients().map { it.secretKey })

        assertEquals("Parameter 'secret_key' must not be blank", load.bridge.restoreClient("  ").text("error"))
    }

    @Test
    fun `removing a client forgets it in the registry, the project and the history`() {
        val load = Load()
        val clientId = load.bridge.createClient().text("client_id")!!
        val keptId = load.bridge.createClient().text("client_id")!!
        load.bridge.generatePayload(clientId, null)
        burp.arrive("secret-1", dnsAt("p1", "2026-11-17T10:00:00Z"))
        assertEquals(1, load.bridge.pollInteractions(clientId, null, null).int("interaction_count"))

        val removed = load.bridge.removeClient(clientId)
        assertTrue(removed.flag("removed"))
        assertEquals("secret-1", removed.text("secret_key"))
        assertEquals(setOf(keptId), load.state.collaboratorClients.keys.toSet())
        assertEquals(listOf(keptId), load.savedClients().map { it.clientId })
        assertTrue(load.provider.query().records.isEmpty())
        assertNull(load.provider.payloads["p1"])

        assertEquals("Client not found: $clientId", load.bridge.pollInteractions(clientId, null, null).text("error"))
        assertEquals("Client not found: $clientId", load.bridge.removeClient(clientId).text("error"))
        assertEquals(setOf(keptId), Load().state.collaboratorClients.keys.toSet(), "and it stays gone on the next load")
    }

    @Test
    fun `a saved client Burp cannot restore stays saved and comes back once Burp can`() {
        Load().bridge.createClient()

        burp.collaboratorAvailable = false
        val load = Load()
        assertTrue(load.state.collaboratorClients.isEmpty())
        val listed = load.bridge.listClients()
        assertEquals(0, listed.int("client_count"))
        val unrestored = listed.getValue("unrestored").jsonArray.single().jsonObject
        assertEquals("collab-001", unrestored.text("client_id"))
        assertEquals("oast.test", unrestored.text("server"))
        assertEquals("Collaborator is a Professional feature", unrestored.text("error"))
        val refused = load.bridge.pollInteractions("collab-001", null, null).text("error")
        assertTrue("could not restore it: Collaborator is a Professional feature" in assertNotNull(refused), refused)
        assertEquals(listOf("collab-001"), load.savedClients().map { it.clientId }, "the secret key is not thrown away")

        burp.collaboratorAvailable = true
        assertEquals(0, load.bridge.pollInteractions("collab-001", null, null).int("interaction_count"))
        assertEquals(setOf("collab-001"), load.state.collaboratorClients.keys.toSet())
        assertNull(load.bridge.listClients()["unrestored"])
    }

    @Test
    fun `without Collaborator the answer is an error, not an exception`() {
        burp.collaboratorAvailable = false
        val load = Load()

        assertEquals(
            "Collaborator API is not available in Burp Suite Community Edition",
            load.bridge.createClient().text("error")
        )
        assertEquals(
            "Collaborator API is not available in Burp Suite Community Edition",
            load.bridge.restoreClient("some-secret").text("error")
        )
        assertTrue("not available" in assertNotNull(assertFailsWith<IllegalStateException> { load.provider.generatePayload("x") }.message))
        assertTrue(load.state.collaboratorClients.isEmpty())
        assertTrue(load.savedClients().isEmpty())
    }

    // ---------------------------------------------------------------
    // Polling and history
    // ---------------------------------------------------------------

    @Test
    fun `filtering by type never loses the other interactions`() {
        val load = Load()
        val clientId = load.bridge.createClient().text("client_id")!!
        // queued out of order: one poll fetches all three and records them by time
        burp.arrive(
            "secret-1",
            smtpAt("p1", "2026-11-17T10:00:02Z"), dnsAt("p1", "2026-11-17T10:00:00Z"), httpAt("p1", "2026-11-17T10:00:01Z"),
        )

        val http = load.bridge.pollInteractions(clientId, "http", null)
        assertEquals(listOf("http"), http.types())
        assertEquals(2, http.int("filtered_out"))

        // the server has handed everything out; only the history can still answer these
        assertEquals(listOf("dns"), load.bridge.pollInteractions(clientId, "dns", null).types())
        assertEquals(listOf("smtp"), load.bridge.pollInteractions(clientId, "SMTP", null).types())

        val all = load.bridge.pollInteractions(clientId, null, null)
        assertEquals(listOf("dns", "http", "smtp"), all.types())
        assertEquals(listOf(1L, 2L, 3L), all.seqs())
        assertNull(all["filtered_out"])
        assertEquals(4, burp.polls)
        assertEquals(3, load.bridge.listClients().clients().single().int("interactions_recorded"))
    }

    @Test
    fun `a payload is traced to its interactions by id`() {
        val load = Load()
        val clientId = load.bridge.createClient().text("client_id")!!
        val first = load.bridge.generatePayload(clientId, null)
        val second = load.bridge.generatePayload(clientId, "mark-7!")

        assertEquals("p1", first.text("payload_id"))
        assertEquals("p1.oast.test", first.text("payload"))
        assertEquals("http://p1.oast.test", first.text("interaction_url"))
        assertEquals("p2", second.text("payload_id"))
        assertEquals("mark7", second.text("custom_data"))
        assertNotNull(second["warning"], "the label was changed to fit Collaborator's rule")

        burp.arrive(
            "secret-1",
            dnsAt("p1", "2026-11-17T10:00:00Z"),
            httpAt("p2", "2026-11-17T10:00:01Z", customData = "mark7"),
            httpAt("p1", "2026-11-17T10:00:02Z"),
            dnsAt("zz9", "2026-11-17T10:00:03Z"), // a payload of this client that Raijin did not generate
        )

        val byId = load.bridge.pollInteractions(clientId, null, "p1")
        assertEquals(listOf("dns", "http"), byId.types())
        assertEquals(listOf(1L, 3L), byId.seqs())
        assertEquals(2, byId.int("filtered_out"))
        for (hit in byId.interactions()) {
            assertEquals("p1", hit.text("payload_id"))
            assertEquals("p1", hit.text("id"))
            assertEquals("p1.oast.test", hit.text("payload"))
        }

        // the payload host, and a URL around it, name the same payload
        assertEquals(listOf(1L, 3L), load.bridge.pollInteractions(clientId, null, "p1.oast.test").seqs())
        assertEquals(listOf(1L, 3L), load.bridge.pollInteractions(clientId, null, "http://P1.oast.test/x").seqs())
        assertEquals(listOf(3L), load.bridge.pollInteractions(clientId, "http", "p1").seqs(), "filters combine")

        val marked = load.bridge.pollInteractions(clientId, null, second.text("payload_id")).interactions().single()
        assertEquals("mark7", marked.text("custom_data"))
        assertEquals("p2.oast.test", marked.text("payload"))

        val stray = load.bridge.pollInteractions(clientId, null, "zz9").interactions().single()
        assertEquals("zz9", stray.text("payload_id"))
        assertNull(stray["payload"])

        assertTrue(load.bridge.pollInteractions(clientId, null, "p404").interactions().isEmpty())
        assertEquals(2, load.bridge.listClients().clients().single().int("payloads_generated"))
    }

    @Test
    fun `since and limit page through the history and pick up what arrives later`() {
        val load = Load()
        val clientId = load.bridge.createClient().text("client_id")!!
        burp.arrive("secret-1", *(0..4).map { dnsAt("p1", "2026-11-17T10:00:0${it}Z") }.toTypedArray())

        val one = load.bridge.pollInteractions(clientId, null, null, limit = 2)
        assertEquals(listOf(1L, 2L), one.seqs())
        assertTrue(one.flag("has_more"))
        assertEquals(2, one.int("next_since"))

        val two = load.bridge.pollInteractions(clientId, null, null, since = 2, limit = 2)
        assertEquals(listOf(3L, 4L), two.seqs())
        assertTrue(two.flag("has_more"))

        val three = load.bridge.pollInteractions(clientId, null, null, since = 4, limit = 2)
        assertEquals(listOf(5L), three.seqs())
        assertFalse(three.flag("has_more"))
        assertEquals(5, three.int("next_since"))

        val idle = load.bridge.pollInteractions(clientId, null, null, since = 5)
        assertEquals(0, idle.int("interaction_count"))
        assertEquals(5, idle.int("next_since"))

        burp.arrive("secret-1", httpAt("p1", "2026-11-17T10:01:00Z"))
        val fresh = load.bridge.pollInteractions(clientId, null, null, since = 5)
        assertEquals(listOf(6L), fresh.seqs())
        assertEquals(listOf("http"), fresh.types())
    }

    @Test
    fun `a poll result shows what was exfiltrated`() {
        val load = Load()
        val clientId = load.bridge.createClient().text("client_id")!!
        val request = "POST /leak?d=c2VjcmV0 HTTP/1.1\r\nHost: p1.oast.test\r\nCookie: session=abc\r\nUser-Agent: curl/8.4.0\r\n\r\npw=hunter2"
        burp.arrive(
            "secret-1",
            dnsAt("p1", "2026-11-17T10:00:00Z"),
            interaction("p1", InteractionType.HTTP, "2026-11-17T10:00:01Z", http = httpHit("http://p1.oast.test/leak?d=c2VjcmV0", request)),
            smtpAt("p1", "2026-11-17T10:00:02Z"),
        )
        val (dns, http, smtp) = load.bridge.pollInteractions(clientId, null, null).interactions()

        assertEquals("203.0.113.5", http.text("client_ip"))
        assertEquals(44321, http.int("client_port"))
        assertEquals("2026-11-17T10:00:01Z", http.text("timestamp"))
        val httpDetails = http.getValue("http_details").jsonObject
        assertEquals("HTTP", httpDetails.text("protocol"))
        assertEquals("POST", httpDetails.text("request_method"))
        assertEquals("http://p1.oast.test/leak?d=c2VjcmV0", httpDetails.text("request_url"))
        assertEquals("POST /leak?d=c2VjcmV0 HTTP/1.1", httpDetails.text("request_line"))
        assertEquals(
            listOf("Host" to "p1.oast.test", "Cookie" to "session=abc", "User-Agent" to "curl/8.4.0"),
            httpDetails.getValue("request_headers").jsonArray.map { it.jsonObject.text("name") to it.jsonObject.text("value") }
        )
        assertEquals("pw=hunter2", httpDetails.text("request_body"))
        assertEquals(200, httpDetails.int("response_status"))
        assertEquals(
            listOf("Server" to "Burp Collaborator"),
            httpDetails.getValue("response_headers").jsonArray.map { it.jsonObject.text("name") to it.jsonObject.text("value") }
        )
        assertEquals("<html><body>zq8</body></html>", httpDetails.text("response_body"))

        val dnsDetails = dns.getValue("dns_details").jsonObject
        assertEquals("A", dnsDetails.text("query_type"))
        assertEquals("p1.oast.test", dnsDetails.text("query_name"))
        assertEquals("00".repeat(12) + "027031" + "046f617374" + "0474657374" + "00" + "00010001", dnsDetails.text("query_hex"))

        val smtpDetails = smtp.getValue("smtp_details").jsonObject
        assertEquals("SMTP", smtpDetails.text("protocol"))
        assertEquals("EHLO x\r\nRCPT TO:<a@p1.oast.test>\r\n", smtpDetails.text("conversation"))
    }

    @Test
    fun `a malformed DNS query is reported as a decode error, not as a name`() {
        val load = Load()
        val clientId = load.bridge.createClient().text("client_id")!!
        // a reserved label type where the QNAME should start, followed by bytes that used to be read as a label
        val query = ByteArray(12) + byteArrayOf(0x80.toByte()) + ByteArray(130) { 'a'.code.toByte() } + byteArrayOf(0)
        burp.arrive("secret-1", interaction("p1", InteractionType.DNS, "2026-11-17T10:00:00Z", dns = rawDns(query)))

        val dns = load.bridge.pollInteractions(clientId, null, null).interactions().single().getValue("dns_details").jsonObject
        assertNull(dns["query_name"])
        assertEquals("reserved label type (length byte 0x80) at offset 12", dns.text("query_name_error"))
        assertEquals("UNKNOWN", dns.text("query_type"))
        assertTrue(dns.text("query_hex")!!.startsWith("00".repeat(12) + "80" + "61".repeat(130)))
    }

    @Test
    fun `an interaction whose details Burp cannot give is still recorded`() {
        val load = Load()
        val clientId = load.bridge.createClient().text("client_id")!!
        val broken: Interaction = fake { m, _ ->
            when (m) {
                "id" -> interactionId("p1")
                "type" -> InteractionType.HTTP
                "timeStamp" -> ZonedDateTime.parse("2026-11-17T10:00:00Z")
                "clientIp" -> InetAddress.getByName("203.0.113.5")
                "clientPort" -> 44321
                "customData" -> Optional.empty<String>()
                else -> throw IllegalStateException("details unavailable")
            }
        }
        burp.arrive("secret-1", broken, interaction("p1", InteractionType.SMTP, "2026-11-17T10:00:01Z"))

        val poll = load.bridge.pollInteractions(clientId, null, null)
        assertNull(poll["error"])
        val (http, smtp) = poll.interactions()
        assertEquals("p1", http.text("payload_id"))
        assertEquals("Could not read HTTP details: details unavailable", http.getValue("http_details").jsonObject.text("error"))
        assertEquals("SMTP details not available", smtp.getValue("smtp_details").jsonObject.text("error"))
    }

    @Test
    fun `each interaction is announced once, however often it is read`() {
        val load = Load()
        val clientId = load.bridge.createClient().text("client_id")!!
        burp.arrive("secret-1", dnsAt("p1", "2026-11-17T10:00:00Z"), httpAt("p1", "2026-11-17T10:00:01Z"))

        load.bridge.pollInteractions(clientId, "http", null)
        load.bridge.pollInteractions(clientId, null, null)
        load.bridge.pollInteractions(clientId, "dns", null)

        val events = load.interactionEvents()
        assertEquals(listOf("dns", "http"), events.map { it.text("type") }, "the type filter of the first poll hid nothing from listeners")
        assertEquals(listOf(1L, 2L), events.map { it.getValue("seq").jsonPrimitive.long })
        assertTrue(events.all { it.text("client_id") == clientId && it.text("id") == "p1" })
        val httpEvent = events[1].getValue("http_details").jsonObject
        assertEquals("GET", httpEvent.text("request_method"))
        assertEquals("http://p1.oast.test/", httpEvent.text("request_url"))
        assertEquals(200, httpEvent.int("response_status"))
        assertNull(httpEvent["request_headers"], "an event is a summary; the poll result has the full exchange")
        assertNull(httpEvent["response_body"])
    }

    @Test
    fun `a poll that fails is an error and the interactions are there on the next one`() {
        val load = Load()
        val clientId = load.bridge.createClient().text("client_id")!!
        burp.arrive("secret-1", dnsAt("p1", "2026-11-17T10:00:00Z"))

        burp.failNextPoll = true
        assertEquals(
            "Failed to poll interactions: Burp Collaborator is disabled",
            load.bridge.pollInteractions(clientId, null, null).text("error")
        )
        assertEquals(listOf("dns"), load.bridge.pollInteractions(clientId, null, null).types())
    }

    @Test
    fun `bad poll arguments are rejected before the server is asked`() {
        val load = Load()
        val clientId = load.bridge.createClient().text("client_id")!!
        burp.arrive("secret-1", dnsAt("p1", "2026-11-17T10:00:00Z"))

        val badType = load.bridge.pollInteractions(clientId, "ftp", null).text("error")
        assertEquals("Parameter 'type' has invalid value 'ftp'. Allowed: dns, http, smtp", badType)
        assertEquals("Parameter 'since' must be 0 or greater (got -1)", load.bridge.pollInteractions(clientId, null, null, since = -1).text("error"))
        assertEquals("Parameter 'limit' must be between 1 and 1000 (got 0)", load.bridge.pollInteractions(clientId, null, null, limit = 0).text("error"))
        assertEquals("Parameter 'limit' must be between 1 and 1000 (got 1001)", load.bridge.pollInteractions(clientId, null, null, limit = 1001).text("error"))
        assertEquals(
            "Parameter 'max_body_length' must be between 1 and 1000000 (got 0)",
            load.bridge.pollInteractions(clientId, null, null, maxBodyLength = 0).text("error")
        )
        assertEquals("Client not found: collab-404", load.bridge.pollInteractions("collab-404", null, null).text("error"))
        assertEquals(0, burp.polls, "a rejected poll must not drain the server")

        // blank filters mean no filter
        assertEquals(listOf("dns"), load.bridge.pollInteractions(clientId, " ", "").types())
    }

    // ---------------------------------------------------------------
    // Turbo side of the shared provider
    // ---------------------------------------------------------------

    @Test
    fun `Turbo payloads use a listed client and share the history with the tools`() {
        val load = Load()
        val payload = load.provider.generatePayload("SSRF in webhook")
        assertEquals("p1.oast.test", payload)

        val turboClient = load.bridge.listClients().clients().single()
        assertEquals("collab-001", turboClient.text("client_id"))
        assertEquals("turbo", turboClient.text("label"))
        assertEquals(1, turboClient.int("payloads_generated"))
        assertEquals("p2.oast.test", load.provider.generatePayload("second"), "the same client serves the next payload")
        assertEquals(1, load.state.collaboratorClients.size)

        burp.arrive("secret-1", httpAt("p1", "2026-11-17T10:00:01Z"), dnsAt("p1", "2026-11-17T10:00:00Z"), dnsAt("p2", "2026-11-17T10:00:02Z"))
        val viaTurbo = load.provider.getInteractions(listOf(payload))
        assertEquals(listOf("DNS", "HTTP"), viaTurbo.map { it.type })
        assertTrue(viaTurbo.all { it.payload == "p1.oast.test" && it.metadata == "SSRF in webhook" && it.clientIp == "203.0.113.5" })
        assertEquals("p1.oast.test", viaTurbo[0].details["query_name"])
        assertEquals("GET / HTTP/1.1\r\nHost: p1.oast.test\r\n\r\n", viaTurbo[1].details["request"])
        assertEquals(COLLABORATOR_RESPONSE, viaTurbo[1].details["response"])

        // Turbo's read consumed nothing: the tools see the same interactions, with the Turbo label
        val viaTools = load.bridge.pollInteractions("collab-001", null, null)
        assertEquals(listOf("dns", "http", "dns"), viaTools.types())
        assertEquals(listOf("SSRF in webhook", "SSRF in webhook", "second"), viaTools.interactions().map { it.text("metadata") })
        assertEquals(2, burp.polls, "one poll by Turbo and one by the tools; neither fetched the other's client twice")
    }

    @Test
    fun `Turbo HTTP hits are copied to Organizer once`() {
        val load = Load()
        val payload = load.provider.generatePayload("SSRF in webhook")
        burp.arrive("secret-1", dnsAt("p1", "2026-11-17T10:00:00Z"), httpAt("p1", "2026-11-17T10:00:01Z"))

        load.provider.getInteractions(listOf(payload))
        load.provider.getInteractions(null)
        load.bridge.pollInteractions("collab-001", null, null)
        assertEquals(listOf("[Collaborator] SSRF in webhook | 2026-11-17T10:00:01Z | 203.0.113.5"), burp.organized)

        // a client the tools created is not Turbo's: its hits stay out of Organizer
        val toolsClient = load.bridge.createClient().text("client_id")!!
        burp.arrive("secret-2", httpAt("p9", "2026-11-17T10:00:05Z"))
        assertEquals(1, load.bridge.pollInteractions(toolsClient, null, null).int("interaction_count"))
        assertEquals(1, burp.organized.size)
    }

    @Test
    fun `Turbo keeps its client across a reload`() {
        val first = Load()
        first.provider.generatePayload("before the reload")

        val second = Load()
        assertEquals("p2.oast.test", second.provider.generatePayload("after the reload"))
        assertEquals(setOf("collab-001"), second.state.collaboratorClients.keys.toSet())
        assertEquals(listOf("secret-1"), burp.restored)

        // an interaction of the payload generated before the reload still reaches Turbo, by its host
        burp.arrive("secret-1", dnsAt("p1", "2026-11-17T10:00:00Z"))
        val old = second.provider.getInteractions(listOf("p1.oast.test")).single()
        assertEquals("p1", old.payload, "its host and label were only known to the previous load")
        assertNull(old.metadata)
    }

    @Test
    fun `a Turbo poll reaches every client when the payload is not a known one`() {
        val load = Load()
        load.bridge.createClient()
        load.bridge.createClient()
        burp.arrive("secret-1", dnsAt("a1", "2026-11-17T10:00:00Z"))
        burp.arrive("secret-2", dnsAt("b1", "2026-11-17T10:00:01Z"))

        assertEquals(listOf("b1"), load.provider.getInteractions(listOf("b1.oast.test")).map { it.payload })
        assertEquals(2, burp.polls, "both clients were polled")
        // which client is polled first is not defined, so neither is the order of the two records
        assertEquals(setOf("a1", "b1"), load.provider.getInteractions(null).map { it.payload }.toSet())
        assertEquals(listOf("dns"), load.bridge.pollInteractions("collab-001", null, null).types(), "nothing was lost to the other reader")
    }
}
