package io.bitbytelab.raijin.bridge

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

class AuthDiffVerdictTest {

    // exact-match similarity for deterministic tests (0 or 100)
    private val sim = { a: String, b: String -> if (a == b) 100.0 else 0.0 }
    private fun lr(name: String, status: Int, body: String) = AuthDiffVerdict.LevelResult(name, status, body)

    @Test
    fun `flags all-identical responses as critical broken access control`() {
        val f = AuthDiffVerdict.assess(listOf(lr("admin", 200, "data"), lr("user", 200, "data"), lr("none", 200, "data")), sim)
        assertTrue(f.any { it.id == "all_identical" && it.severity == "critical" })
    }

    @Test
    fun `flags an unauth level that returns the same protected body as an authed level`() {
        val f = AuthDiffVerdict.assess(
            listOf(lr("admin", 200, "secret"), lr("user", 403, "denied"), lr("none", 200, "secret")), sim
        )
        assertTrue(f.any { it.id == "unauth_reads_protected" && it.severity == "critical" })
    }

    @Test
    fun `flags an unauth-accessible endpoint even when the body differs`() {
        val f = AuthDiffVerdict.assess(listOf(lr("admin", 200, "secret"), lr("none", 200, "public-page")), sim)
        assertTrue(f.any { it.id == "unauth_accessible" && it.severity == "high" })
        assertFalse(f.any { it.id == "unauth_reads_protected" })
    }

    @Test
    fun `proper enforcement (authed 200, unauth 401) yields no critical or high finding`() {
        val f = AuthDiffVerdict.assess(listOf(lr("admin", 200, "secret"), lr("none", 401, "denied")), sim)
        assertFalse(f.any { it.severity == "critical" || it.severity == "high" })
    }

    @Test
    fun `flags two different authenticated identities sharing protected content even when a third level differs`() {
        // The documented Autorize setup: a "captured" browsing session, a lower-privilege
        // identity, and "none". If low_priv sees the SAME content as the real session while none
        // is correctly blocked, overall status is not uniform (captured/low_priv=200, none=403),
        // so the all-identical branch never fires — but captured vs low_priv must still be flagged.
        val f = AuthDiffVerdict.assess(
            listOf(lr("captured", 200, "secret"), lr("low_priv", 200, "secret"), lr("none", 403, "denied")), sim
        )
        assertTrue(f.any { it.id == "cross_identity_match" && it.severity == "critical" })
        // none was properly blocked (403, not a 2xx/3xx) — must not also be flagged as accessible.
        assertFalse(f.any { it.id == "unauth_accessible" })
    }

    @Test
    fun `a matched unauth level is not also reported as unauth_accessible`() {
        val f = AuthDiffVerdict.assess(
            listOf(lr("admin", 200, "secret"), lr("user", 403, "denied"), lr("none", 200, "secret")), sim
        )
        assertTrue(f.any { it.id == "unauth_reads_protected" })
        assertFalse(f.any { it.id == "unauth_accessible" })
    }

    // Graduated similarity (not just exact-match) so the threshold overrides below are meaningful.
    private val gradedSim = { a: String, b: String ->
        if (a == b) 100.0 else if (a.take(3) == b.take(3)) 80.0 else 0.0
    }

    @Test
    fun `a lower unauthMatchThreshold flags a looser body match that the default would miss`() {
        val results = listOf(lr("admin", 200, "secretXYZ"), lr("none", 200, "secretABC"))
        val default = AuthDiffVerdict.assess(results, gradedSim)
        assertFalse(default.any { it.id == "unauth_reads_protected" })

        val loosened = AuthDiffVerdict.assess(results, gradedSim, unauthMatchThreshold = 75.0)
        assertTrue(loosened.any { it.id == "unauth_reads_protected" })
    }

    @Test
    fun `a lower allSimilarThreshold downgrades a near-identical response to all_identical`() {
        val results = listOf(lr("admin", 200, "dataXYZ"), lr("user", 200, "dataABC"), lr("none", 200, "dataQRS"))
        val default = AuthDiffVerdict.assess(results, gradedSim)
        assertFalse(default.any { it.id == "all_identical" })

        val loosened = AuthDiffVerdict.assess(results, gradedSim, allSimilarThreshold = 75.0)
        assertTrue(loosened.any { it.id == "all_identical" })
    }

    // ---- uniform refusals never rank above info (plan P0.3 / P4.2) ----

    private fun redirect(name: String, location: String?, status: Int = 302, body: String = "") =
        AuthDiffVerdict.LevelResult(name, status, body, location = location)

    private fun isActionable(f: AuthDiffVerdict.Finding) = f.severity == "critical" || f.severity == "high"

    @Test
    fun `identical 401 403 404 500 and no-response levels never yield a high or critical finding`() {
        for (status in listOf(401, 403, 404, 500, 0)) {
            val f = AuthDiffVerdict.assess(
                listOf(lr("admin", status, "nope"), lr("user", status, "nope"), lr("none", status, "nope")), sim
            )
            assertEquals(listOf("all_identical_non_success"), f.map { it.id }, "status $status")
            assertEquals("info", f.single().severity, "status $status")
        }
    }

    @Test
    fun `refusals with differing bodies yield nothing at all`() {
        for (status in listOf(401, 403, 404, 500)) {
            val f = AuthDiffVerdict.assess(
                listOf(lr("admin", status, "request a1"), lr("user", status, "request b2"), lr("none", status, "request c3")), sim
            )
            assertTrue(f.isEmpty(), "status $status: $f")
        }
    }

    @Test
    fun `levels all bounced to a login page are a uniform denial`() {
        val f = AuthDiffVerdict.assess(
            listOf(
                redirect("admin", "/login?next=%2Fadmin"),
                redirect("user", "/users/sign_in"),
                redirect("none", "https://sso.example.com/start")
            ),
            sim
        )
        assertEquals(listOf("all_identical_non_success"), f.map { it.id })
        assertEquals("info", f.single().severity)
    }

    @Test
    fun `a login redirect next to a real redirect of the same status is not identical access`() {
        // Same 302 and the same empty body: only the Location tells the two levels apart.
        val authedFirst = AuthDiffVerdict.assess(
            listOf(redirect("admin", "/dashboard"), redirect("none", "/login?next=%2Fdashboard")), sim
        )
        assertTrue(authedFirst.none(::isActionable), authedFirst.toString())

        val unauthFirst = AuthDiffVerdict.assess(
            listOf(redirect("none", "/login?next=%2Fdashboard"), redirect("admin", "/dashboard")), sim
        )
        assertTrue(unauthFirst.none(::isActionable), unauthFirst.toString())
    }

    @Test
    fun `an unauthenticated level redirected where no authenticated level goes is informational`() {
        val otherStatus = AuthDiffVerdict.assess(listOf(lr("admin", 200, "secret"), redirect("none", "/welcome")), sim)
        assertEquals(listOf("unauth_redirected"), otherStatus.map { it.id })
        assertEquals("info", otherStatus.single().severity)

        val sameStatus = AuthDiffVerdict.assess(listOf(redirect("admin", "/dashboard"), redirect("none", "/welcome")), sim)
        assertEquals(listOf("unauth_redirected"), sameStatus.map { it.id })
    }

    @Test
    fun `the same non-login redirect for every level is still flagged`() {
        val f = AuthDiffVerdict.assess(
            listOf(redirect("admin", "/orders/55?t=a1"), redirect("none", "https://shop.example/orders/55?t=b2")), sim
        )
        assertTrue(f.any { it.id == "all_identical" && it.severity == "critical" }, f.toString())
    }

    @Test
    fun `a level that got no response next to a served one is not a finding`() {
        val f = AuthDiffVerdict.assess(listOf(lr("admin", 200, "secret"), lr("none", 0, "")), sim)
        assertTrue(f.isEmpty(), f.toString())
    }

    @Test
    fun `two unauthenticated baselines agreeing is not broken access control`() {
        val f = AuthDiffVerdict.assess(listOf(lr("none", 200, "page"), lr("anonymous", 200, "page")), sim)
        assertTrue(f.none { it.severity == "critical" }, f.toString())
        assertEquals(listOf("unauth_accessible", "unauth_accessible"), f.map { it.id })
    }

    // ---- refusals served with a success status ----

    @Test
    fun `a denial message served with 200 to every level is a uniform denial`() {
        val refusal = "{\"errors\":[{\"message\":\"Not authorized\",\"extensions\":{\"code\":\"FORBIDDEN\"}}],\"data\":null}"
        val f = AuthDiffVerdict.assess(listOf(lr("admin", 200, refusal), lr("user", 200, refusal), lr("none", 200, refusal)), sim)
        assertEquals(listOf("all_identical_soft_denial"), f.map { it.id })
        assertEquals("info", f.single().severity)
    }

    @Test
    fun `a login page served with 200 to the unauthenticated level is not access`() {
        val loginPage = "<html><head><title>Sign in</title></head><body><form action=\"/session\" method=\"post\">" +
            "<input name=\"user\"><input type=\"password\" name=\"pass\"></form></body></html>"
        val f = AuthDiffVerdict.assess(listOf(lr("admin", 200, "<html>orders of admin</html>"), lr("none", 200, loginPage)), sim)
        assertEquals(listOf("unauth_soft_denial"), f.map { it.id })
        assertEquals("info", f.single().severity)
    }

    @Test
    fun `a caller-supplied denial fingerprint turns a 200 into a refusal`() {
        val levels = listOf(lr("admin", 200, "Bitte anmelden"), lr("none", 200, "Bitte anmelden"))
        assertTrue(AuthDiffVerdict.assess(levels, sim).any { it.id == "all_identical" })

        val f = AuthDiffVerdict.assess(levels, sim, denied = { it.body.contains("anmelden") })
        assertEquals(listOf("all_identical_soft_denial"), f.map { it.id })
    }

    @Test
    fun `denial heuristic recognises refusals and leaves data alone`() {
        val refusals = listOf(
            "{\"error\":\"unauthorized\",\"message\":\"Full authentication is required to access this resource\"}",
            "{\"detail\":\"Authentication credentials were not provided.\"}",
            "{\"success\":false,\"code\":401,\"msg\":\"x\"}",
            "{\"status\":\"403\",\"data\":null}",
            "<html><body><h1>Access Denied</h1></body></html>",
            "Forbidden",
            "{\"error\":\"access_denied\"}",
            "{\"error\":\"invalid_token\",\"error_description\":\"The access token expired\"}",
            "{\"message\":\"Please log in to continue\"}",
            "Your session has expired",
            "<html><head><title>Acme</title></head><body><form method=\"post\" action=\"/users/sign_in\"><input type=password name=p></form></body></html>"
        )
        refusals.forEach { assertTrue(AuthDenialHeuristic.looksDenied(it), it) }

        val data = listOf(
            "", "data", "{\"id\":1002,\"name\":\"Bob\",\"email\":\"bob@example.com\"}",
            "{\"authenticated\":true,\"user\":\"bob\"}",
            // denial words used as field names are not refusals
            "{\"permissions\":[\"forbidden_words_edit\"],\"is_forbidden\":false}",
            "{\"status\":\"ok\",\"unauthorized\":false}",
            "{\"forbidden\" : false,\"id\":1}",
            "{\"message\":\"Login successful\",\"token\":\"abc\"}",
            "{\"code\":200,\"status\":\"ok\"}",
            // a page with a password field that is not a login page
            "<html><head><title>Users</title></head><body><form action=\"/admin/users/create\"><input type=\"password\" name=\"pw\"></form></body></html>",
            "<html><head><title>Change password</title></head><body><form action=\"/account/password\"><input type=\"password\"></form></body></html>",
            // a denial word in a long document is content, not a refusal
            "x".repeat(3000) + " unauthorized"
        )
        data.forEach { assertFalse(AuthDenialHeuristic.looksDenied(it), it.take(120)) }
    }

    @Test
    fun `denial words in json data are content, only the envelope's error, message or detail refuses`() {
        val data = listOf(
            "[{\"state\":\"session_expired\"}]",
            "{\"state\":\"session_expired\",\"id\":7}",
            "{\"sessions\":[{\"id\":1,\"status\":\"expired\",\"note\":\"session expired\"}]}",
            "{\"data\":{\"message\":\"Please log in to see the attachment\"}}",
            "{\"jobs\":[{\"id\":3,\"error\":\"token expired\"}]}",
            "{\"logs\":[{\"status\":403,\"path\":\"/admin\"}]}",
            "{\"message\":{\"from\":\"bob\",\"text\":\"not allowed here\"}}",
            // JSON lines are records too
            "{\"id\":1}\n{\"state\":\"unauthorized\"}"
        )
        data.forEach { assertFalse(AuthDenialHeuristic.looksDenied(it), it) }

        val refusals = listOf(
            "{\"error\":{\"code\":401,\"message\":\"Request had invalid authentication credentials.\"}}",
            "{\"errors\":[{\"status\":\"403\",\"title\":\"Forbidden\"}]}",
            "{\"Message\":\"User is not authorized to access this resource\"}",
            "{\"messages\":[\"Session expired\"]}",
            "{\"fault\":{\"faultstring\":\"Invalid ApiKey\"}}",
            "{\"statusCode\":403,\"message\":\"x\"}",
            "{\"Error-Code\":\"401\"}"
        )
        refusals.forEach { assertTrue(AuthDenialHeuristic.looksDenied(it), it) }
    }

    @Test
    fun `short json data every identity reads alike is exposure, not a refusal`() {
        val data = "[{\"state\":\"session_expired\"}]"
        val f = AuthDiffVerdict.assess(listOf(lr("admin", 200, data), lr("low_priv", 200, data)), sim)
        assertEquals(listOf("all_identical"), f.map { it.id })
        assertEquals("critical", f.single().severity)
    }

    // ---- redirects to authenticate ----

    @Test
    fun `recognises redirects that send the client to authenticate`() {
        val bounces = listOf(
            "/login", "https://ex.com/login", "/auth/signin", "/users/sign_in", "/wp-login.php?redirect_to=x",
            "/Account/Login?ReturnUrl=%2Fadmin", "/accounts/login/?next=/a/", "/session/new", "/sessions/new",
            "login.php", "/logon.aspx", "/oauth2/v1/authorize?client_id=x", "https://login.microsoftonline.com/common/oauth2",
            "https://tenant.auth0.com/u/x", "/sso/saml", "/cas/login?service=https%3A%2F%2Fapp", "/?returnUrl=%2Fadmin",
            "/start?continue=https://app/x", "/index.php?action=login", "/?q=user/login", "/#/login",
            "/app#!/signin?next=%2Fx", "/unauthorized", "/access-denied", "/error/forbidden", "//sso.example.com/x"
        )
        bounces.forEach { assertTrue(AuthDiffVerdict.isAuthRedirect(it), it) }

        val elsewhere = listOf(
            null, "", "/", "/dashboard", "/home", "https://app.example.com/home", "/users/loginov", "/blog/in",
            "/catalog-in-stock", "/api/v1/logins", "/authors/5", "/orders/403", "/items?next=cursor123",
            "/profile?uid=1", "/cart?added=1", "/sessions/123", "/v1/users/1", "/search?q=login+page"
        )
        elsewhere.forEach { assertFalse(AuthDiffVerdict.isAuthRedirect(it), it.toString()) }
    }

    @Test
    fun `an application served from an auth-named host is not bounced by its own redirects`() {
        val console = "https://auth.example.com/console"
        assertTrue(AuthDiffVerdict.isAuthRedirect(console), "host unknown: reads as an identity provider")
        assertTrue(AuthDiffVerdict.isAuthRedirect(console, requestHost = "app.example.com"))
        assertFalse(AuthDiffVerdict.isAuthRedirect(console, requestHost = "AUTH.example.com"))
        // its login page is still a login page
        assertTrue(AuthDiffVerdict.isAuthRedirect("https://auth.example.com/login", requestHost = "auth.example.com"))

        val levels = listOf(redirect("admin", console), redirect("none", console))
        assertTrue(AuthDiffVerdict.assess(levels, sim).none(::isActionable))
        val onThatHost = AuthDiffVerdict.assess(levels, sim, url = "https://auth.example.com:8443/api/keys")
        assertTrue(onThatHost.any { it.id == "all_identical" && it.severity == "critical" }, onThatHost.toString())
    }

    // ---- static assets outside the all-identical case ----

    private fun css(name: String, status: Int, body: String) =
        AuthDiffVerdict.LevelResult(name, status, body, contentType = "text/css; charset=utf-8")

    @Test
    fun `a static asset no level is refused is not broken access control`() {
        val f = AuthDiffVerdict.assess(listOf(css("admin", 200, "a{}"), css("user", 200, "b{}"), css("none", 200, "a{}")), sim)
        assertTrue(f.none(::isActionable), f.toString())
        assertTrue(f.any { it.id == "static_asset_accessible" && it.severity == "info" }, f.toString())
    }

    @Test
    fun `a static asset one level is refused is protected and an unauthenticated read counts`() {
        val f = AuthDiffVerdict.assess(listOf(css("admin", 200, "a{}"), css("user", 403, "no"), css("none", 200, "a{}")), sim)
        assertTrue(f.any { it.id == "unauth_reads_protected" && it.severity == "critical" }, f.toString())
    }

    @Test
    fun `304 not modified and redirects to generic error pages are treated as non-success`() {
        val errorRedirects = listOf(
            "/error", "/error.html", "/error/500", "/errors?code=403",
            "https://app.example.com/404", "/404.html", "/500", "/maintenance", "/oops", "/not-found"
        )
        errorRedirects.forEach { assertTrue(AuthDiffVerdict.isErrorRedirect(it), it) }
        assertFalse(AuthDiffVerdict.isErrorRedirect("/orders/403"))
        assertFalse(AuthDiffVerdict.isErrorRedirect("/orders/404"))
        assertFalse(AuthDiffVerdict.isErrorRedirect("/dashboard"))

        val fErrorRedirect = AuthDiffVerdict.assess(
            listOf(lr("admin", 200, """{"secret":1}"""), redirect("none", "/error")),
            sim
        )
        assertTrue(fErrorRedirect.none(::isActionable), fErrorRedirect.toString())

        val fNotModified = AuthDiffVerdict.assess(
            listOf(lr("admin", 200, """{"secret":1}"""), AuthDiffVerdict.LevelResult("none", 304, "")),
            sim
        )
        assertTrue(fNotModified.none(::isActionable), fNotModified.toString())
    }
}
