package io.bitbytelab.raijin.recon

import io.bitbytelab.raijin.core.ProbeResult
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class Soft404Test {

    private fun seen(path: String, status: Int, body: String, location: String? = null): PathFingerprint =
        Soft404.fingerprint(path, ProbeResult(status, body, if (location == null) emptyMap() else mapOf("location" to location)))

    /** A not-found page that repeats the requested path [times] times. */
    private fun echoing(path: String, times: Int): String = "<html>\n<p>Nothing at " + "$path ".repeat(times) + "here</p>\n</html>"

    @Test
    fun `paths are told apart by how servers route them`() {
        assertEquals(Soft404.PLAIN, Soft404.shapeOf("/admin"))
        assertEquals(Soft404.PLAIN, Soft404.shapeOf("/api/v1/users?id=1"))
        assertEquals(Soft404.DIRECTORY, Soft404.shapeOf("/assets/"))
        assertEquals(Soft404.DOTFILE, Soft404.shapeOf("/.env"))
        assertEquals(Soft404.DOTFILE, Soft404.shapeOf("/app/.htaccess"))
        assertEquals("ext:php", Soft404.shapeOf("/index.PHP"))
        assertEquals("ext:gz", Soft404.shapeOf("/backup.tar.gz"))
        // A dot that does not end in an extension: a version number, a trailing dot.
        assertEquals(Soft404.PLAIN, Soft404.shapeOf("/release-1.2-notes_final"))
        assertEquals(Soft404.PLAIN, Soft404.shapeOf("/file."))
    }

    @Test
    fun `directory and made-up sibling stay next to the path`() {
        assertEquals("/", Soft404.directoryOf("/admin"))
        assertEquals("/a/b/", Soft404.directoryOf("/a/b/c.php?x=/y"))
        assertEquals("/assets/", Soft404.directoryOf("/assets/"))

        val random = Random(1)
        assertTrue(Regex("/a/b/[a-z][a-z0-9]{11}\\.php").matches(Soft404.madeUpSibling("/a/b/c.php", random)))
        assertTrue(Regex("/a/[a-z][a-z0-9]{11}").matches(Soft404.madeUpSibling("/a/users", random)))
        assertTrue(Regex("/a/[a-z][a-z0-9]{11}/").matches(Soft404.madeUpSibling("/a/users/", random)))
        assertTrue(Regex("/\\.[a-z][a-z0-9]{11}").matches(Soft404.madeUpSibling("/.env", random)))
    }

    @Test
    fun `calibration covers several lengths and shapes, and the extensions the wordlist uses`() {
        val paths = Soft404.calibrationPaths(listOf("/a.bak", "/b.bak", "/c.txt", "/.git/HEAD", "/.env", "/dir/", "/plain"), Random(1))
        val shapes = paths.groupingBy { Soft404.shapeOf(it) }.eachCount()

        assertEquals(paths.size, paths.toSet().size)
        assertTrue(paths.filter { Soft404.shapeOf(it) == Soft404.PLAIN }.map { it.length }.toSet().size >= 3, "plain paths of too few lengths")
        assertTrue(paths.any { it.count { ch -> ch == '/' } == 2 && !it.endsWith("/") }, "no nested path")
        assertEquals(1, shapes["ext:json"])
        assertEquals(1, shapes["ext:php"])
        assertEquals(4, shapes[Soft404.DIRECTORY])
        assertEquals(3, shapes["ext:bak"])
        assertEquals(3, shapes["ext:txt"])
        assertEquals(3, shapes[Soft404.DOTFILE])
        assertEquals(3, paths.filter { it.endsWith(".bak") }.map { it.length }.toSet().size, "the .bak paths do not differ in length")

        // Without a wordlist the fixed set is still there.
        assertEquals(6, Soft404.calibrationPaths(emptyList(), Random(1)).size)
    }

    @Test
    fun `a fingerprint counts lines and words and reduces the redirect target to its shape`() {
        val page = seen("/a/b", 200, "one two\nthree\n\n  four  ")
        assertEquals(23, page.length)
        assertEquals(3, page.lines)
        assertEquals(4, page.words)
        assertNull(page.location)

        val mark = Soft404.PATH_MARK
        assertEquals("$mark/", Soft404.normalizeLocation("https://t.example/a/b/", "/a/b"))
        assertEquals("/login?next=$mark", Soft404.normalizeLocation("/login?next=%2Fa%2Fb", "/a/b"))
        assertEquals("/en$mark", Soft404.normalizeLocation("//t.example/en/a/b", "/a/b?x=1"))
        assertEquals("/login", Soft404.normalizeLocation(" /login ", "/a/b"))
        assertEquals("/", Soft404.normalizeLocation("https://other.example", "/a/b"))
    }

    @Test
    fun `a not-found page that repeats the path matches whatever the path length`() {
        for (times in 0..3) {
            val profile = Soft404Profile()
            for (path in listOf("/abcdefgh", "/abcdefghijklmnopqrstuvwx", "/abcdefgh/ijklmnop")) {
                profile.add(Soft404.SITE, seen(path, 200, echoing(path, times)))
            }
            assertTrue(profile.wildcard)
            for (path in listOf("/x", "/admin", "/a/very/long/path/that/is/much/longer/than/any/calibration/path")) {
                assertTrue(profile.matches(seen(path, 200, echoing(path, times))), "times=$times path=$path")
            }
            // Another page at the same status is not the not-found page.
            assertFalse(profile.matches(seen("/admin", 200, "<html>\n<h1>Admin</h1>\n" + "<p>row</p>\n".repeat(40) + "</html>")), "times=$times")
            assertFalse(profile.matches(seen("/admin", 403, echoing("/admin", times))), "another status")
        }
    }

    @Test
    fun `a page whose length varies on its own is matched within what the samples showed`() {
        val profile = Soft404Profile()
        for ((path, filler) in listOf("/abcdefgh" to 60, "/abcdefghijklmnopqrstuvwx" to 0, "/abcdefgh/ijklmnop" to 30)) {
            profile.add(Soft404.SITE, seen(path, 404, "<html>\n<p>not found</p>\n" + "x".repeat(filler) + "\n</html>"))
        }
        assertTrue(profile.matches(seen("/admin", 404, "<html>\n<p>not found</p>\n" + "x".repeat(100) + "\n</html>")))
        assertFalse(profile.matches(seen("/admin", 404, "<html>\n<p>not found</p>\n" + "x".repeat(400) + "\n</html>")))
        assertFalse(profile.wildcard)
    }

    @Test
    fun `two samples are not enough to read a length difference as a repeated path`() {
        val profile = Soft404Profile()
        // 16 characters apart in path and in body: a coincidence as far as two samples can tell.
        profile.add(Soft404.SITE, seen("/abcdefgh", 404, "x".repeat(100)))
        profile.add(Soft404.SITE, seen("/abcdefghijklmnopqrstuvwx", 404, "x".repeat(116)))
        assertTrue(profile.matches(seen("/a", 404, "x".repeat(108))))
    }

    @Test
    fun `redirects are compared by where they lead`() {
        val profile = Soft404Profile()
        profile.add(Soft404.SITE, seen("/abcdefgh", 301, "", "/abcdefgh/"))
        profile.add(Soft404.SITE, seen("/abcdefghijklmnop", 301, "", "https://t.example/abcdefghijklmnop/"))

        assertTrue(profile.matches(seen("/images", 301, "moved", "/images/")))
        assertFalse(profile.matches(seen("/images", 301, "", "/login")))
        assertFalse(profile.matches(seen("/images", 302, "", "/images/")))
    }

    @Test
    fun `a shape is judged by its own samples, an unsampled shape by all of them`() {
        val profile = Soft404Profile()
        profile.add(Soft404.SITE, seen("/abcdefgh", 404, "not found"))
        profile.add(Soft404.SITE, seen("/abcdefgh.php", 403, "php disabled"))

        assertTrue(profile.matches(seen("/index.php", 403, "php disabled")))
        // A plain path answered like the .php handler is not what plain made-up paths get.
        assertFalse(profile.matches(seen("/admin", 403, "php disabled")))
        // No .bak path was sampled: any known not-found answer counts.
        assertTrue(profile.matches(seen("/db.bak", 403, "php disabled")))
        assertTrue(profile.matches(seen("/db.bak", 404, "not found")))
        assertFalse(profile.matches(seen("/db.bak", 200, "PK...")))
    }

    @Test
    fun `what is learned for a directory applies under it only`() {
        val profile = Soft404Profile()
        profile.add(Soft404.SITE, seen("/abcdefgh", 404, "not found"))
        profile.add("/private/", seen("/private/abcdefgh", 403, "Forbidden"))

        assertTrue(profile.matches(seen("/private/keys", 403, "Forbidden")))
        assertTrue(profile.matches(seen("/private/deep/er.txt", 403, "Forbidden")))
        assertFalse(profile.matches(seen("/admin", 403, "Forbidden")))
        assertFalse(profile.wildcard)
    }

    @Test
    fun `fingerprints of the same page agree across paths, different pages do not`() {
        val forbidden = seen("/abc", 403, "Forbidden")
        assertTrue(forbidden.sameAs(seen("/a/much/longer/path.php", 403, "Forbidden")))
        assertFalse(forbidden.sameAs(seen("/abc", 404, "Forbidden")))
        assertFalse(forbidden.sameAs(seen("/abc", 403, "Forbidden\n".repeat(30))))
        assertFalse(seen("/abc", 302, "", "/login").sameAs(seen("/abc", 302, "", "/other")))
        assertTrue(seen("/abc", 302, "", "/abc/").sameAs(seen("/defgh", 302, "", "/defgh/")))
    }
}
