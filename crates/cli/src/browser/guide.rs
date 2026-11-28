//! The `browser` guide texts: how to call it, the page command cheat-sheet with what replaces
//! each old `browser_*` tool, and the automation block format.

pub const BROWSER_GUIDE: &str = r#"browser: ShardBrowser profiles and their browser, driven in-process.
Call: browser {"do":"<action>", ...its parameters}; several in order: browser {"batch":[{"do":...},...],"bail":true}. run takes the same calls as {"do":"browser.<action>", ...}. guide {"topic":"browser.<action>"} gives one action's parameters.

Typical flow:
1. {"do":"create_temporary_profile","via_burp":true}: a throwaway profile whose traffic goes through this target's Burp (its id is P).
2. {"do":"page","profile_id":"P","cmd":"open https://target"}
3. {"do":"page","profile_id":"P","cmd":"snapshot -i"}, then "cmd":"click @eN" or "cmd":"fill @eN \"text\"".
4. human_fill / human_click where the site watches how input arrives.
5. script (Playwright JS or automation blocks) for what page commands cannot do.
6. {"do":"stop_profile","id":"P"}

Rules:
- Refs (@eN) come from snapshot; they work in page commands and in the selector of human/touch actions.
- Page commands do not auto-wait: use "wait <sel>".
- Routes, dialog handlers and other listeners set in a script last only while that script runs: put the actions that need them in the same script.
- Page actions and scripts start the profile when it is not running (headless: true for no window).

Config: SHARDX_API, else [browser] api in raijin.toml, else the local launcher's port (default http://127.0.0.1:40325); SHARDX_TOKEN (or the variable [browser] token_env names), else a token made from the local launcher's own settings, so a launcher on this machine needs no setup. health_check shows which token is used. Playwright scripts need the driver: cargo install playwright-rs --features cli && playwright-rs install (or PLAYWRIGHT_DRIVER_PATH). Topics: browser.page (page commands), browser.blocks (automation blocks)."#;

pub const PAGE_GUIDE: &str = r#"page: agent-browser commands on a profile's browser. {"do":"page","profile_id":"<id>","cmd":"<line>"} runs one line; "cmds":["<line>",...] runs several, stopping at the first failure unless "continue_on_error":true. Quote text with spaces: fill @e2 "hello world".

Commands:
- open <url> | back | forward | reload
- snapshot [-i] [-c] [-d N] [-s <css>]   (-i: interactive elements only; refs [ref=eN])
- click|dblclick|hover|focus|check|uncheck <sel>; click <sel> --button right
- fill <sel> <text> | type <sel> <text> | press <key> | select <sel> <value> | upload <sel> <abs paths...> | drag <from> <to>
- get text|html|value|attr|count|box|url|title ...; is visible|enabled|checked <sel>
- wait <sel> [--state visible|hidden] [--timeout <ms>] | wait <ms> | wait --url <glob> | wait --load <state> | wait --fn <js> | wait --download <abs path>
- scroll down <px> | scrollintoview <sel>
- screenshot [--full] [<sel>] [<abs.png>] (returns the path; without one the file goes to <target>/.raijin/screenshots/) | pdf <abs.pdf> | eval <js> (everything after "eval " is the JavaScript, quotes included; one wholly quoted token is unquoted)
- cookies [set <name> <value> --url <u>|clear] | storage local [get <k>|set <k> <v>|clear]
- tab list|new [url]|<tN>|close [tN] | frame <css selector of the iframe element>|main (e.g. frame iframe[name=x]) | dialog accept [text]|dismiss (confirm and prompt; alert and beforeunload are accepted automatically)
- set viewport <w> <h> | set headers <json> | set offline on|off
- network requests [--filter <s>] [--type <csv>] [--method <m>] [--status <code|4xx|400-499>] [--full] [--clear] | network request <id> | network route <url> [--abort|--body <json>] [--resource-type <csv>] | network unroute [url] | network har start | network har stop <path>
- console | errors | mouse move <x> <y> | mouse down|up [button] | keyboard inserttext <text>
- find text|role|label <value> <action> [text]

Network capture runs from the moment raijin attaches to the profile. network requests prints one line per request (id method status type url), --full every field, --clear empties the log. Redirect hops share an id; network request <id> shows the last hop with its body.

Selectors: CSS, xpath=..., or snapshot refs (@eN). text= and role= are not selectors here: use find text|role|label <value> <action>.
Not available: connect, close, session, install, upgrade, dashboard, stream, batch, --stdin (start_profile / stop_profile manage the browser).
Below, page "X" means {"do":"page","profile_id":"<id>","cmd":"X"}, cmds [...] means "cmds":[...], and script js: X means {"do":"script","profile_id":"<id>","js":"X"}."#;

pub const BLOCKS_GUIDE: &str = r#"Automation blocks: browser {"do":"script","profile_id":"<id>","blocks":[{"kind":"goto","params":{"url":"https://example.com"}},...]} runs them in the launcher's own runner on that profile. Each block: {"kind":..., "params":{...}, "on_fail":"stop"|"next"}. Variables are written {{name}}.

Kinds and params:
- Profiles and proxies: profile.create|profile.temp (name, folder, platform, proxy, into); profile.use (id); profile.keep (folder); profile.delete (id); proxy.set|proxy.swap (proxy)
- Variables: var.set (name, value); var.math (op, a, b, into); var.random (into, list, min, max)
- http.request (url, method, into, headers, body, session, via, timeout)
- Navigation: goto (url; returns once the page has loaded); reload; back; forward; waitLoad (timeout in seconds, default 30: waits for the next load event, so use it only after a click or script that navigates, never right after goto; it returns at the timeout without failing)
- Input: click|doubleClick|rightClick|hover (selector | x, y); drag|swipe (selector, to, dx, dy, holdMs, button); scroll (deltaY, deltaX, selector); type (selector, text); press (key, modifiers); clear (selector, count)
- Waits, all in seconds, not ms (a wait longer than the call's timeout_ms is refused): wait (seconds, default 1); waitFor (selector, timeout, default 15); waitGone (selector, timeout); waitText (selector, text, timeout); waitUrl (url, timeout)
- Conditions: if.exists (selector); if.text (selector, op, text); if.url (op, text); if.value (a, op, b)
- Reads: count (selector, into); readText (selector, into); readAttribute (selector, name, into)
- screenshot (path); log (text); stop
- script.run (file|source, world, into)
- touch.tap|touch.longPress|touch.swipe|touch.drag|touch.pinch (selector, x, y, to, holdMs, tapCount, dx, dy, scale); screen.rotate (angle, turnMs)
- Files and data: file.readLine (path, into, take); file.append (path, line); db.open|db.exec|db.query|db.close
- flow.call (project)

The result: {project_id, project_name, saved, ok, workers, log}; ok is false (an error result) when a worker did not finish "done".
The launcher closes the profile's browser when the run ends, and a temporary profile is then deleted: run blocks on a persistent profile when page commands follow, or put the whole flow in the blocks.
Saved projects: save_as keeps the project under that name; rerun it with {"do":"script","project":"<name>","profile_id":"<id>"} (profile_id rebinds its first, raijin-profile, block)."#;

/// The Node MCP server's `browser_*` tools and what replaces each here.
pub const LEGACY: &[(&str, &str)] = &[
    ("browser_navigate", r#"page "open <url>""#),
    ("browser_evaluate", r#"page "eval <js>""#),
    ("browser_content", "script js: return await page.content()"),
    (
        "browser_screenshot",
        r#"page "screenshot [--full] [<abs.png>]" (no path: .raijin/screenshots/)"#,
    ),
    (
        "browser_element_screenshot",
        r#"page "screenshot <sel> [<abs.png>]""#,
    ),
    ("browser_click", r#"page "click <sel>""#),
    ("browser_double_click", r#"page "dblclick <sel>""#),
    (
        "browser_right_click",
        r#"page "click <sel> --button right""#,
    ),
    ("browser_fill", r#"page "fill <sel> <text>""#),
    ("browser_type", r#"page "type <sel> <text>""#),
    (
        "browser_current_url",
        r#"page cmds ["get url","get title"]"#,
    ),
    ("browser_back", r#"page "back""#),
    ("browser_forward", r#"page "forward""#),
    ("browser_reload", r#"page "reload""#),
    (
        "browser_wait_for_selector",
        r#"page "wait <sel> --state visible --timeout <ms>""#,
    ),
    ("browser_wait_for_load", r#"page "wait --load <state>""#),
    ("browser_wait", r#"page "wait <ms>""#),
    ("browser_get_text", r#"page "get text <sel>""#),
    ("browser_text", r#"page "get text body""#),
    ("browser_get_attribute", r#"page "get attr <sel> <name>""#),
    (
        "browser_get_html",
        "script js: return await page.locator(SEL).first().evaluate(e => e.outerHTML)",
    ),
    ("browser_exists", r#"page "get count <sel>""#),
    ("browser_count", r#"page "get count <sel>""#),
    (
        "browser_links",
        "script js: return await page.$$eval('a[href]', as => as.map(a => ({text: a.innerText.trim().slice(0,120), href: a.href})))",
    ),
    ("browser_press", r#"page "press <key>""#),
    (
        "browser_press_on",
        r#"page cmds ["focus <sel>","press <key>"]"#,
    ),
    ("browser_hover", r#"page "hover <sel>""#),
    ("browser_focus", r#"page "focus <sel>""#),
    ("browser_select_option", r#"page "select <sel> <value>""#),
    (
        "browser_set_checkbox",
        r#"page "check <sel>" / "uncheck <sel>""#,
    ),
    (
        "browser_scroll",
        r#"page "scrollintoview <sel>" or "scroll down <px>""#,
    ),
    (
        "browser_scroll_to_bottom",
        r#"page "eval window.scrollTo(0, document.body.scrollHeight)""#,
    ),
    ("browser_set_files", r#"page "upload <sel> <abs paths...>""#),
    ("browser_set_viewport", r#"page "set viewport <w> <h>""#),
    ("browser_pdf", r#"page "pdf <abs.pdf>""#),
    ("browser_get_cookies", r#"page "cookies""#),
    (
        "browser_set_cookies",
        r#"page "cookies set <name> <value> --url <u>""#,
    ),
    ("browser_clear_cookies", r#"page "cookies clear""#),
    ("browser_list_tabs", r#"page "tab list""#),
    ("browser_open_tab", r#"page "tab new [url]""#),
    ("browser_switch_tab", r#"page "tab <tN>""#),
    ("browser_close_tab", r#"page "tab close [tN]""#),
    (
        "browser_element_state",
        r#"page "is visible|enabled|checked <sel>""#,
    ),
    ("browser_bounding_box", r#"page "get box <sel>""#),
    ("browser_input_value", r#"page "get value <sel>""#),
    ("browser_wait_for_url", r#"page "wait --url <glob>""#),
    ("browser_wait_for_function", r#"page "wait --fn <js>""#),
    ("browser_drag", r#"page "drag <from> <to>""#),
    (
        "browser_mouse_click",
        r#"page cmds ["mouse move <x> <y>","mouse down left","mouse up left"]"#,
    ),
    (
        "browser_local_storage",
        r#"page "storage local [get <k>|set <k> <v>|clear]""#,
    ),
    ("browser_set_extra_headers", r#"page "set headers <json>""#),
    (
        "browser_dialog",
        r#"page "dialog accept [text]" / "dialog dismiss" (an open dialog); a standing policy: script with page.on('dialog', ...) — alert and beforeunload are accepted automatically"#,
    ),
    (
        "browser_block_resources",
        r#"page "network route * --abort --resource-type <csv>""#,
    ),
    (
        "browser_frames",
        "script js: return page.frames().map((f,i)=>({index:i,name:f.name(),url:f.url()}))",
    ),
    (
        "browser_frame_evaluate",
        r#"page cmds ["frame iframe[name=x]","eval <js>","frame main"]"#,
    ),
    (
        "browser_get_texts",
        "script js: return await page.locator(SEL).allInnerTexts()",
    ),
    (
        "browser_insert_text",
        r#"page "keyboard inserttext <text>""#,
    ),
    ("browser_aria_snapshot", r#"page "snapshot [-s <sel>]""#),
    (
        "browser_wait_for_response",
        "script js: const r = await page.waitForResponse(r => r.url().includes(P), {timeout: 30000}); return {url: r.url(), status: r.status()}",
    ),
    (
        "browser_capture_start",
        r#"page "network requests --clear" (capture is always on; this empties the log) (or "network har start")"#,
    ),
    (
        "browser_capture_stop",
        r#"page "network requests" (or "network har stop <path>")"#,
    ),
    (
        "browser_mock",
        r#"page "network route <pattern> --body <json>"; a custom status or content-type: script with page.route"#,
    ),
    ("browser_unmock", r#"page "network unroute [pattern]""#),
    (
        "browser_intercept",
        "script js: await page.route(P, r => r.continue({headers: {...r.request().headers(), ...H}, postData: B})), with the actions that need it in the same script",
    ),
    (
        "browser_set_network_conditions",
        r#"page "set offline on|off"; latency/throughput: script js: const s = await context.newCDPSession(page); await s.send('Network.emulateNetworkConditions', {offline:false, latency:L, downloadThroughput:D*128, uploadThroughput:U*128})"#,
    ),
    (
        "browser_wait_for_download",
        r#"page "wait --download <abs path> --timeout <ms>""#,
    ),
];

/// [`LEGACY`] as text, one `old → replacement` per line.
pub fn legacy_table() -> String {
    let mut out = String::from("Old browser_* tools and what replaces them:");
    for (old, replacement) in LEGACY {
        out.push('\n');
        out.push_str(old);
        out.push_str(" → ");
        out.push_str(replacement);
    }
    out
}
