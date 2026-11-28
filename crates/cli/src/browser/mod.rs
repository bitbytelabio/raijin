//! The `browser` tool of `raijin mcp`: `ShardBrowser` profiles through the launcher's HTTP API, and
//! their browser in-process through the vendored agent-browser engine (page commands), the
//! `Motion` CDP domain (human and touch input), and Playwright or automation-block scripts.

mod actions;
mod guide;
mod launcher;
mod motion;
mod page;
mod script;

use std::collections::HashMap;
use std::sync::OnceLock;

use agent_browser::flags::Flags;
use rmcp::model::{CallToolResult, ContentBlock, JsonObject};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::config::Target;
use crate::mcp::args::{parse_args, schema_of};
use crate::mcp::error::{self, Code, ToolError};

use actions::{
    AddExtensionArgs, AddProxyArgs, BookmarkArgs, BundleArgs, CookiesArgs, CreateProfileArgs,
    DeleteFolderArgs, EditProfileArgs, FingerprintArgs, FromTemplateArgs, IdArgs, NameArgs, NoArgs,
    OptionalNameArgs, PathArgs, ProfileTagsArgs, RenameFolderArgs, SaveProjectArgs, StartArgs,
    TagArgs, TempProfileArgs, TemplateArgs,
};
use motion::{
    HumanClickArgs, HumanFillArgs, HumanTypeArgs, PointArgs, ProfileArgs, RotateArgs,
    TouchDragArgs, TouchLongPressArgs, TouchPinchArgs, TouchSwipeArgs, TouchTapArgs,
};
use page::PageArgs;
use script::{ScriptArgs, ScriptNameArgs};

/// The tool's own description, also checked by the gateway's example test.
pub const BROWSER_DESCRIPTION: &str = "ShardBrowser profiles and their browser, driven in-process: \
launcher actions, page commands on the agent-browser engine (snapshot -i, click @e3, network requests), \
human/touch input, Playwright JS and automation-block scripts you can save and rerun. {\"do\":\"<action>\", ...}; \
several in order: {\"batch\":[{\"do\":...},...],\"bail\":true}. {\"do\":\"browser.actions\"} or guide \
{\"topic\":\"browser\"} lists the actions; guide {\"topic\":\"browser.<action>\"} gives one's parameters. \
Config: SHARDX_API, SHARDX_TOKEN.";

/// The browser actions and the launcher they talk to; one per gateway.
pub struct Hub {
    launcher: launcher::Launcher,
    /// Page sessions by profile id.
    sessions: Mutex<HashMap<String, page::Entry>>,
    /// agent-browser's flags (environment and config file), read once.
    flags: OnceLock<Result<Flags, String>>,
}

/// What a browser action needs from the gateway.
#[derive(Clone, Copy)]
pub struct Ctx<'a> {
    pub target: Option<&'a Target>,
    pub target_error: Option<&'a str>,
    pub remote: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Read,
    Write,
    Destructive,
}

/// Reads `arguments` for tool `name` as the action's argument type: its notes, or the error.
#[cfg(test)]
type Check = fn(&str, Option<JsonObject>, &Value, bool) -> Result<Vec<String>, ToolError>;

struct Action {
    name: &'static str,
    group: &'static str,
    description: &'static str,
    schema: fn() -> JsonObject,
    /// Reads a call as the action's arguments; the example test checks every example with it.
    #[cfg(test)]
    check: Check,
    /// A `browser` call (JSON) that errors show as `example`.
    example: &'static str,
    kind: Kind,
}

impl Action {
    fn example(&self) -> Value {
        serde_json::from_str(self.example)
            .unwrap_or_else(|_| json!({"do": format!("browser.{}", self.name)}))
    }

    fn destructive(&self) -> bool {
        self.kind == Kind::Destructive
    }
}

#[cfg(test)]
fn check<T: DeserializeOwned + JsonSchema>(
    tool: &str,
    arguments: Option<JsonObject>,
    example: &Value,
    destructive: bool,
) -> Result<Vec<String>, ToolError> {
    parse_args::<T>(tool, arguments, example, destructive).map(|(_, notes)| notes)
}

macro_rules! action {
    ($name:literal, $group:ident, $args:ty, $kind:ident, $example:literal, $description:expr $(,)?) => {
        Action {
            name: $name,
            group: $group,
            description: $description,
            schema: schema_of::<$args>,
            #[cfg(test)]
            check: check::<$args>,
            example: $example,
            kind: Kind::$kind,
        }
    };
}

/// Appended to the description of the actions that take `via_burp`.
macro_rules! via_burp_note {
    () => {
        " via_burp:true points the profile at this target's running Burp proxy (burp_project picks one when several run); HTTPS then needs Burp's CA trusted by the browser."
    };
}

const PROFILES: &str = "profiles";
const PROXIES: &str = "proxies";
const LIBRARY: &str = "library";
const AUTOMATION: &str = "automation";
const PAGE: &str = "page";
const HUMAN: &str = "human";
const TOUCH: &str = "touch";
const SCRIPT: &str = "script";

/// Groups in listing order.
const GROUPS: [&str; 8] = [
    PROFILES, PROXIES, LIBRARY, AUTOMATION, PAGE, HUMAN, TOUCH, SCRIPT,
];

const ACTIONS: &[Action] = &[
    action!(
        "health_check",
        PROFILES,
        NoArgs,
        Read,
        r#"{"do":"browser.health_check"}"#,
        "Whether the launcher's API is reachable and the token is right. Returns what it found rather than throwing, so this is the first thing to try when another tool fails.",
    ),
    action!(
        "list_profiles",
        PROFILES,
        NoArgs,
        Read,
        r#"{"do":"browser.list_profiles"}"#,
        "List persistent profiles with their running state and CDP endpoint.",
    ),
    action!(
        "find_profile_by_name",
        PROFILES,
        NameArgs,
        Read,
        r#"{"do":"browser.find_profile_by_name","name":"shop"}"#,
        "Find profiles whose name contains `name`, case-insensitively. Saves listing everything to turn a name into an id.",
    ),
    action!(
        "get_profile",
        PROFILES,
        IdArgs,
        Read,
        r#"{"do":"browser.get_profile","id":"p1"}"#,
        "Get a profile's full stored config by id.",
    ),
    action!(
        "new_fingerprint",
        PROFILES,
        FingerprintArgs,
        Read,
        r#"{"do":"browser.new_fingerprint","platform":"Windows"}"#,
        "Generate a fresh uniquified fingerprint (random platform_version, host-aware CPU/RAM, this computer's screen on Windows/Linux, the template's on macOS/Android). Not persisted.",
    ),
    action!(
        "create_profile",
        PROFILES,
        CreateProfileArgs,
        Write,
        r#"{"do":"browser.create_profile","name":"shop test","platform":"Windows"}"#,
        concat!(
            "Create a persistent profile. If `fingerprint` is omitted, a new one is generated for `platform` (or the host OS). `proxy` is a string added to the store; `folder` files it.",
            via_burp_note!()
        ),
    ),
    action!(
        "create_temporary_profile",
        PROFILES,
        TempProfileArgs,
        Write,
        r#"{"do":"browser.create_temporary_profile","platform":"Windows"}"#,
        concat!(
            "Create a TEMPORARY profile (hidden from the list, auto-deleted on close). Random/specified fingerprint, optional inline proxy string and noise.",
            via_burp_note!()
        ),
    ),
    action!(
        "edit_profile",
        PROFILES,
        EditProfileArgs,
        Write,
        r#"{"do":"browser.edit_profile","id":"p1","name":"shop test 2"}"#,
        concat!(
            "Edit a profile. Only provided fields change; `fingerprint` replaces it verbatim; folder:'' unfiles; proxy_id:'' unbinds; color:'' goes back to the name-derived one; `extensions` replaces the whole list; `tags` (ids or names from list_tags) replaces the profile's tags.",
            via_burp_note!()
        ),
    ),
    action!(
        "delete_profile",
        PROFILES,
        IdArgs,
        Destructive,
        r#"{"do":"browser.delete_profile","id":"p1"}"#,
        "Move a profile to the trash, restorable for 7 days (see list_trash / restore_profile).",
    ),
    action!(
        "start_profile",
        PROFILES,
        StartArgs,
        Write,
        r#"{"do":"browser.start_profile","id":"p1","headless":true}"#,
        "Launch a profile with CDP. Returns { pid, cdp:{ web_socket_debugger_url, http_url } }. The call waits up to 30s for the endpoint; if it still has none, cdp is null and cdp_error says why. Set headless to run without a window. A password-protected profile needs its password.",
    ),
    action!(
        "stop_profile",
        PROFILES,
        IdArgs,
        Destructive,
        r#"{"do":"browser.stop_profile","id":"p1"}"#,
        "Stop a profile's browser (graceful).",
    ),
    action!(
        "list_running",
        PROFILES,
        NoArgs,
        Read,
        r#"{"do":"browser.list_running"}"#,
        "List running profiles with pid and CDP endpoint.",
    ),
    action!(
        "list_fingerprints",
        PROFILES,
        NoArgs,
        Read,
        r#"{"do":"browser.list_fingerprints"}"#,
        "List the fingerprint library entries.",
    ),
    action!(
        "list_trash",
        PROFILES,
        NoArgs,
        Read,
        r#"{"do":"browser.list_trash"}"#,
        "Deleted profiles still restorable, with the day each one expires.",
    ),
    action!(
        "restore_profile",
        PROFILES,
        IdArgs,
        Write,
        r#"{"do":"browser.restore_profile","id":"p1"}"#,
        "Bring a deleted profile back under its own id, with its cookies and logins.",
    ),
    action!(
        "purge_profile",
        PROFILES,
        IdArgs,
        Destructive,
        r#"{"do":"browser.purge_profile","id":"p1"}"#,
        "Delete a trashed profile for good. There is nothing after this.",
    ),
    action!(
        "export_cookies",
        PROFILES,
        IdArgs,
        Read,
        r#"{"do":"browser.export_cookies","id":"p1"}"#,
        "Export a profile's cookies (decrypted).",
    ),
    action!(
        "import_cookies",
        PROFILES,
        CookiesArgs,
        Destructive,
        r#"{"do":"browser.import_cookies","id":"p1","cookies":[{"name":"sid","value":"x","domain":"example.com","path":"/"}]}"#,
        "Import cookies into a STOPPED profile.",
    ),
    action!(
        "list_proxies",
        PROXIES,
        NoArgs,
        Read,
        r#"{"do":"browser.list_proxies"}"#,
        "List stored proxies (no credentials).",
    ),
    action!(
        "add_proxy",
        PROXIES,
        AddProxyArgs,
        Write,
        r#"{"do":"browser.add_proxy","proxy":"http://127.0.0.1:8080","name":"local"}"#,
        "Add a proxy to the store. Pass `proxy` as a string (scheme://user:pass@host:port) or explicit fields.",
    ),
    action!(
        "delete_proxy",
        PROXIES,
        IdArgs,
        Destructive,
        r#"{"do":"browser.delete_proxy","id":"x1"}"#,
        "Delete a stored proxy by id.",
    ),
    action!(
        "list_folders",
        LIBRARY,
        NoArgs,
        Read,
        r#"{"do":"browser.list_folders"}"#,
        "List folder tags.",
    ),
    action!(
        "rename_folder",
        LIBRARY,
        RenameFolderArgs,
        Write,
        r#"{"do":"browser.rename_folder","folder":"old","name":"new"}"#,
        "Rename a folder (retags its profiles).",
    ),
    action!(
        "delete_folder",
        LIBRARY,
        DeleteFolderArgs,
        Destructive,
        r#"{"do":"browser.delete_folder","folder":"old"}"#,
        "Delete a folder. delete_profiles=true removes its profiles; false unfiles them.",
    ),
    action!(
        "list_extensions",
        LIBRARY,
        NoArgs,
        Read,
        r#"{"do":"browser.list_extensions"}"#,
        "Extensions in the library, with ids to pass to create_profile / edit_profile.",
    ),
    action!(
        "add_extension",
        LIBRARY,
        AddExtensionArgs,
        Write,
        r#"{"do":"browser.add_extension","url":"https://chromewebstore.google.com/detail/x/abcdefghijklmnopabcdefghijklmnop"}"#,
        "Add an extension. `url` takes a Web Store page, a bare extension id, or a direct .crx/.zip link — the launcher downloads it. `path` takes a local file or unpacked folder.",
    ),
    action!(
        "delete_extension",
        LIBRARY,
        IdArgs,
        Destructive,
        r#"{"do":"browser.delete_extension","id":"e1"}"#,
        "Remove an extension from the library. Profiles that named it stop loading it on their next start.",
    ),
    action!(
        "list_bookmarks",
        LIBRARY,
        NoArgs,
        Read,
        r#"{"do":"browser.list_bookmarks"}"#,
        "Folder-scoped bookmarks pushed into profiles.",
    ),
    action!(
        "save_bookmark",
        LIBRARY,
        BookmarkArgs,
        Write,
        r#"{"do":"browser.save_bookmark","url":"https://example.com","title":"Example"}"#,
        "Add or update a bookmark. Bound to a folder it reaches every profile in it; folder '' means every profile. Applied on each profile's next launch.",
    ),
    action!(
        "delete_bookmark",
        LIBRARY,
        IdArgs,
        Destructive,
        r#"{"do":"browser.delete_bookmark","id":"b1"}"#,
        "Delete a bookmark; it leaves its profiles on their next launch.",
    ),
    action!(
        "list_tags",
        LIBRARY,
        NoArgs,
        Read,
        r#"{"do":"browser.list_tags"}"#,
        "Tags in their order (id, name, color) and by_profile: tag ids by profile id. list_profiles shows each profile's tag ids too.",
    ),
    action!(
        "save_tag",
        LIBRARY,
        TagArgs,
        Write,
        r#"{"do":"browser.save_tag","name":"pentest","color":"red"}"#,
        "Add a tag (no id) or rename/recolor one (id). Names are unique, case aside. color is one of blue, violet, magenta, red, orange, yellow, green, sky; a new tag without one takes the next.",
    ),
    action!(
        "delete_tag",
        LIBRARY,
        IdArgs,
        Destructive,
        r#"{"do":"browser.delete_tag","id":"t1"}"#,
        "Delete a tag; the profiles that carried it stay, without it.",
    ),
    action!(
        "set_profile_tags",
        LIBRARY,
        ProfileTagsArgs,
        Destructive,
        r#"{"do":"browser.set_profile_tags","id":"p1","tags":["pentest"]}"#,
        "Give a profile exactly these tags: ids or names from list_tags. [] clears. An unknown tag changes nothing; make it with save_tag first.",
    ),
    action!(
        "list_templates",
        LIBRARY,
        NoArgs,
        Read,
        r#"{"do":"browser.list_templates"}"#,
        "Profile templates: a profile's settings kept under a name, and where each new profile's fingerprint comes from.",
    ),
    action!(
        "save_template",
        LIBRARY,
        TemplateArgs,
        Write,
        r#"{"do":"browser.save_template","name":"windows desktop","profile_id":"p1"}"#,
        "Add or update a profile template. profile_id takes that profile's settings, folder, tags and fingerprint source; never its fingerprint, name, notes or cookies.",
    ),
    action!(
        "delete_template",
        LIBRARY,
        IdArgs,
        Destructive,
        r#"{"do":"browser.delete_template","id":"t1"}"#,
        "Delete a profile template; profiles made from it stay as they are.",
    ),
    action!(
        "create_profile_from_template",
        LIBRARY,
        FromTemplateArgs,
        Write,
        r#"{"do":"browser.create_profile_from_template","id":"t1","name":"shop test 3"}"#,
        "Create a profile from a template: its settings, and a fresh fingerprint of its own from the template's source.",
    ),
    action!(
        "list_automation_projects",
        AUTOMATION,
        NoArgs,
        Read,
        r#"{"do":"browser.list_automation_projects"}"#,
        "List automation projects with their blocks and run settings.",
    ),
    action!(
        "get_automation_project",
        AUTOMATION,
        IdArgs,
        Read,
        r#"{"do":"browser.get_automation_project","id":"a1"}"#,
        "Get one automation project by id.",
    ),
    action!(
        "create_automation_project",
        AUTOMATION,
        OptionalNameArgs,
        Write,
        r#"{"do":"browser.create_automation_project","name":"login flow"}"#,
        "Create an empty automation project. Add steps with save_automation_project.",
    ),
    action!(
        "save_automation_project",
        AUTOMATION,
        SaveProjectArgs,
        Destructive,
        r#"{"do":"browser.save_automation_project","id":"a1","project":{"name":"login flow","blocks":[]}}"#,
        "Replace a project whole — send it back the way get_automation_project returned it, with `blocks` and `run` edited. The id in the path wins.",
    ),
    action!(
        "delete_automation_project",
        AUTOMATION,
        IdArgs,
        Destructive,
        r#"{"do":"browser.delete_automation_project","id":"a1"}"#,
        "Delete an automation project. This one is not a trash — it is gone.",
    ),
    action!(
        "duplicate_automation_project",
        AUTOMATION,
        IdArgs,
        Write,
        r#"{"do":"browser.duplicate_automation_project","id":"a1"}"#,
        "Copy an automation project.",
    ),
    action!(
        "export_automation_project",
        AUTOMATION,
        IdArgs,
        Read,
        r#"{"do":"browser.export_automation_project","id":"a1"}"#,
        "Export a project as a bundle. Any module its steps call travels inside the bundle. Parameters the project marked secret come out empty, and `needs` says which ones.",
    ),
    action!(
        "import_automation_project",
        AUTOMATION,
        BundleArgs,
        Write,
        r#"{"do":"browser.import_automation_project","bundle":{"project":{"name":"login flow","blocks":[]}}}"#,
        "Import a project bundle; it arrives as a new project with a new id. Modules carried in the bundle are installed first, except where one is already installed under the same id — that one is kept.",
    ),
    action!(
        "run_automation_project",
        AUTOMATION,
        IdArgs,
        Write,
        r#"{"do":"browser.run_automation_project","id":"a1"}"#,
        "Start a project. Answers as soon as the run is under way — the browsers it needs come from its own profile blocks. Poll automation_status for progress.",
    ),
    action!(
        "stop_automation_project",
        AUTOMATION,
        IdArgs,
        Destructive,
        r#"{"do":"browser.stop_automation_project","id":"a1"}"#,
        "Ask a run to stop. Each browser finishes the step it is in and then closes, so the run does not end the instant this answers.",
    ),
    action!(
        "automation_status",
        AUTOMATION,
        IdArgs,
        Read,
        r#"{"do":"browser.automation_status","id":"a1"}"#,
        "How a run is going: each worker's pass, step and status, plus the tail of the log. Null when the project is not running.",
    ),
    action!(
        "list_automation_runs",
        AUTOMATION,
        NoArgs,
        Read,
        r#"{"do":"browser.list_automation_runs"}"#,
        "Every automation run going right now.",
    ),
    action!(
        "list_automation_modules",
        AUTOMATION,
        NoArgs,
        Read,
        r#"{"do":"browser.list_automation_modules"}"#,
        "List installed WebAssembly modules. Each contributes blocks under the kind `module:<module id>:<block>`.",
    ),
    action!(
        "install_automation_module",
        AUTOMATION,
        PathArgs,
        Write,
        r#"{"do":"browser.install_automation_module","path":"/tmp/module.wasm"}"#,
        "Install a .wasm module from a path on this machine.",
    ),
    action!(
        "remove_automation_module",
        AUTOMATION,
        IdArgs,
        Destructive,
        r#"{"do":"browser.remove_automation_module","id":"m1"}"#,
        "Remove a module. Projects using its blocks stop working; nothing rewrites them.",
    ),
    action!(
        "page",
        PAGE,
        PageArgs,
        Write,
        r#"{"do":"browser.page","profile_id":"p1","cmd":"snapshot -i"}"#,
        "Run agent-browser commands on the profile's browser, started when it is not running (headless applies to that start): cmd is one command line such as \"open https://example.com\", \"snapshot -i\", \"click @e3\" or \"fill @e2 'text'\"; cmds runs several in order, stopping at the first failure unless continue_on_error is true. Snapshot refs (@eN) work in later commands and in the selector of human/touch actions. Commands do not auto-wait: use \"wait <sel>\". guide {\"topic\":\"browser.page\"} lists the commands and what replaces each old browser_* tool.",
    ),
    action!(
        "human_move",
        HUMAN,
        PointArgs,
        Write,
        r#"{"do":"browser.human_move","profile_id":"p1","selector":"@e3"}"#,
        "Move the pointer to an element (or a point) along a human trajectory. Give either selector or x+y.",
    ),
    action!(
        "human_click",
        HUMAN,
        HumanClickArgs,
        Write,
        r#"{"do":"browser.human_click","profile_id":"p1","selector":"@e3"}"#,
        "Move to an element (or a point) and click it the way a person does. Give either selector or x+y.",
    ),
    action!(
        "human_type",
        HUMAN,
        HumanTypeArgs,
        Write,
        r#"{"do":"browser.human_type","profile_id":"p1","text":"hello"}"#,
        "Type text into whatever currently has focus, key by key with human timing. Use human_fill to focus a field first.",
    ),
    action!(
        "human_fill",
        HUMAN,
        HumanFillArgs,
        Write,
        r##"{"do":"browser.human_fill","profile_id":"p1","selector":"#email","text":"a@example.com","clear":true}"##,
        "Click a field and type into it, both humanly. The one to reach for on a form.",
    ),
    action!(
        "human_release_pointer",
        HUMAN,
        ProfileArgs,
        Write,
        r#"{"do":"browser.human_release_pointer","profile_id":"p1"}"#,
        "Drop this profile's pointer. Rarely needed — the next human_* call makes a new one.",
    ),
    action!(
        "touch_tap",
        TOUCH,
        TouchTapArgs,
        Write,
        r#"{"do":"browser.touch_tap","profile_id":"p1","selector":"@e3"}"#,
        "Tap an element (or a point) with a finger. Phone profiles only. Give either selector or x+y.",
    ),
    action!(
        "touch_long_press",
        TOUCH,
        TouchLongPressArgs,
        Write,
        r#"{"do":"browser.touch_long_press","profile_id":"p1","selector":"@e3"}"#,
        "Press and hold — the gesture that opens a context menu on a phone. Phone profiles only.",
    ),
    action!(
        "touch_swipe",
        TOUCH,
        TouchSwipeArgs,
        Write,
        r#"{"do":"browser.touch_swipe","profile_id":"p1","dy":-400}"#,
        "Swipe a finger across the glass — the way a phone scrolls. Start at a selector or x+y (default: the middle of the viewport), then give either dx+dy or to_x+to_y. Phone profiles only. An end outside the viewport is kept at its edge (the result's note says so).",
    ),
    action!(
        "touch_drag",
        TOUCH,
        TouchDragArgs,
        Write,
        r#"{"do":"browser.touch_drag","profile_id":"p1","selector":"@e3","to_selector":"@e7"}"#,
        "Press, wait for the item to be picked up, carry it and set it down — a list reorder, a card moved between columns. Different from touch_swipe in the wait, which is what makes it a drag and not a scroll. Phone profiles only. Give the end as to_selector, to_x+to_y, or dx+dy (an offset from the start); an end outside the viewport is kept at its edge.",
    ),
    action!(
        "touch_pinch",
        TOUCH,
        TouchPinchArgs,
        Write,
        r#"{"do":"browser.touch_pinch","profile_id":"p1","scale":2}"#,
        "Two fingers converging on or spreading from a point. Above 1 zooms in, below 1 zooms out. Phone profiles only.",
    ),
    action!(
        "rotate_screen",
        TOUCH,
        RotateArgs,
        Write,
        r#"{"do":"browser.rotate_screen","profile_id":"p1","angle":90}"#,
        "Turn the handset. The sensors move first and the picture commits at the end, which is the order a real phone produces. Answers when the new angle has reached the page, so screen.width read straight afterwards is already the turned one. Phone profiles only.",
    ),
    action!(
        "script",
        SCRIPT,
        ScriptArgs,
        Destructive,
        r#"{"do":"browser.script","profile_id":"p1","js":"return await page.title()"}"#,
        "Run one of: js, a Playwright JavaScript body run as an async function of (browser, context, page, playwright, args) against the profile's browser over CDP, its return value (JSON) the result; saved_js, a script saved with save_as; blocks, a ShardBrowser automation block list the launcher runs (guide {\"topic\":\"browser.blocks\"}); project, a saved automation project by id or name. save_as keeps js as <target>/.raijin/scripts/<name>.js when it succeeds, or blocks as an automation project of that name. profile_id: the profile to run on (started when needed; headless applies to that start). timeout_ms defaults to 120000. Routes and listeners set in a script last only while it runs. Needs the Playwright driver for js (playwright-rs install).",
    ),
    action!(
        "list_scripts",
        SCRIPT,
        NoArgs,
        Read,
        r#"{"do":"browser.list_scripts"}"#,
        "Saved Playwright scripts of this target (.raijin/scripts): name, size, and the first line when it is a // comment.",
    ),
    action!(
        "delete_script",
        SCRIPT,
        ScriptNameArgs,
        Destructive,
        r#"{"do":"browser.delete_script","name":"title"}"#,
        "Delete a saved Playwright script of this target.",
    ),
];

/// The listing action: names every action by group.
const LIST_ACTION: &str = "actions";

fn action(name: &str) -> Option<&'static Action> {
    ACTIONS.iter().find(|a| a.name == name)
}

/// Action name normal form: trimmed, lowercase, `-` as `_`.
fn norm(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace('-', "_")
}

/// `name` without a `browser.` prefix (any case), when it has one.
fn strip_browser(name: &str) -> Option<&str> {
    let name = name.trim();
    let head = name.get(..8)?;
    head.eq_ignore_ascii_case("browser.").then(|| &name[8..])
}

/// Whether `name` (any case) is `browser.<action>` for an action or `browser.actions`.
pub fn names_action(name: &str) -> bool {
    strip_browser(name).is_some_and(|rest| {
        let rest = norm(rest);
        rest == LIST_ACTION || action(&rest).is_some()
    })
}

/// Whether the schema of `browser.<action>` declares `key`.
pub fn declares(name: &str, key: &str) -> bool {
    strip_browser(name)
        .and_then(|rest| action(&norm(rest)))
        .is_some_and(|a| {
            (a.schema)()
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|p| p.contains_key(key))
        })
}

/// Whether `topic` is `browser` or `browser.<something>`.
pub fn is_topic(topic: &str) -> bool {
    let t = topic.trim();
    t.eq_ignore_ascii_case("browser") || strip_browser(t).is_some()
}

/// The guide text for `browser`, `browser.page`, `browser.blocks` or `browser.<action>`.
pub fn topic(topic: &str) -> CallToolResult {
    let Some(rest) = strip_browser(topic).map(norm) else {
        return text_result(format!("{}\n\n{}", guide::BROWSER_GUIDE, listing()));
    };
    if rest == LIST_ACTION || rest.is_empty() {
        return text_result(format!("{}\n\n{}", guide::BROWSER_GUIDE, listing()));
    }
    if rest == "blocks" {
        return text_result(guide::BLOCKS_GUIDE);
    }
    let Some(found) = action(&rest) else {
        let mut names: Vec<&str> = ACTIONS.iter().map(|a| a.name).collect();
        names.push("blocks");
        let near = crate::util::suggest(&rest, names, 3)
            .into_iter()
            .map(|n| format!("browser.{n}"))
            .collect();
        return ToolError::new(
            Code::UnknownTopic,
            format!("no browser topic \"{}\"", topic.trim()),
        )
        .did_you_mean(near)
        .see(error::guide_call(Some("browser")))
        .into_result();
    };
    let view = action_view(found);
    if found.name == "page" {
        return text_result(format!(
            "{}\n\n{}\n\nParameters: {view}",
            guide::PAGE_GUIDE,
            guide::legacy_table()
        ));
    }
    json_result(&view)
}

fn action_view(a: &Action) -> Value {
    json!({
        "action": format!("browser.{}", a.name),
        "description": a.description,
        "inputSchema": Value::Object((a.schema)()),
        "example": a.example(),
    })
}

/// Every action by group, one line per group.
fn listing() -> String {
    let mut lines = vec![
        "Actions (browser {\"do\":\"<action>\", ...}; guide {\"topic\":\"browser.<action>\"} gives one's parameters):"
            .to_owned(),
    ];
    for group in GROUPS {
        let names: Vec<&str> = ACTIONS
            .iter()
            .filter(|a| a.group == group)
            .map(|a| a.name)
            .collect();
        lines.push(format!("{group}: {}", names.join(", ")));
    }
    lines.join("\n")
}

/// The gateway overview's line for the browser tool.
pub fn overview_line() -> String {
    "browser — ShardBrowser profiles and their browser: launcher API, page commands (agent-browser engine), human/touch input, Playwright and automation scripts: browser {\"do\":\"browser.actions\"} or guide {\"topic\":\"browser\"}".to_owned()
}

fn json_result(value: &Value) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(value.to_string())])
}

fn text_result(message: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(message.into())])
}

/// An error result: `error`'s envelope with `extra` fields added.
fn error_with(error: &ToolError, extra: Value) -> CallToolResult {
    let mut value = error.to_value();
    if let (Some(object), Value::Object(extra)) = (value.as_object_mut(), extra) {
        object.extend(extra);
    }
    CallToolResult::error(vec![ContentBlock::text(value.to_string())])
}

/// One action call being run: its arguments until they are read, and the notes for the result.
struct Call<'a> {
    action: &'static Action,
    arguments: Option<JsonObject>,
    ctx: Ctx<'a>,
    notes: Vec<String>,
}

impl Call<'_> {
    /// The arguments read as `T` (once); what reading changed goes to the notes.
    fn args<T: DeserializeOwned + JsonSchema>(&mut self) -> Result<T, ToolError> {
        let (args, notes) = parse_args::<T>(
            &format!("browser.{}", self.action.name),
            self.arguments.take(),
            &self.action.example(),
            self.action.destructive(),
        )?;
        self.notes.extend(notes);
        Ok(args)
    }
}

impl Hub {
    /// The launcher `settings` (`[browser]` of raijin.toml) and the environment point at.
    pub fn new(settings: &crate::config::Browser) -> Self {
        Self {
            launcher: launcher::Launcher::new(settings),
            sessions: Mutex::default(),
            flags: OnceLock::new(),
        }
    }

    fn flags(&self) -> Result<&Flags, ToolError> {
        self.flags
            .get_or_init(|| agent_browser::flags::try_parse_flags(&[]))
            .as_ref()
            .map_err(|e| {
                ToolError::new(
                    Code::ConfigError,
                    format!("agent-browser configuration: {e}"),
                )
            })
    }

    /// Runs browser action `name` (without `browser.`) with `arguments`.
    pub async fn call(
        &self,
        name: &str,
        arguments: Option<JsonObject>,
        ctx: Ctx<'_>,
    ) -> CallToolResult {
        let name = norm(name);
        if name == LIST_ACTION {
            return text_result(listing());
        }
        if let Some((old, replacement)) = guide::LEGACY.iter().find(|(old, _)| *old == name) {
            return ToolError::new(
                Code::UnknownTool,
                format!("{old} has no action of its own here: use {replacement}"),
            )
            .see(error::guide_call(Some("browser.page")))
            .into_result();
        }
        let Some(action) = action(&name) else {
            let near = crate::util::suggest(&name, ACTIONS.iter().map(|a| a.name), 3)
                .into_iter()
                .map(|n| format!("browser.{n}"))
                .collect();
            return ToolError::new(
                Code::UnknownTool,
                format!("unknown browser action \"{name}\""),
            )
            .did_you_mean(near)
            .see(error::guide_call(Some("browser")))
            .into_result();
        };
        let mut call = Call {
            action,
            arguments,
            ctx,
            notes: Vec::new(),
        };
        let result = match action.group {
            PAGE => self.page(&mut call).await,
            HUMAN | TOUCH => self.motion(&mut call).await,
            SCRIPT => self.script(&mut call).await,
            _ => self.launcher_action(&mut call).await,
        };
        let result = result.unwrap_or_else(ToolError::into_result);
        error::with_notes(result, &call.notes)
    }
}

/// Whether `call` (a `browser` call with `do`) fits the parameters of browser action `name`.
#[cfg(test)]
pub(crate) fn call_fits(name: &str, call: &JsonObject) -> Result<(), ToolError> {
    let mut args = call.clone();
    args.remove("do");
    let name = norm(name);
    if name == LIST_ACTION {
        return if args.is_empty() {
            Ok(())
        } else {
            Err(ToolError::new(
                Code::UnknownParameter,
                "browser.actions takes no parameters",
            ))
        };
    }
    let found = action(&name)
        .ok_or_else(|| ToolError::new(Code::UnknownTool, format!("no browser action {name}")))?;
    (found.check)(
        &format!("browser.{name}"),
        (!args.is_empty()).then_some(args),
        &found.example(),
        found.destructive(),
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(value: &Value) -> JsonObject {
        value.as_object().cloned().expect("object")
    }

    #[test]
    fn every_action_example_fits_its_parameters() {
        for a in ACTIONS {
            let call = object(&a.example());
            assert_eq!(
                call["do"].as_str(),
                Some(format!("browser.{}", a.name).as_str()),
                "{}: example names another action",
                a.name
            );
            call_fits(a.name, &call).unwrap_or_else(|e| panic!("{}: {}", a.name, e.error));
        }
        assert!(GROUPS.iter().all(|g| ACTIONS.iter().any(|a| a.group == *g)));
    }

    #[test]
    fn legacy_names_are_never_actions() {
        for (old, replacement) in guide::LEGACY {
            assert!(old.starts_with("browser_"), "{old}");
            assert!(!replacement.is_empty(), "{old}");
        }
        assert!(ACTIONS.iter().all(|a| !a.name.starts_with("browser_")));
    }

    #[test]
    fn page_results_are_shaped_for_tokens() {
        let snapshot = json!({"snapshot": "- button [ref=e1]", "refs": {"e1": {}}, "origin": "x"});
        assert_eq!(page::shape(&snapshot), "- button [ref=e1]");
        assert_eq!(
            page::shape(&json!({"url": "https://a", "origin": "x", "lifecycle": {"reused": true}})),
            "https://a"
        );
        assert_eq!(
            page::shape(&json!({"x": 1, "y": 2, "width": 3, "height": 4})),
            r#"{"x":1,"y":2,"width":3,"height":4}"#
        );
        assert_eq!(page::shape(&Value::Null), "ok");
    }

    #[test]
    fn blocks_get_ids_and_the_profile_first() {
        let blocks = script::prepare_blocks(
            vec![json!({"kind": "goto", "params": {"url": "u"}})],
            Some("p1"),
        )
        .expect("blocks");
        assert_eq!(blocks[0]["id"], "raijin-profile");
        assert_eq!(blocks[0]["kind"], "profile.use");
        assert_eq!(blocks[0]["params"], json!({"id": "p1"}));
        assert_eq!(blocks[1]["id"], "s1");
        let err = script::prepare_blocks(vec![json!({"params": {}})], None).expect_err("no kind");
        assert_eq!(err.code, Code::InvalidArguments);
    }

    #[test]
    fn eval_lines_keep_their_javascript() {
        let js = |line: &str| page::eval_script(line);
        let some = |s: &str| Some(s.to_owned());
        assert_eq!(
            js("eval localStorage.setItem('k','v')"),
            some("localStorage.setItem('k','v')")
        );
        assert_eq!(js("eval 'abc'.length"), some("'abc'.length"));
        assert_eq!(
            js("eval document.querySelectorAll('p').length"),
            some("document.querySelectorAll('p').length")
        );
        assert_eq!(js(r#"eval "document.title""#), some("document.title"));
        assert_eq!(js(r#"eval "a"+"b""#), some(r#""a"+"b""#));
        assert_eq!(js(r#"eval "say \"hi\"""#), some(r#"say "hi""#));
        assert_eq!(js("agent-browser eval 1+1"), some("1+1"));
        assert_eq!(js("EVAL 1"), some("1"));
        assert_eq!(js("eval"), None);
        assert_eq!(js("evaluate x"), None);
    }

    #[test]
    fn network_requests_are_one_line_each() {
        let data = json!({"requests": [
            {"requestId": "1.1", "method": "GET", "status": 301, "resourceType": "Document", "url": "https://a/"},
            {"requestId": "1.1", "method": "GET", "resourceType": "Fetch", "url": "https://a/x"},
        ]});
        let text = page::summarize_requests(data);
        let lines: Vec<&str> = text.as_str().expect("text").lines().collect();
        assert_eq!(lines.len(), 3, "{text}");
        assert!(lines[0].starts_with("2 requests "), "{}", lines[0]);
        assert_eq!(lines[1], "1.1 GET 301 Document https://a/");
        assert_eq!(lines[2], "1.1 GET - Fetch https://a/x");
        assert_eq!(
            page::summarize_requests(json!({"requests": []})),
            json!("0 requests")
        );
        assert_eq!(
            page::summarize_requests(json!({"cleared": true})),
            json!({"cleared": true})
        );
    }

    #[test]
    fn swipe_ends_stay_in_the_viewport() {
        assert_eq!(
            motion::clamp_into(480.0, -227.0, (960.0, 345.0)),
            (480.0, 0.0, true)
        );
        assert_eq!(
            motion::clamp_into(2000.0, 400.0, (960.0, 345.0)),
            (959.0, 344.0, true)
        );
        assert_eq!(
            motion::clamp_into(10.0, 10.0, (960.0, 345.0)),
            (10.0, 10.0, false)
        );
    }

    #[test]
    fn string_script_args_become_json() {
        let mut notes = Vec::new();
        let args = script::script_args(Some(json!("{\"hello\": \"world\"}")), &mut notes);
        assert_eq!(args, json!({"hello": "world"}));
        assert_eq!(notes, ["coerced 'args' from string to object"]);
        let mut notes = Vec::new();
        assert_eq!(
            script::script_args(Some(json!("plain")), &mut notes),
            json!("plain")
        );
        assert_eq!(
            script::script_args(Some(json!("42")), &mut notes),
            json!("42")
        );
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(script::script_args(None, &mut notes), Value::Null);
    }

    #[test]
    fn block_waits_longer_than_the_call_are_refused() {
        let call = std::time::Duration::from_secs(120);
        let goto = json!({"kind": "goto", "params": {"url": "u"}});
        let err = script::check_block_waits(
            &[
                goto.clone(),
                json!({"kind": "waitLoad", "params": {"timeout": 15000}}),
            ],
            call,
            "blocks",
        )
        .expect_err("15000 s");
        assert_eq!(err.code, Code::InvalidArguments);
        assert!(
            err.error
                .starts_with("blocks[1] (waitLoad) timeout is 15000 s"),
            "{}",
            err.error
        );
        let fine = [goto, json!({"kind": "waitLoad", "params": {"timeout": 10}})];
        assert!(script::check_block_waits(&fine, call, "blocks").is_ok());
        let variable = [json!({"kind": "wait", "params": {"seconds": "{{x}}"}})];
        assert!(script::check_block_waits(&variable, call, "blocks").is_ok());
    }

    #[test]
    fn screenshots_without_a_path_stay_with_the_target() {
        let mut flags = agent_browser::flags::try_parse_flags(&[]).expect("flags");
        flags.screenshot_dir = None;
        let parse = |line: &str| {
            let argv = agent_browser::commands::shell_words_split(line);
            agent_browser::commands::parse_command(&argv, &flags).expect(line)
        };
        let dir = std::path::Path::new("/t/.raijin/screenshots");
        for line in ["screenshot", "screenshot --full", "screenshot #hero"] {
            let mut cmd = parse(line);
            assert_eq!(
                page::place_screenshot(&mut cmd, Some(dir)).as_deref(),
                Some(dir),
                "{line}"
            );
            assert_eq!(cmd["screenshotDir"], "/t/.raijin/screenshots", "{line}");
        }
        for line in [
            "screenshot /tmp/x.png",
            "screenshot #hero /tmp/x.png",
            "get url",
        ] {
            let mut cmd = parse(line);
            let before = cmd.clone();
            assert_eq!(page::place_screenshot(&mut cmd, Some(dir)), None, "{line}");
            assert_eq!(cmd, before, "{line}");
        }
        let mut own = json!({"action": "screenshot", "path": null, "screenshotDir": "/mine"});
        assert_eq!(page::place_screenshot(&mut own, Some(dir)), None);
        assert_eq!(own["screenshotDir"], "/mine");
        let mut cmd = parse("screenshot");
        assert_eq!(page::place_screenshot(&mut cmd, None), None);
    }
}
