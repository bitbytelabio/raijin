//! Page sessions (one agent-browser `DaemonState` attached to each profile's browser) and the
//! `page` action that runs agent-browser command lines on them.

use std::fmt::Write as _;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use agent_browser::commands::{parse_command, shell_words_split};
use agent_browser::native::actions::{DaemonState, execute_command};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::sync::{Mutex, OwnedMutexGuard};

use super::{Call, Hub, error_with, text_result};
use crate::config::{Target, user_state_dir};
use crate::mcp::error::{Code, ToolError};

/// One profile's attached engine and what the Motion actions keep for it.
pub struct Session {
    pub state: DaemonState,
    /// The page session the Motion pointer was created on.
    pub pointer_on: Option<String>,
    /// Whether the page claims a touchscreen, once asked.
    pub touch: Option<bool>,
}

/// An element's box in viewport CSS pixels.
#[derive(Debug, Clone, Copy)]
pub struct Rect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// A page session with the browser endpoint it is attached to.
pub struct Entry {
    ws_url: String,
    session: Arc<Mutex<Session>>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PageArgs {
    pub profile_id: String,
    /// One agent-browser command line, e.g. "snapshot -i" or "click @e3".
    pub cmd: Option<String>,
    /// Several command lines, run in order.
    pub cmds: Option<Vec<String>>,
    /// cmds: run the lines after a failed one too (default false: stop at the first failure).
    /// Not `bail`, which `run` reads as its own batch flag.
    pub continue_on_error: Option<bool>,
    /// Start the profile without a window when it is not running.
    pub headless: Option<bool>,
}

/// A page command line ready to run.
struct Prepared {
    cmd: Value,
    /// `network requests --full`: keep every field.
    full: bool,
    /// The directory a `screenshot` without a path is saved to, made owner-only before it runs.
    shots: Option<PathBuf>,
}

/// Where a `screenshot` without a path goes: `<target>/.raijin/screenshots`, else
/// `~/.raijin/screenshots`; `None` without a home, leaving the engine's own default.
fn screenshot_dir(target: Option<&Target>) -> Option<PathBuf> {
    match target {
        Some(t) => Some(t.state_dir().join("screenshots")),
        None => user_state_dir().ok().map(|d| d.join("screenshots")),
    }
}

/// Points a parsed `screenshot` without a path at `dir` (the engine would save it under
/// `~/.agent-browser`); the directory to create, or `None` when the command is left as it is
/// (another action, a path given, or `AGENT_BROWSER_SCREENSHOT_DIR` already set).
pub fn place_screenshot(cmd: &mut Value, dir: Option<&Path>) -> Option<PathBuf> {
    let dir = dir?;
    let bare = cmd.get("action").and_then(Value::as_str) == Some("screenshot")
        && cmd.get("path").is_none_or(Value::is_null)
        && cmd.get("screenshotDir").is_none_or(Value::is_null);
    if !bare {
        return None;
    }
    cmd["screenshotDir"] = json!(dir.to_string_lossy());
    Some(dir.to_path_buf())
}

/// First words agent-browser has that manage something raijin owns, with why they are refused.
const REFUSED: &[(&[&str], &str)] = &[
    (
        &["connect", "close", "quit", "exit"],
        "start_profile/stop_profile manage the browser",
    ),
    (
        &[
            "session",
            "install",
            "upgrade",
            "doctor",
            "dashboard",
            "stream",
            // Opens a local browser that would inherit this server's stdio (the MCP stream).
            "inspect",
            "mcp",
            "chat",
            "skills",
            "plugin",
            "plugins",
            "profiles",
            "batch",
            "--session",
        ],
        "not available inside raijin",
    ),
];

/// A command result in few tokens: a snapshot's tree as text (its refs are in the tree), a lone
/// string field as itself, anything else as compact JSON without `origin`, `id` and the
/// session's `lifecycle` report.
pub fn shape(data: &Value) -> String {
    match data {
        Value::Null => "ok".to_owned(),
        Value::String(s) => s.clone(),
        Value::Object(object) => {
            if let Some(Value::String(tree)) = object.get("snapshot") {
                let mut out = tree.clone();
                if let Some(Value::String(warning)) = object.get("warning") {
                    out.push('\n');
                    out.push_str(warning);
                }
                return out;
            }
            let rest: Map<String, Value> = object
                .iter()
                .filter(|(k, _)| !matches!(k.as_str(), "origin" | "id" | "lifecycle"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if rest.len() == 1
                && let Some(Value::String(s)) = rest.values().next()
            {
                return s.clone();
            }
            Value::Object(rest).to_string()
        }
        other => other.to_string(),
    }
}

/// Runs a parsed agent-browser command; `data` on success.
async fn run_parsed(state: &mut DaemonState, cmd: &Value) -> Result<Value, ToolError> {
    // The engine's command future is large and deeply nested: boxed, it stays off the caller's
    // stack, and as a `dyn` its `Send` is proven here rather than again for every caller.
    let command: Pin<Box<dyn Future<Output = Value> + Send + '_>> =
        Box::pin(execute_command(cmd, state));
    let response = command.await;
    if response.get("success").and_then(Value::as_bool) == Some(true) {
        return Ok(response.get("data").cloned().unwrap_or(Value::Null));
    }
    let mut message = format!(
        "agent-browser: {}",
        response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("the command failed")
    );
    if let Some(code) = response.get("code").and_then(Value::as_str) {
        message.push_str(" (");
        message.push_str(code);
        message.push(')');
    }
    Err(ToolError::new(Code::ToolFailed, message))
}

impl Hub {
    /// The profile's page session, starting the profile (`headless`) when it is not running and
    /// attaching anew when its browser endpoint changed.
    pub(super) async fn session(
        &self,
        profile_id: &str,
        headless: bool,
    ) -> Result<Arc<Mutex<Session>>, ToolError> {
        let cdp = self.launcher.cdp(profile_id, headless).await?;
        {
            let sessions = self.sessions.lock().await;
            if let Some(entry) = sessions.get(profile_id)
                && entry.ws_url == cdp.ws_url
            {
                return Ok(Arc::clone(&entry.session));
            }
        }
        // Boxed: the engine state is large and lives across awaits here.
        let mut attached = Box::new(DaemonState::new());
        let argv = vec!["connect".to_owned(), cdp.ws_url.clone()];
        self.exec(&mut attached, &argv).await.map_err(|e| {
            ToolError::new(
                Code::ToolFailed,
                format!(
                    "agent-browser could not attach to profile {profile_id}: {}",
                    e.error
                ),
            )
        })?;
        // Without a stream server the engine turns capture on only at the first `network
        // requests`; everything loaded before that would be lost.
        let capture = ["network".to_owned(), "requests".to_owned()];
        if let Err(e) = self.exec(&mut attached, &capture).await {
            self.detach(&mut attached).await;
            return Err(ToolError::new(
                Code::ToolFailed,
                format!(
                    "agent-browser could not start network capture on profile {profile_id}: {}",
                    e.error
                ),
            ));
        }
        let fresh = Arc::new(Mutex::new(Session {
            state: *attached,
            pointer_on: None,
            touch: None,
        }));
        // Another call may have attached meanwhile: keep its session and detach this one. A
        // session of an older endpoint is replaced and detached. Detaching waits for the session,
        // so it happens after the map is unlocked.
        let (session, unused) = {
            let mut sessions = self.sessions.lock().await;
            match sessions.get(profile_id) {
                Some(entry) if entry.ws_url == cdp.ws_url => {
                    (Arc::clone(&entry.session), Some(fresh))
                }
                _ => {
                    let replaced = sessions.insert(
                        profile_id.to_owned(),
                        Entry {
                            ws_url: cdp.ws_url,
                            session: Arc::clone(&fresh),
                        },
                    );
                    (fresh, replaced.map(|e| e.session))
                }
            }
        };
        if let Some(unused) = unused {
            self.detach(&mut unused.lock().await.state).await;
        }
        Ok(session)
    }

    /// Disconnects `state` from its browser without closing the browser.
    async fn detach(&self, state: &mut DaemonState) {
        let _ = self.exec(state, &["close".to_owned()]).await;
    }

    /// The page session of `profile_id` when one is attached; never starts anything.
    pub(super) async fn existing_session(&self, profile_id: &str) -> Option<Arc<Mutex<Session>>> {
        self.sessions
            .lock()
            .await
            .get(profile_id)
            .map(|e| Arc::clone(&e.session))
    }

    /// Detaches from the profile's browser (without closing it) and forgets the session.
    pub(super) async fn drop_session(&self, profile_id: &str) {
        let Some(entry) = self.sessions.lock().await.remove(profile_id) else {
            return;
        };
        let mut session = entry.session.lock().await;
        self.detach(&mut session.state).await;
    }

    /// Parses and runs one agent-browser command line (already split into words).
    pub(super) async fn exec(
        &self,
        state: &mut DaemonState,
        argv: &[String],
    ) -> Result<Value, ToolError> {
        let cmd = parse_command(argv, self.flags()?)
            .map_err(|e| ToolError::new(Code::InvalidArguments, e.format()))?;
        run_parsed(state, &cmd).await
    }

    /// `js` evaluated in the active page; its `result`.
    pub(super) async fn eval(&self, state: &mut DaemonState, js: &str) -> Result<Value, ToolError> {
        let argv = ["eval".to_owned(), "-b".to_owned(), STANDARD.encode(js)];
        let data = self.exec(state, &argv).await?;
        Ok(data.get("result").cloned().unwrap_or(Value::Null))
    }

    /// The box of `selector` (CSS, xpath= or @ref) once it is visible and scrolled into view.
    pub(super) async fn bbox(
        &self,
        state: &mut DaemonState,
        selector: &str,
    ) -> Result<Rect, ToolError> {
        let sel = selector.to_owned();
        let words = |w: &[&str]| -> Vec<String> { w.iter().map(|s| (*s).to_owned()).collect() };
        // `wait` takes CSS only; a snapshot ref names an element that already exists.
        if !sel.starts_with('@') {
            self.exec(
                state,
                &words(&["wait", &sel, "--state", "visible", "--timeout", "15000"]),
            )
            .await?;
        }
        self.exec(state, &words(&["scrollintoview", &sel])).await?;
        let found = self.exec(state, &words(&["get", "box", &sel])).await?;
        let field = |k: &str| found.get(k).and_then(Value::as_f64);
        match (field("x"), field("y"), field("width"), field("height")) {
            (Some(x), Some(y), Some(width), Some(height)) => Ok(Rect {
                x,
                y,
                width,
                height,
            }),
            _ => Err(ToolError::new(
                Code::ToolFailed,
                format!("element is not rendered, so it has no coordinates: {selector}"),
            )),
        }
    }

    /// `page`: one command line or several, on the profile's page session.
    pub(super) async fn page(&self, call: &mut Call<'_>) -> Result<CallToolResult, ToolError> {
        let args: PageArgs = call.args()?;
        let (lines, many) = match (args.cmd, args.cmds) {
            (Some(_), Some(_)) => {
                return Err(ToolError::new(
                    Code::InvalidArguments,
                    "browser.page takes cmd (one line) or cmds (several), not both",
                )
                .param("cmds")
                .example(call.action.example()));
            }
            (Some(line), None) => (vec![line], false),
            (None, Some(lines)) => (lines, true),
            (None, None) => {
                return Err(ToolError::new(
                    Code::MissingParameter,
                    "browser.page needs 'cmd', an agent-browser command line such as \"snapshot -i\"",
                )
                .param("cmd")
                .example(call.action.example()));
            }
        };
        // Every line is checked before the browser starts: a typo never starts a profile.
        let shots = screenshot_dir(call.ctx.target);
        let prepared: Vec<Result<Prepared, ToolError>> = lines
            .iter()
            .map(|l| self.prepare_line(l, shots.as_deref(), &mut call.notes))
            .collect();
        let headless = args.headless.unwrap_or(false);
        if !many {
            let p = prepared.into_iter().next().expect("one line")?;
            let session = self.session(&args.profile_id, headless).await?;
            let mut session = session.lock().await;
            let data = run_line(&mut session.state, &p).await?;
            return Ok(text_result(shape(&data)));
        }
        let bail = !args.continue_on_error.unwrap_or(false);
        if bail && let Some((i, Err(e))) = prepared.iter().enumerate().find(|(_, p)| p.is_err()) {
            return Ok(error_with(e, json!({"step": i + 1, "done": ""})));
        }
        // Opened at the first runnable line: lines that all failed to parse start nothing.
        let mut session: Option<OwnedMutexGuard<Session>> = None;
        let mut done: Vec<String> = Vec::new();
        for (i, (line, p)) in lines.iter().zip(&prepared).enumerate() {
            let ran = match p {
                Ok(p) => {
                    let s = match &mut session {
                        Some(s) => s,
                        None => session.insert(
                            self.session(&args.profile_id, headless)
                                .await?
                                .lock_owned()
                                .await,
                        ),
                    };
                    run_line(&mut s.state, p).await
                }
                Err(e) => Err(e.clone()),
            };
            let shown = match ran {
                Ok(data) => shape(&data),
                Err(e) if bail => {
                    return Ok(error_with(
                        &e,
                        json!({"step": i + 1, "done": done.join("\n\n")}),
                    ));
                }
                Err(e) => format!("error: {}", e.error),
            };
            done.push(format!("> {line}\n{shown}"));
        }
        Ok(CallToolResult::success(vec![ContentBlock::text(
            done.join("\n\n"),
        )]))
    }

    /// One command line, split, checked against what raijin manages itself and parsed; nothing
    /// runs yet.
    fn prepare_line(
        &self,
        line: &str,
        shots: Option<&Path>,
        notes: &mut Vec<String>,
    ) -> Result<Prepared, ToolError> {
        let mut argv = shell_words_split(line);
        if argv.first().is_some_and(|w| w == "agent-browser") {
            argv.remove(0);
            let note = "dropped the leading 'agent-browser'".to_owned();
            if !notes.contains(&note) {
                notes.push(note);
            }
        }
        let Some(first) = argv.first().map(|w| w.to_ascii_lowercase()) else {
            return Err(ToolError::new(
                Code::InvalidArguments,
                "an empty command line; give one such as \"snapshot -i\"",
            )
            .param("cmd"));
        };
        if let Some((_, why)) = REFUSED
            .iter()
            .find(|(words, _)| words.contains(&first.as_str()))
        {
            return Err(
                ToolError::new(Code::InvalidArguments, format!("'{first}': {why}")).param("cmd"),
            );
        }
        // Shell splitting eats the quotes of the JavaScript; the line after `eval` is the script.
        if first == "eval"
            && !argv
                .get(1)
                .is_some_and(|w| matches!(w.as_str(), "-b" | "--base64" | "--stdin"))
            && let Some(js) = eval_script(line)
        {
            argv = vec!["eval".to_owned(), "-b".to_owned(), STANDARD.encode(js)];
        }
        // agent-browser would read it from this server's stdin, which carries the MCP stream.
        if argv.iter().any(|w| w == "--stdin") {
            return Err(ToolError::new(
                Code::InvalidArguments,
                "--stdin is not available inside raijin: put the script inline, or base64 it with -b",
            )
            .param("cmd"));
        }
        // raijin's own flag: the engine does not know it.
        let mut full = false;
        if argv.len() >= 2 && argv[0].eq_ignore_ascii_case("network") && argv[1] == "requests" {
            let before = argv.len();
            argv.retain(|w| w != "--full");
            full = argv.len() != before;
        }
        let mut cmd = parse_command(&argv, self.flags()?)
            .map_err(|e| ToolError::new(Code::InvalidArguments, e.format()).param("cmd"))?;
        if let Some(action) = cmd
            .get("action")
            .and_then(Value::as_str)
            .filter(|a| matches!(*a, "launch" | "close"))
        {
            return Err(ToolError::new(
                Code::InvalidArguments,
                format!(
                    "'{first}' would {action} the browser: start_profile/stop_profile manage it"
                ),
            )
            .param("cmd"));
        }
        let shots = place_screenshot(&mut cmd, shots);
        Ok(Prepared { cmd, full, shots })
    }
}

/// Runs a prepared line; `network requests` comes back one line per request unless `--full`.
async fn run_line(state: &mut DaemonState, p: &Prepared) -> Result<Value, ToolError> {
    // Screenshots hold what the page showed: owner-only, like the rest of `.raijin/`.
    if let Some(dir) = &p.shots {
        crate::util::private_dir(dir)
            .map_err(|e| ToolError::new(Code::ToolFailed, format!("{e:#}")))?;
    }
    let data = run_parsed(state, &p.cmd).await?;
    if p.cmd.get("action").and_then(Value::as_str) == Some("requests") && !p.full {
        return Ok(summarize_requests(data));
    }
    Ok(data)
}

/// The JavaScript of an `eval` line as written: everything after the word `eval`, with one wholly
/// quoted token unquoted. `None` when the line is not `eval` or has no script.
pub fn eval_script(line: &str) -> Option<String> {
    /// `s` without its leading `word` (any case) when the word stands alone.
    fn strip_word<'a>(s: &'a str, word: &str) -> Option<&'a str> {
        let head = s.get(..word.len())?;
        let rest = &s[word.len()..];
        (head.eq_ignore_ascii_case(word) && rest.chars().next().is_none_or(char::is_whitespace))
            .then(|| rest.trim_start())
    }
    let line = line.trim_start();
    let line = strip_word(line, "agent-browser").unwrap_or(line);
    let rest = strip_word(line, "eval")?.trim();
    if rest.is_empty() {
        return None;
    }
    let mut chars = rest.char_indices();
    let (_, q) = chars.next()?;
    if q == '"' || q == '\'' {
        let mut escaped = false;
        let mut close = None;
        for (i, c) in chars {
            if escaped {
                escaped = false;
            } else if c == '\\' && q == '"' {
                escaped = true;
            } else if c == q {
                close = Some(i);
                break;
            }
        }
        if close == Some(rest.len() - 1) {
            let inside = &rest[1..rest.len() - 1];
            let js = if q == '"' {
                unescape_double(inside)
            } else {
                inside.to_owned()
            };
            return (!js.is_empty()).then_some(js);
        }
    }
    Some(rest.to_owned())
}

/// The inside of a double-quoted token: `\"` and `\\` unescaped, every other backslash kept.
fn unescape_double(inside: &str) -> String {
    let mut out = String::with_capacity(inside.len());
    let mut chars = inside.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\'
            && let Some(&next) = chars.peek()
            && (next == '"' || next == '\\')
        {
            out.push(next);
            chars.next();
            continue;
        }
        out.push(c);
    }
    out
}

/// `network requests` data as one line per request; any other data (`--clear`) unchanged.
pub fn summarize_requests(data: Value) -> Value {
    let Some(requests) = data.get("requests").and_then(Value::as_array) else {
        return data;
    };
    let n = requests.len();
    if n == 0 {
        return Value::String("0 requests".to_owned());
    }
    let s = if n == 1 { "" } else { "s" };
    let mut out = format!(
        "{n} request{s} (id method status type url); network request <id> shows one with headers and body, --full shows every field:"
    );
    for r in requests {
        let field = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or_default();
        let status = r
            .get("status")
            .filter(|v| !v.is_null())
            .map_or_else(|| "-".to_owned(), Value::to_string);
        let _ = write!(
            out,
            "\n{} {} {status} {} {}",
            field("requestId"),
            field("method"),
            field("resourceType"),
            field("url")
        );
    }
    Value::String(out)
}
