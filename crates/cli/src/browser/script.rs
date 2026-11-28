//! `script`: a Playwright JavaScript body run by the Playwright driver's Node over CDP, or a
//! `ShardBrowser` automation block list run by the launcher; saved ones rerun. Plus the saved-script
//! actions `list_scripts` and `delete_script`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use reqwest::Method;
use rmcp::model::CallToolResult;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;

use super::actions::NoArgs;
use super::{Call, Hub, error_with, json_result};
use crate::mcp::error::{Code, ToolError};

const DEFAULT_TIMEOUT_MS: u64 = 120_000;
const MAX_TIMEOUT_MS: u64 = 1_800_000;
/// Most bytes of script output a result carries, per stream.
const MAX_OUTPUT: usize = 16_384;
/// Starts the runner's result line on stdout.
const MARK: &str = "\u{0}raijin-result\u{0}";
/// The block a script puts first to run on a given profile.
const PROFILE_BLOCK: &str = "raijin-profile";

/// Runs `{code, args}` from stdin as an async function body against the browser at `RAIJIN_CDP`
/// and prints `MARK` + `{ok, value|error}`. It never closes the browser: exiting drops the CDP
/// connection and leaves the profile running.
const JS_RUNNER: &str = r#"const MARK = "\u0000raijin-result\u0000";
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => (input += c));
process.stdin.on("end", async () => {
  let out;
  try {
    const { code, args } = JSON.parse(input);
    const playwright = require(process.env.RAIJIN_PW_CORE);
    const browser = await playwright.chromium.connectOverCDP(process.env.RAIJIN_CDP, { timeout: 30000 });
    const context = browser.contexts()[0] ?? (await browser.newContext());
    const pages = context.pages().filter((p) => !p.url().startsWith("devtools://"));
    const page = pages.find((p) => p.url() === process.env.RAIJIN_ACTIVE_URL) ?? pages[0] ?? (await context.newPage());
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
    const value = await new AsyncFunction("browser", "context", "page", "playwright", "args", code)(browser, context, page, playwright, args);
    out = { ok: true, value: value === undefined ? null : value };
  } catch (e) {
    out = { ok: false, error: String((e && e.stack) || e) };
  }
  let text;
  try { text = JSON.stringify(out); }
  catch (e) { text = JSON.stringify({ ok: false, error: "the return value is not JSON-serializable: " + e.message }); }
  process.stdout.write("\n" + MARK + text + "\n", () => process.exit(0));
});
"#;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScriptArgs {
    /// The profile to run on (started when needed). `js` and `saved_js` need it; `blocks` and
    /// `project` run on it when given.
    pub profile_id: Option<String>,
    /// A Playwright JavaScript async function body; browser, context, page, playwright and args
    /// are in scope and its return value (JSON) is the result.
    pub js: Option<String>,
    /// The name of a script saved with `save_as`.
    pub saved_js: Option<String>,
    /// `ShardBrowser` automation blocks (`{"kind", "params", "on_fail"}`); guide
    /// `{"topic":"browser.blocks"}`.
    pub blocks: Option<Vec<Value>>,
    /// A saved automation project by id or name.
    pub project: Option<String>,
    /// js: the value of `args`.
    pub args: Option<Value>,
    /// Keep js (when it succeeds) as <target>/.raijin/scripts/<name>.js, or blocks as an
    /// automation project of that name: letters, digits, _ and -, up to 64.
    pub save_as: Option<String>,
    /// Default 120000, at most 1800000.
    pub timeout_ms: Option<u64>,
    /// Start the profile without a window when it is not running.
    pub headless: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScriptNameArgs {
    pub name: String,
}

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The blocks to run: each an object with a string `kind`, given an id when it has none, with a
/// `profile.use` block for `profile_id` first.
pub fn prepare_blocks(
    blocks: Vec<Value>,
    profile_id: Option<&str>,
) -> Result<Vec<Value>, ToolError> {
    let mut out = Vec::with_capacity(blocks.len() + 1);
    for (i, mut block) in blocks.into_iter().enumerate() {
        let Some(object) = block.as_object_mut() else {
            return Err(ToolError::new(
                Code::InvalidArguments,
                format!("blocks[{i}] is not an object"),
            )
            .param("blocks"));
        };
        if !object.get("kind").is_some_and(Value::is_string) {
            return Err(ToolError::new(
                Code::InvalidArguments,
                format!("blocks[{i}] has no string 'kind'; guide {{\"topic\":\"browser.blocks\"}} lists them"),
            )
            .param("blocks"));
        }
        if !object.get("id").is_some_and(Value::is_string) {
            object.insert("id".to_owned(), json!(format!("s{}", i + 1)));
        }
        out.push(block);
    }
    if let Some(profile_id) = profile_id {
        match out.first_mut() {
            Some(first) if first["id"] == PROFILE_BLOCK => set_profile(first, profile_id),
            _ => out.insert(
                0,
                json!({"id": PROFILE_BLOCK, "kind": "profile.use", "label": "raijin: profile", "params": {"id": profile_id}}),
            ),
        }
    }
    Ok(out)
}

/// Points a `profile.use` block at `profile_id`; `params` that is not an object is replaced.
fn set_profile(block: &mut Value, profile_id: &str) {
    if !block.get("params").is_some_and(Value::is_object) {
        block["params"] = json!({});
    }
    block["params"]["id"] = json!(profile_id);
}

/// Saved script names in `dir`, sorted.
fn saved_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            name.strip_suffix(".js").map(str::to_owned)
        })
        .collect();
    names.sort();
    names
}

fn millis(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

impl Hub {
    pub(super) async fn script(&self, call: &mut Call<'_>) -> Result<CallToolResult, ToolError> {
        match call.action.name {
            "list_scripts" => {
                call.args::<NoArgs>()?;
                let dir = scripts_dir(call)?;
                let list: Vec<Value> = saved_names(&dir)
                    .into_iter()
                    .map(|name| {
                        let path = dir.join(format!("{name}.js"));
                        let text = std::fs::read_to_string(&path).unwrap_or_default();
                        let about = text
                            .lines()
                            .next()
                            .and_then(|l| l.strip_prefix("//"))
                            .map(str::trim);
                        json!({"name": name, "bytes": text.len(), "about": about})
                    })
                    .collect();
                Ok(json_result(&Value::Array(list)))
            }
            "delete_script" => {
                let ScriptNameArgs { name } = call.args()?;
                let dir = scripts_dir(call)?;
                let path = dir.join(format!("{name}.js"));
                if !valid_name(&name) || !path.is_file() {
                    return Err(not_saved(&name, &dir));
                }
                std::fs::remove_file(&path).map_err(|e| {
                    ToolError::new(
                        Code::ToolFailed,
                        format!("deleting {}: {e}", path.display()),
                    )
                })?;
                Ok(json_result(&json!({"deleted": name})))
            }
            _ => self.run_script(call).await,
        }
    }

    async fn run_script(&self, call: &mut Call<'_>) -> Result<CallToolResult, ToolError> {
        let args: ScriptArgs = call.args()?;
        let given: Vec<&str> = [
            ("js", args.js.is_some()),
            ("saved_js", args.saved_js.is_some()),
            ("blocks", args.blocks.is_some()),
            ("project", args.project.is_some()),
        ]
        .into_iter()
        .filter_map(|(k, set)| set.then_some(k))
        .collect();
        match given.len() {
            0 => {
                return Err(ToolError::new(
                    Code::MissingParameter,
                    "browser.script needs one of js, saved_js, blocks or project",
                )
                .param("js")
                .example(call.action.example()));
            }
            1 => {}
            _ => {
                return Err(ToolError::new(
                    Code::InvalidArguments,
                    format!(
                        "browser.script takes one of js, saved_js, blocks or project; got {}",
                        given.join(", ")
                    ),
                )
                .param(given[1]));
            }
        }
        if let Some(name) = &args.save_as {
            if !valid_name(name) {
                return Err(ToolError::new(
                    Code::InvalidArguments,
                    "save_as must be 1 to 64 letters, digits, _ or -",
                )
                .param("save_as")
                .got(json!(name)));
            }
            if args.saved_js.is_some() || args.project.is_some() {
                return Err(ToolError::new(
                    Code::InvalidArguments,
                    "save_as goes with js or blocks; saved_js and project are saved already",
                )
                .param("save_as"));
            }
        }
        let mut timeout_ms = args.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
        if timeout_ms > MAX_TIMEOUT_MS {
            timeout_ms = MAX_TIMEOUT_MS;
            call.notes
                .push(format!("timeout_ms clamped to {MAX_TIMEOUT_MS}"));
        }
        let timeout = Duration::from_millis(timeout_ms);
        if args.js.is_some() || args.saved_js.is_some() {
            self.run_js(call, args, timeout).await
        } else {
            self.run_blocks(call, args, timeout).await
        }
    }

    async fn run_js(
        &self,
        call: &mut Call<'_>,
        args: ScriptArgs,
        timeout: Duration,
    ) -> Result<CallToolResult, ToolError> {
        let Some(profile_id) = args.profile_id.as_deref() else {
            return Err(ToolError::new(
                Code::MissingParameter,
                "browser.script with js or saved_js needs 'profile_id'",
            )
            .param("profile_id")
            .example(call.action.example()));
        };
        let code = js_code(call, &args)?;
        let save_dir = match &args.save_as {
            Some(_) => Some(scripts_dir(call)?),
            None => None,
        };
        let (node, playwright_core) = driver()?;
        let cdp = self
            .launcher
            .cdp(profile_id, args.headless.unwrap_or(false))
            .await?;
        let active_url = self.active_url(profile_id).await;
        let started = Instant::now();
        let mut child = tokio::process::Command::new(&node)
            .arg("-e")
            .arg(JS_RUNNER)
            .env("RAIJIN_PW_CORE", &playwright_core)
            .env("RAIJIN_CDP", &cdp.http_url)
            .env("RAIJIN_ACTIVE_URL", &active_url)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                ToolError::new(
                    Code::ConfigError,
                    format!("starting {}: {e}", node.display()),
                )
            })?;
        let input = json!({"code": code, "args": args.args.clone().unwrap_or(Value::Null)});
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(input.to_string().as_bytes())
                .await
                .map_err(|e| ToolError::new(Code::ToolFailed, format!("the script runner: {e}")))?;
        }
        // Dropping the child on timeout kills it (`kill_on_drop`).
        let Ok(output) = tokio::time::timeout(timeout, child.wait_with_output()).await else {
            return Err(ToolError::new(
                Code::ToolFailed,
                format!(
                    "script ran past timeout_ms ({} ms) and was stopped",
                    timeout.as_millis()
                ),
            ));
        };
        let output = output
            .map_err(|e| ToolError::new(Code::ToolFailed, format!("the script runner: {e}")))?;
        let duration_ms = millis(started);
        let RunnerOutput {
            result,
            logs,
            stderr,
        } = runner_output(&output)?;
        if result.get("ok").and_then(Value::as_bool) != Some(true) {
            if args.save_as.is_some() {
                call.notes.push("not saved: the script failed".to_owned());
            }
            let stack = result
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            let first = stack.lines().next().unwrap_or(stack);
            let error = ToolError::new(Code::ToolFailed, format!("script failed: {first}"));
            return Ok(error_with(
                &error,
                json!({"stack": stack, "logs": logs, "duration_ms": duration_ms}),
            ));
        }
        let mut value = json!({
            "ok": true,
            "value": result.get("value").cloned().unwrap_or(Value::Null),
            "logs": logs,
            "duration_ms": duration_ms,
        });
        if !stderr.is_empty() {
            value["stderr"] = json!(stderr);
        }
        if let (Some(name), Some(dir), Some(js)) = (&args.save_as, &save_dir, &args.js) {
            crate::util::write_private(&dir.join(format!("{name}.js")), js.as_bytes())
                .map_err(|e| ToolError::new(Code::ToolFailed, format!("{e:#}")))?;
            value["saved"] = json!(name);
        }
        Ok(json_result(&value))
    }

    /// The URL of the page session's active tab, so the script runs on the same tab; empty when
    /// there is no session.
    async fn active_url(&self, profile_id: &str) -> String {
        let Some(session) = self.existing_session(profile_id).await else {
            return String::new();
        };
        let mut session = session.lock().await;
        let words = ["get".to_owned(), "url".to_owned()];
        match self.exec(&mut session.state, &words).await {
            Ok(Value::String(url)) => url,
            Ok(data) => data
                .get("url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            Err(_) => String::new(),
        }
    }

    async fn run_blocks(
        &self,
        call: &mut Call<'_>,
        args: ScriptArgs,
        timeout: Duration,
    ) -> Result<CallToolResult, ToolError> {
        let (project, temporary) = if let Some(wanted) = &args.project {
            let project = self
                .saved_project(call, wanted, args.profile_id.as_deref())
                .await?;
            (project, false)
        } else {
            let blocks = prepare_blocks(
                args.blocks.clone().unwrap_or_default(),
                args.profile_id.as_deref(),
            )?;
            let project = self.blocks_project(blocks, args.save_as.as_deref()).await?;
            (project, args.save_as.is_none())
        };
        let id = project_id(&project)?;
        let name = project.get("name").cloned().unwrap_or(Value::Null);
        let outcome = self.run_project(&id, timeout).await;
        // The launcher closes the bound profile's browser when a run ends.
        if let Some(profile_id) = &args.profile_id {
            self.drop_session(profile_id).await;
        }
        if temporary {
            let _ = self
                .launcher
                .api(Method::DELETE, &["automation", "projects", &id], &[], None)
                .await;
        }
        Ok(match outcome {
            Ok(status) => blocks_result(&id, &name, temporary, &status),
            Err(result) => *result,
        })
    }

    /// Saved project `wanted` (id or name), its `raijin-profile` block rebound to `profile_id`.
    async fn saved_project(
        &self,
        call: &mut Call<'_>,
        wanted: &str,
        profile_id: Option<&str>,
    ) -> Result<Value, ToolError> {
        let l = &self.launcher;
        let all = l.get(&["automation", "projects"]).await?;
        let mut project = find_project(&all, wanted)?;
        let Some(profile_id) = profile_id else {
            return Ok(project);
        };
        let first = project
            .get_mut("blocks")
            .and_then(Value::as_array_mut)
            .and_then(|b| b.first_mut())
            .filter(|b| b["id"] == PROFILE_BLOCK);
        let Some(first) = first else {
            return Err(ToolError::new(
                Code::InvalidArguments,
                "this project has no raijin-profile block to rebind; edit it with save_automation_project",
            )
            .param("profile_id"));
        };
        set_profile(first, profile_id);
        let id = project_id(&project)?;
        l.api(
            Method::PUT,
            &["automation", "projects", &id],
            &[],
            Some(project.clone()),
        )
        .await?;
        call.notes
            .push(format!("rebound the saved project to profile {profile_id}"));
        Ok(project)
    }

    /// A project holding `blocks`: the one named `save_as` (made when missing), else a new
    /// temporary one.
    async fn blocks_project(
        &self,
        blocks: Vec<Value>,
        save_as: Option<&str>,
    ) -> Result<Value, ToolError> {
        let l = &self.launcher;
        let projects_path = ["automation", "projects"];
        let mut existing = None;
        if let Some(name) = save_as {
            let all = l.get(&projects_path).await?;
            existing = all
                .as_array()
                .into_iter()
                .flatten()
                .find(|p| p.get("name").and_then(Value::as_str) == Some(name))
                .cloned();
        }
        let mut project = if let Some(p) = existing {
            p
        } else {
            let name = save_as.map_or_else(
                || format!("raijin-script-{}", crate::util::utc_stamp()),
                str::to_owned,
            );
            l.api(
                Method::POST,
                &projects_path,
                &[],
                Some(json!({"name": name})),
            )
            .await?
        };
        project["blocks"] = Value::Array(blocks);
        project["run"] = json!({"threads": 1, "loops": 1, "hours": 0, "profiles": [], "start": ""});
        let id = project_id(&project)?;
        let saved = l
            .api(
                Method::PUT,
                &["automation", "projects", &id],
                &[],
                Some(project.clone()),
            )
            .await;
        if let Err(e) = saved {
            if save_as.is_none() {
                let _ = l
                    .api(Method::DELETE, &["automation", "projects", &id], &[], None)
                    .await;
            }
            return Err(e);
        }
        Ok(project)
    }
}

/// A finished run as the `script` result: an error result when a worker did not finish `done`.
fn blocks_result(id: &str, name: &Value, temporary: bool, status: &Value) -> CallToolResult {
    let workers = status.get("workers").cloned().unwrap_or(json!([]));
    let failed = workers
        .as_array()
        .into_iter()
        .flatten()
        .find(|w| w.get("status").and_then(Value::as_str) != Some("done"));
    let fields = json!({
        "project_id": id,
        "project_name": name,
        "saved": !temporary,
        "ok": failed.is_none(),
        "workers": workers,
        "log": status.get("log").cloned().unwrap_or(json!([])),
    });
    if let Some(worker) = failed {
        let who = worker
            .get("profile_name")
            .and_then(Value::as_str)
            .filter(|n| !n.is_empty())
            .or_else(|| worker.get("profile_id").and_then(Value::as_str))
            .unwrap_or("a worker");
        let state = worker
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let note = worker.get("note").and_then(Value::as_str).unwrap_or("");
        // The note only names the step ("step 3"); the log line of that step says why.
        let why = status
            .get("log")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .rev()
            .find_map(|line| line.split_once(&format!("{note} — ")).map(|(_, why)| why))
            .filter(|_| !note.is_empty());
        let error = ToolError::new(
            Code::ToolFailed,
            match why {
                Some(why) => format!("the run failed: {who} {state} at {note}: {why}"),
                None => format!("the run failed: {who} {state}: {note}"),
            },
        );
        return error_with(&error, fields);
    }
    json_result(&fields)
}

impl Hub {
    /// Starts project `id` and polls its status until its run ends; the final status, else the
    /// error result to return.
    async fn run_project(&self, id: &str, timeout: Duration) -> Result<Value, Box<CallToolResult>> {
        let failed = |e: ToolError| Box::new(e.into_result());
        let l = &self.launcher;
        let status_path = ["automation", "projects", id, "status"];
        let since = crate::util::now_ms() / 1000;
        l.api(
            Method::POST,
            &["automation", "projects", id, "run"],
            &[],
            None,
        )
        .await
        .map_err(failed)?;
        let deadline = Instant::now() + timeout;
        let ended = |status: &Value| {
            status.get("running").and_then(Value::as_bool) == Some(false)
                // A status left from an earlier run of a saved project is not this run's end.
                && status
                    .get("started_at")
                    .and_then(Value::as_u64)
                    .is_none_or(|t| t + 1 >= since)
        };
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let status = l.get(&status_path).await.map_err(failed)?;
            if ended(&status) {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                break;
            }
        }
        let _ = l
            .api(
                Method::POST,
                &["automation", "projects", id, "stop"],
                &[],
                None,
            )
            .await;
        let grace = Instant::now() + Duration::from_secs(15);
        let mut log = Value::Null;
        while Instant::now() < grace {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if let Ok(status) = l.get(&status_path).await {
                log = status.get("log").cloned().unwrap_or(Value::Null);
                if ended(&status) {
                    break;
                }
            }
        }
        let error = ToolError::new(
            Code::ToolFailed,
            "the run did not finish within timeout_ms; asked it to stop",
        );
        Err(Box::new(error_with(&error, json!({"log": log}))))
    }
}

/// What the JS runner printed: its result object, the script's own output before it, and stderr.
struct RunnerOutput {
    result: Value,
    logs: String,
    stderr: String,
}

fn runner_output(output: &std::process::Output) -> Result<RunnerOutput, ToolError> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = crate::util::truncate_utf8(stderr.trim(), MAX_OUTPUT).to_owned();
    let Some(at) = stdout.rfind(MARK) else {
        let code = output
            .status
            .code()
            .map_or_else(|| "by a signal".to_owned(), |c| c.to_string());
        return Err(ToolError::new(
            Code::ToolFailed,
            format!("the script runner exited without a result (exit {code}): {stderr}"),
        ));
    };
    let logs = crate::util::truncate_utf8(stdout[..at].trim(), MAX_OUTPUT).to_owned();
    let result: Value = serde_json::from_str(stdout[at + MARK.len()..].trim()).map_err(|e| {
        ToolError::new(
            Code::ToolFailed,
            format!("the script runner's result is not JSON: {e}"),
        )
    })?;
    Ok(RunnerOutput {
        result,
        logs,
        stderr,
    })
}

/// The script to run: `js`, or the saved script `saved_js` names.
fn js_code(call: &Call<'_>, args: &ScriptArgs) -> Result<String, ToolError> {
    if let Some(js) = &args.js {
        return Ok(js.clone());
    }
    let Some(name) = &args.saved_js else {
        return Err(ToolError::new(
            Code::Internal,
            "browser.script ran as js without js or saved_js",
        ));
    };
    let dir = scripts_dir(call)?;
    if !valid_name(name) {
        return Err(not_saved(name, &dir));
    }
    std::fs::read_to_string(dir.join(format!("{name}.js"))).map_err(|_| not_saved(name, &dir))
}

/// The Playwright driver's Node and its `playwright-core` package directory.
fn driver() -> Result<(PathBuf, PathBuf), ToolError> {
    let (node, cli_js) = playwright_rs::server::driver::get_driver_executable().map_err(|e| {
        ToolError::new(
            Code::ConfigError,
            format!(
                "{e}\nInstall the Playwright driver: cargo install playwright-rs --features cli && playwright-rs install, or set PLAYWRIGHT_DRIVER_PATH"
            ),
        )
    })?;
    let package = cli_js.parent().map_or_default(Path::to_path_buf);
    Ok((node, package))
}

/// `<target>/.raijin/scripts`, or a config error without a target.
fn scripts_dir(call: &Call<'_>) -> Result<PathBuf, ToolError> {
    call.ctx
        .target
        .map(|t| t.state_dir().join("scripts"))
        .ok_or_else(|| {
            ToolError::new(
                Code::ConfigError,
                "saved scripts need a raijin target (run raijin init)",
            )
        })
}

fn not_saved(name: &str, dir: &Path) -> ToolError {
    ToolError::new(Code::NotFound, format!("no saved script named {name}"))
        .param("name")
        .allowed(saved_names(dir).into_iter().map(Value::String).collect())
}

fn project_id(project: &Value) -> Result<String, ToolError> {
    project
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| {
            ToolError::new(
                Code::Internal,
                "the launcher returned a project without an id",
            )
        })
}

/// The project `wanted` names in `all`: its id, else the one name equal to it ignoring case.
fn find_project(all: &Value, wanted: &str) -> Result<Value, ToolError> {
    let projects: &[Value] = all.as_array().map_or(&[], Vec::as_slice);
    if let Some(p) = projects
        .iter()
        .find(|p| p.get("id").and_then(Value::as_str) == Some(wanted))
    {
        return Ok(p.clone());
    }
    let named: Vec<&Value> = projects
        .iter()
        .filter(|p| {
            p.get("name")
                .and_then(Value::as_str)
                .is_some_and(|n| n.eq_ignore_ascii_case(wanted))
        })
        .collect();
    match named.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(ToolError::new(
            Code::NotFound,
            format!("no automation project with id or name {wanted}"),
        )
        .param("project")
        .allowed(
            projects
                .iter()
                .filter_map(|p| p.get("name").cloned())
                .collect(),
        )),
        many => Err(ToolError::new(
            Code::InvalidArguments,
            format!("several automation projects are named {wanted}; pass the id"),
        )
        .param("project")
        .allowed(many.iter().filter_map(|p| p.get("id").cloned()).collect())),
    }
}
