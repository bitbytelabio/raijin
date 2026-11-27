//! `raijin mcp`: a stdio MCP server (rmcp; MCP 2026-07-28 and the legacy initialize era) with two tools, `guide` and `run`, in front of Raijin's tool API, the Burp lifecycle and the offline history engine; playbooks as prompts, skills and `skill://` resources.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::future::{self, Future};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rmcp::model::Skill as McpSkill;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, GetPromptRequestParams,
    GetPromptResponse, GetPromptResult, GetSkillRequestParams, GetSkillResult, Implementation,
    JsonObject, ListPromptsResult, ListResourcesResult, ListSkillsResult, ListToolsResult,
    PaginatedRequestParams, Prompt, PromptMessage, ReadResourceRequestParams, ReadResourceResponse,
    ReadResourceResult, Resource, ResourceContents, Role, ServerCapabilities, ServerConfig,
    SkillFrontmatter, SkillResource, SkillResources, Tool, ToolAnnotations,
};
use rmcp::service::{MaybeSendFuture, RequestContext};
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::sync::OnceCell;

use super::api::{ApiError, Endpoint, ToolApi};
use super::args::{call_fits, is_empty_value, parse_args, schema_of};
use super::error::{self, Code, ToolError, guide_call};
use super::{spill, stdin};
use crate::burp::{instance, launch};
use crate::catalog::{self, ActionSpec, Catalog, SKILL_FILE, ToolSpec};
use crate::config::{Mode, Remote, Target, user_state_dir};
use crate::data::{self, store};
use crate::history;
use crate::jar::{self, Assets};
use crate::util::{
    Intent, contains_near, edit_distance, intent_call, suggest, suggest_call, truncate_utf8,
    verb_calls,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Surface {
    /// guide and run only. lean (default) suits weak or small models.
    Lean,
    /// Also every Raijin tool, callable directly: full lists every tool (~176 KB tools/list), which some clients truncate.
    Full,
}

const INSTRUCTIONS_HEAD: &str = "Raijin drives Burp Suite through two tools. guide() shows the running Burp \
instances, every tool by domain (grouped tools list their actions) and the playbooks; \
guide({\"topic\":\"<tool, tool.action, domain or playbook>\"}) gives one tool's inputSchema, a domain's tools, or a \
playbook: copy parameter names from it, never guess. run({\"do\":\"<tool>\", ...that tool's parameters}) runs one \
tool; a grouped tool: run({\"do\":\"scope.check\",\"url\":\"https://example.com\"}); several in order: \
run({\"batch\":[{\"do\":...},...],\"bail\":true}). ";
const INSTRUCTIONS_LOCAL: &str =
    "Burp tools need a running Burp: run({\"do\":\"burp_up\"}) first; ";
const INSTRUCTIONS_REMOTE: &str =
    "Burp is remote and not managed here; run({\"do\":\"burp_status\"}) checks it; ";
const INSTRUCTIONS_TAIL: &str = "offline .burp review (domain history) needs no Burp. Pass \"project\" to pick the \
Burp when several run. An error result is JSON with 'error' and 'code': resend 'retry' when it is given, else fix \
the call from 'usage' and 'example'; never resend a call unchanged when 'retryable' is false. Results over the \
inline limit come back as {saved_to, preview}: parse the file with jq/python, never read it whole. Call guide() \
first: it lists every tool by domain; then read the overview playbook: guide({\"topic\":\"overview\"}), also the \
prompt /overview and skill://overview/SKILL.md. 'see' is a call to make first: an object with \"do\" goes to run, \
one with \"guide\" holds guide's arguments.";

/// Why a destructive tool named in another form is not run.
const DESTRUCTIVE_EXACT: &str = "It is destructive, so it runs only under its exact name.";

const GUIDE_HEAD: &str = "Run a tool: run {\"do\":\"<tool>\", ...its parameters}. Grouped tool: run \
{\"do\":\"<tool>.<action>\", ...} e.g. {\"do\":\"scope.check\",\"url\":\"https://example.com\"}. Several in order: \
run {\"batch\":[{\"do\":...},...],\"bail\":true}. One tool's parameters, a domain's tools or a playbook: guide \
{\"topic\":\"<name>\"}.";

const RUN_DESCRIPTION: &str = "Run one Raijin or Burp tool: {\"do\":\"<tool>\", ...that tool's parameters, \
\"project\":\"<optional>\"}; a grouped tool takes {\"do\":\"<tool>.<action>\", ...}. Several in order: \
{\"batch\":[{\"do\":...},...],\"bail\":true}. Names and parameters come from guide. Examples: \
{\"do\":\"proxy_history\",\"count\":20}, {\"do\":\"scope.check\",\"url\":\"https://example.com\"}, {\"do\":\"burp_up\"}.";

/// The example call errors about `run` itself show.
const RUN_EXAMPLE: &str = "{\"do\":\"proxy_history\",\"count\":20}";

const MISSING_DO: &str = "run needs \"do\": the tool to run, e.g. {\"do\":\"proxy_history\",\"count\":20}; \
guide() lists every tool.";

/// After `unknown tool "<name>": ` on the lean surface.
const UNKNOWN_SURFACE_TOOL: &str = "this server has two tools, guide and run. Run Raijin tools through \
run, e.g. run {\"do\":\"proxy_history\",\"count\":20}.";

const LIFECYCLE: &str = "lifecycle";
const HISTORY: &str = "history";
const OTHER: &str = "other";

const LIFECYCLE_DESCRIPTION: &str =
    "Start, stop and inspect this target's CLI-managed Burp instances.";
const LIFECYCLE_NOTES: &str = "Remote mode: only burp_status.";
const HISTORY_DESCRIPTION: &str = "Offline review of this target's .burp projects plus the Raijin archive, \
without starting Burp; reads all projects in parallel.";
const HISTORY_NOTES: &str = "Live data of a running Burp is proxy.";
const DATA: &str = "data";
const DATA_DESCRIPTION: &str = "PortSwigger's XSS and URL-bypass cheat sheets, BChecks and Bambdas (cached in \
~/.raijin/data) plus this target's own payloads and checks (data/): known vectors and checks to start from.";
const DATA_NOTES: &str = "Starting points, not limits: adapt a vector to the context you see and craft new ones \
when none fits. Upstream data downloads on first use and refreshes when older than 7 days; data_update forces it. \
Save what worked with data_add.";
const OTHER_DESCRIPTION: &str =
    "Tools the running Raijin has that this CLI's catalog does not list.";
const OTHER_NOTES: &str = "";

/// Bytes of a tool's first description line shown in a domain listing.
const SUMMARY_BYTES: usize = 200;

/// The playbook of a domain the CLI owns.
fn local_playbook(domain: &str) -> &'static str {
    match domain {
        HISTORY => "offline-history",
        DATA => "data-library",
        _ => "overview",
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct GuideArgs {
    /// A tool, tool.action, old member name, domain, playbook, or playbook file (http-testing/references/pipeline.md). Omit for the overview.
    topic: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct UpArgs {
    /// Project to start (default: `default_project` of raijin.toml).
    project: Option<String>,
    /// headless (default from raijin.toml) or ui.
    mode: Option<Mode>,
    /// Seconds to wait for Burp to come up (default 60, max 600). On timeout the state is `starting`.
    wait_seconds: Option<u64>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DownArgs {
    /// Project to stop (default: `default_project`).
    project: Option<String>,
    /// Stop every running project of this target.
    #[serde(default)]
    all: bool,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct StatusArgs {}

const DEFAULT_WAIT: u64 = 60;
const MAX_WAIT: u64 = 600;

/// A tool the gateway itself implements.
struct LocalTool {
    name: &'static str,
    domain: &'static str,
    description: &'static str,
    schema: fn() -> JsonObject,
    /// A valid `run` call (JSON) that errors show as `example`.
    example: &'static str,
    /// MCP `readOnlyHint`.
    read_only: bool,
    /// MCP `destructiveHint`.
    destructive: bool,
}

impl LocalTool {
    fn example(&self) -> Value {
        serde_json::from_str(self.example).unwrap_or_else(|_| json!({"do": self.name}))
    }

    fn annotations(&self) -> Value {
        json!({"readOnlyHint": self.read_only, "destructiveHint": self.destructive, "openWorldHint": false})
    }
}

const LOCAL_TOOLS: &[LocalTool] = &[
    LocalTool {
        name: "burp_up",
        domain: LIFECYCLE,
        description: "Start Burp with Raijin for a project of this target (detached; survives this session).",
        schema: schema_of::<UpArgs>,
        example: r#"{"do":"burp_up"}"#,
        read_only: false,
        destructive: false,
    },
    LocalTool {
        name: "burp_down",
        domain: LIFECYCLE,
        description: "Stop a project's Burp (graceful, then SIGTERM, then SIGKILL), or every one with all=true.",
        schema: schema_of::<DownArgs>,
        example: r#"{"do":"burp_down"}"#,
        read_only: false,
        destructive: true,
    },
    LocalTool {
        name: "burp_status",
        domain: LIFECYCLE,
        description: "Every project of this target and its Burp state; in remote mode, whether the remote Raijin answers.",
        schema: schema_of::<StatusArgs>,
        example: r#"{"do":"burp_status"}"#,
        read_only: true,
        destructive: false,
    },
    LocalTool {
        name: "history_list",
        domain: HISTORY,
        description: "Exchanges (Proxy history of every .burp project + Raijin's archive of tool traffic) or scanner issues, oldest first, filtered and paged.",
        schema: schema_of::<history::list::ListParams>,
        example: r#"{"do":"history_list","limit":20}"#,
        read_only: true,
        destructive: false,
    },
    LocalTool {
        name: "history_show",
        domain: HISTORY,
        description: "One exchange or issue by ref (<project>:<id>, <project>:a<seq>, <project>:i<seq>): headers whole, bodies cut at max_body.",
        schema: schema_of::<history::show::ShowParams>,
        example: r#"{"do":"history_show","ref":"main:1"}"#,
        read_only: true,
        destructive: false,
    },
    LocalTool {
        name: "history_search",
        domain: HISTORY,
        description: "Regex over raw requests/responses of every project; up to 3 hits per entry with context.",
        schema: schema_of::<history::search::SearchParams>,
        example: r#"{"do":"history_search","pattern":"(?i)password","limit":20}"#,
        read_only: true,
        destructive: false,
    },
    LocalTool {
        name: "history_endpoints",
        domain: HISTORY,
        description: "API map: exchanges grouped by host + method + path, with query/body parameter names, statuses and projects.",
        schema: schema_of::<history::endpoints::EndpointsParams>,
        example: r#"{"do":"history_endpoints","limit":50}"#,
        read_only: true,
        destructive: false,
    },
    LocalTool {
        name: "history_diff",
        domain: HISTORY,
        description: "Unified diff of two exchanges (response by default).",
        schema: schema_of::<history::diff::DiffParams>,
        example: r#"{"do":"history_diff","a":"main:1","b":"main:2"}"#,
        read_only: true,
        destructive: false,
    },
    LocalTool {
        name: "history_export",
        domain: HISTORY,
        description: "bproj JSON export of each project (plus the archive files) under .raijin/exports/.",
        schema: schema_of::<history::export::ExportParams>,
        example: r#"{"do":"history_export"}"#,
        read_only: false,
        destructive: false,
    },
    LocalTool {
        name: "data_list",
        domain: DATA,
        description: "Data sources: PortSwigger cache state (commit, age, entries per category) and this target's own data.",
        schema: schema_of::<data::tools::ListArgs>,
        example: r#"{"do":"data_list"}"#,
        read_only: true,
        destructive: false,
    },
    LocalTool {
        name: "data_search",
        domain: DATA,
        description: "Search cheat sheet vectors, BChecks and Bambdas by words and filters; payload rows show the vector, scripts come whole from data_get.",
        schema: schema_of::<data::tools::SearchArgs>,
        example: r#"{"do":"data_search","query":"svg onload","source":"xss","limit":10}"#,
        read_only: true,
        destructive: false,
    },
    LocalTool {
        name: "data_get",
        domain: DATA,
        description: "One entry by id, whole: the vector or the BCheck/Bambda script, and every upstream field.",
        schema: schema_of::<data::tools::GetArgs>,
        example: r#"{"do":"data_get","id":"xss:events/onload/svg"}"#,
        read_only: true,
        destructive: false,
    },
    LocalTool {
        name: "data_payloads",
        domain: DATA,
        description: "Payload strings matching the filters, <attacker>/<allowed> filled in, ready for http_fuzz payloads.",
        schema: schema_of::<data::tools::PayloadsArgs>,
        example: r#"{"do":"data_payloads","source":"url","category":"loopback","limit":50}"#,
        read_only: true,
        destructive: false,
    },
    LocalTool {
        name: "data_add",
        domain: DATA,
        description: "Save a payload (data/payloads/<category>.json), BCheck or Bambda to this target's data folder, tracked by git.",
        schema: schema_of::<data::tools::AddArgs>,
        example: r#"{"do":"data_add","category":"waf-bypass","payload":"<svg/onload=alert(1)>","description":"passes the WAF on /search"}"#,
        read_only: false,
        destructive: false,
    },
    LocalTool {
        name: "data_import",
        domain: DATA,
        description: "Import a BCheck (custom_check.bcheck_import) or Bambda (bambda_import) into the running Burp by id.",
        schema: schema_of::<data::tools::ImportArgs>,
        example: r#"{"do":"data_import","id":"bchecks:examples/blind-ssrf"}"#,
        read_only: false,
        destructive: false,
    },
    LocalTool {
        name: "data_update",
        domain: DATA,
        description: "Download PortSwigger's data now (all sources or one) into ~/.raijin/data.",
        schema: schema_of::<data::tools::UpdateArgs>,
        example: r#"{"do":"data_update"}"#,
        read_only: false,
        destructive: false,
    },
];

fn local_tool(name: &str) -> Option<&'static LocalTool> {
    LOCAL_TOOLS.iter().find(|t| t.name == name)
}

fn text(value: &Value) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(value.to_string())])
}

fn plain(message: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(message.into())])
}

/// A local tool's arguments read as `T`, with `local`'s example and destructiveness for errors. A
/// data tool's `source:"all"` (any case) is read as no source.
fn local_args<T: serde::de::DeserializeOwned + JsonSchema>(
    local: &LocalTool,
    mut arguments: Option<JsonObject>,
) -> Result<(T, Vec<String>), ToolError> {
    let mut all_note = None;
    if local.domain == DATA
        && let Some(args) = arguments.as_mut()
        && args
            .get("source")
            .and_then(Value::as_str)
            .is_some_and(|s| s.trim().eq_ignore_ascii_case("all"))
    {
        args.remove("source");
        all_note = Some("read 'source' \"all\" as unset".to_owned());
    }
    let (parsed, mut notes) =
        parse_args(local.name, arguments, &local.example(), local.destructive)?;
    notes.splice(0..0, all_note);
    Ok((parsed, notes))
}

fn run_example() -> Value {
    serde_json::from_str(RUN_EXAMPLE).unwrap_or_default()
}

/// An error envelope's `retry`, `example` and `see` `run` calls with `"project"` added, so resending
/// them reaches the same Burp; any other result is returned as is.
fn with_project(mut result: CallToolResult, project: &str) -> CallToolResult {
    if result.is_error != Some(true) || result.content.len() != 1 {
        return result;
    }
    let Some(Ok(Value::Object(mut envelope))) = result.content[0]
        .as_text()
        .map(|t| serde_json::from_str::<Value>(&t.text))
    else {
        return result;
    };
    if !envelope.get("code").is_some_and(Value::is_string) {
        return result;
    }
    for key in ["retry", "example", "see"] {
        if let Some(Value::Object(call)) = envelope.get_mut(key)
            && call.contains_key("do")
        {
            call.entry("project").or_insert_with(|| json!(project));
        }
    }
    result.content[0] = ContentBlock::text(Value::Object(envelope).to_string());
    result
}

/// An error envelope's `retry` set to `call`; any other result is returned as is.
fn with_retry(mut result: CallToolResult, call: Value) -> CallToolResult {
    if result.is_error != Some(true) || result.content.len() != 1 {
        return result;
    }
    let Some(Ok(Value::Object(mut envelope))) = result.content[0]
        .as_text()
        .map(|t| serde_json::from_str::<Value>(&t.text))
    else {
        return result;
    };
    envelope.insert("retry".to_owned(), call);
    result.content[0] = ContentBlock::text(Value::Object(envelope).to_string());
    result
}

/// Reads what a `run` call holds besides the call itself, each reading noted: an empty `do`,
/// `batch` or `project` (a strict-mode client fills every property) is dropped, and without a
/// call key a pasted `see` (`{"see":{"do":"turbo_run.list"}}`) becomes the call. A pasted guide
/// call (`{"guide":{"topic":"util.hash"}}`) gives `Some` with guide's arguments, every other key
/// but `project` noted as ignored.
fn read_pasted_calls(raw: &mut JsonObject, notes: &mut Vec<String>) -> Option<JsonObject> {
    for key in ["do", "batch", "project"] {
        match raw.get(key) {
            Some(Value::Null) => {
                raw.remove(key);
            }
            Some(v) if is_empty_value(v) => {
                raw.remove(key);
                notes.push(format!("ignored empty '{key}'"));
            }
            _ => {}
        }
    }
    unwrap_call(raw, notes);
    if CALL_KEYS.iter().any(|k| raw.contains_key(*k)) {
        return None;
    }
    let guide = raw.remove("guide")?;
    let args = match guide {
        Value::Object(o) => o,
        Value::String(s) => {
            let mut o = JsonObject::new();
            o.insert("topic".to_owned(), json!(s));
            o
        }
        _ => JsonObject::new(),
    };
    notes.extend(
        raw.keys()
            .filter(|k| k.as_str() != "project")
            .map(|k| format!("ignored '{k}' next to \"guide\"")),
    );
    notes.push("ran guide; tool calls go in \"do\"".to_owned());
    Some(args)
}

/// Keys of an error envelope that hold a call, as models paste them back whole.
const PASTED_KEYS: [&str; 3] = ["retry", "see", "example"];

/// Reads a call pasted in another shape into `raw`, when `raw` names no tool ([`CALL_KEYS`]):
/// `{"retry":{...}}`, `{"see":...}` or `{"example":...}` (an object is the call, a string its
/// tool), a JSON string in `arguments` holding the call (also encoded twice), or the
/// `tool_calls`/`tool_uses` items ([`item_call`]): one is the call, more a `batch`. Keys already
/// in `raw` win. Each reading is noted.
fn unwrap_call(raw: &mut JsonObject, notes: &mut Vec<String>) {
    let names_tool = |raw: &JsonObject| CALL_KEYS.iter().any(|k| raw.contains_key(*k));
    if names_tool(raw) {
        return;
    }
    let merge = |raw: &mut JsonObject, call: JsonObject| {
        for (k, v) in call {
            raw.entry(k).or_insert(v);
        }
    };
    for key in PASTED_KEYS {
        match raw.get(key) {
            Some(Value::Object(_)) => {
                if let Some(Value::Object(call)) = raw.remove(key) {
                    merge(raw, call);
                }
            }
            Some(Value::String(s)) if !s.trim().is_empty() => {
                let tool = s.trim().to_owned();
                raw.remove(key);
                raw.insert("do".to_owned(), json!(tool));
            }
            _ => continue,
        }
        notes.push(format!("read '{key}' as the call"));
        if names_tool(raw) {
            return;
        }
    }
    if let Some(Value::String(s)) = raw.get(WRAPPER_KEY)
        && let Some((call, twice)) = json_object(s)
        && CALL_KEYS.iter().any(|k| call.contains_key(*k))
    {
        raw.remove(WRAPPER_KEY);
        merge(raw, call);
        notes.push(format!("read '{WRAPPER_KEY}' as the call"));
        if twice {
            notes.push(DOUBLE_ENCODED.to_owned());
        }
        return;
    }
    for key in ["tool_calls", "tool_uses"] {
        let Some(Value::Array(items)) = raw.get(key) else {
            continue;
        };
        let mut item_notes = Vec::new();
        let calls: Vec<JsonObject> = items
            .iter()
            .filter_map(Value::as_object)
            .filter_map(|item| item_call(item, &mut item_notes))
            .collect();
        if calls.is_empty() || calls.len() != items.len() {
            continue;
        }
        raw.remove(key);
        if let [call] = calls.as_slice() {
            merge(raw, call.clone());
            notes.push(format!("read '{key}' as the call"));
        } else {
            raw.insert("batch".to_owned(), json!(calls));
            notes.push(format!("read '{key}' as a batch"));
        }
        notes.extend(item_notes);
        return;
    }
}

/// The note for parameters sent as JSON encoded twice (`"\"{\\\"a\\\":1}\""`).
const DOUBLE_ENCODED: &str = "read 'arguments' as JSON inside a JSON string";

/// `s` parsed as a JSON object, also when it is a JSON string holding one (encoded twice); the
/// flag says the second parse was needed.
fn json_object(s: &str) -> Option<(JsonObject, bool)> {
    match serde_json::from_str::<Value>(s).ok()? {
        Value::Object(o) => Some((o, false)),
        Value::String(inner) => serde_json::from_str::<JsonObject>(&inner)
            .ok()
            .map(|o| (o, true)),
        _ => None,
    }
}

/// The call one `tool_calls`/`tool_uses` item holds (`{"function":{"name":...,"arguments":...}}`,
/// `{"recipient_name":"functions.x","parameters":...}`): `do` and its arguments. None when the
/// item names no tool.
fn item_call(item: &JsonObject, notes: &mut Vec<String>) -> Option<JsonObject> {
    let function = item.get("function").and_then(Value::as_object);
    let name = function
        .and_then(|f| f.get("name"))
        .or_else(|| item.get("recipient_name"))
        .or_else(|| item.get("name"))
        .and_then(Value::as_str)?;
    let name = error::strip_server_prefix(name).unwrap_or(name).trim();
    let args = function
        .and_then(|f| f.get("arguments"))
        .or_else(|| item.get("parameters"))
        .or_else(|| item.get("arguments"))
        .or_else(|| item.get("input"));
    let args = match args {
        Some(Value::Object(o)) => o.clone(),
        Some(Value::String(s)) => match json_object(s) {
            Some((o, twice)) => {
                if twice && !notes.iter().any(|n| n == DOUBLE_ENCODED) {
                    notes.push(DOUBLE_ENCODED.to_owned());
                }
                o
            }
            None => JsonObject::new(),
        },
        _ => JsonObject::new(),
    };
    let mut call = JsonObject::new();
    call.insert("do".to_owned(), json!(name));
    for (k, v) in args {
        call.entry(k).or_insert(v);
    }
    Some(call)
}

/// `batch` given as `kind` ("a string", "an object", ...) instead of an array.
fn batch_type_error(kind: &str, got: Value) -> CallToolResult {
    ToolError::new(
        Code::InvalidType,
        format!("'batch' must be a JSON array of {{\"do\":...}} objects, got {kind}."),
    )
    .param("batch")
    .got(got)
    .example(json!({"batch": [run_example()]}))
    .into_result()
}

/// A failed batch step's `error`, or its whole result as text.
fn failure_reason(failed: &Value) -> String {
    match failed {
        Value::String(s) => s.clone(),
        other => other
            .get("error")
            .and_then(Value::as_str)
            .map_or_else(|| other.to_string(), str::to_owned),
    }
}

/// A failed batch step's `code`, `tool_failed` when it has none.
fn failure_code(failed: &Value) -> String {
    failed
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("tool_failed")
        .to_owned()
}

/// The batch that repairs a failed one: each failed step's `retry` in order (a `retry` that is
/// itself a batch is spliced in, its `bail` kept), then the steps `bail` left unrun. None unless
/// every failed step has a `retry`; steps that succeeded are never repeated.
fn batch_retry(failures: &[(usize, Value)], not_run: &[Value], bail: bool) -> Option<Value> {
    if failures.is_empty() {
        return None;
    }
    let mut steps = Vec::new();
    let mut bail = bail;
    for (_, failed) in failures {
        let retry = failed.get("retry")?.as_object()?;
        match retry.get("batch").and_then(Value::as_array) {
            Some(inner) => {
                steps.extend(inner.iter().cloned());
                bail |= retry.get("bail").and_then(Value::as_bool) == Some(true);
            }
            None => steps.push(Value::Object(retry.clone())),
        }
    }
    steps.extend(not_run.iter().cloned());
    Some(json!({"batch": steps, "bail": bail}))
}

/// `run`'s `bail`: a boolean, also as a boolean word (`"true"`, `"yes"`, `"0"`, ...) or the integer
/// 0 or 1 (noted); absent or null is false. Anything else is refused: a batch that runs on after a
/// failure is not what `bail` asked for.
fn read_bail(value: Option<Value>) -> Result<(bool, Option<String>), ToolError> {
    match value {
        None | Some(Value::Null) => Ok((false, None)),
        Some(Value::Bool(b)) => Ok((b, None)),
        Some(Value::String(s)) if super::args::bool_word(&s).is_some() => {
            let b = super::args::bool_word(&s) == Some(true);
            Ok((
                b,
                Some(format!("coerced 'bail' from string \"{s}\" to boolean")),
            ))
        }
        Some(Value::Number(n)) if matches!(n.as_u64(), Some(0 | 1)) => Ok((
            n.as_u64() == Some(1),
            Some(format!("coerced 'bail' from {n} to boolean")),
        )),
        Some(other) => Err(ToolError::new(
            Code::InvalidType,
            format!("run: 'bail' must be true or false, got {other}."),
        )
        .param("bail")
        .got(other)
        .expected("true or false")
        .example(json!({"batch": [run_example()], "bail": true}))),
    }
}

/// `bail` taken out of every batch step, each noted: it belongs next to `batch`, so the first one
/// is the batch's (`Some`) unless `bail_given` (one was next to `batch`), and the rest are ignored.
/// A step `bail` that is no boolean is refused as [`read_bail`] refuses it.
fn take_step_bail(
    steps: &mut [Value],
    bail_given: bool,
    notes: &mut Vec<String>,
) -> Result<Option<bool>, ToolError> {
    let mut bail = None;
    for (i, step) in steps.iter_mut().enumerate() {
        let Some(step_bail) = step.as_object_mut().and_then(|s| s.remove("bail")) else {
            continue;
        };
        let n = i + 1;
        if bail_given || bail.is_some() {
            notes.push(format!(
                "ignored 'bail' in step {n}; set it once next to batch"
            ));
            continue;
        }
        let (b, note) = read_bail(Some(step_bail))?;
        notes.extend(note);
        notes.push(format!("read 'bail' from step {n} as the batch's bail"));
        bail = Some(b);
    }
    Ok(bail)
}

/// A history tool's failure as an envelope: a bad ref is `invalid_arguments`, a ref with nothing
/// behind it `not_found`, an unknown project `invalid_enum` with the known ones (and `retry` when
/// there is only one); anything else `tool_failed`.
fn history_error(tool: &str, e: &anyhow::Error, sent: &JsonObject) -> ToolError {
    let list = json!({"do": "history_list"});
    match history::Problem::of(e) {
        Some(history::Problem::BadRef(message)) => {
            let param = ["ref", "a", "b"].into_iter().find(|k| {
                sent.get(*k)
                    .and_then(Value::as_str)
                    .is_some_and(|v| message.contains(v))
            });
            let mut err = ToolError::new(Code::InvalidArguments, format!("{tool}: {message}."));
            if let Some(param) = param {
                err = err.param(param).got(sent[param].clone());
            }
            err.see(list)
        }
        Some(history::Problem::NotFound(message)) => {
            ToolError::new(Code::NotFound, format!("{tool}: {message}.")).see(list)
        }
        Some(history::Problem::BadPattern { pattern, reason }) => ToolError::new(
            Code::InvalidArguments,
            format!(
                "{tool}: 'pattern' is not a valid regex ({reason}); escape regex characters such as [ ( . * with a backslash to match them literally. {tool} uses Rust regex (no look-around); proxy_history_search accepts it on live data."
            ),
        )
        .param("pattern")
        .got(json!(pattern)),
        // The project came from a ref (`history_show`, `history_diff`): the ref is what to fix.
        Some(history::Problem::UnknownProject { wanted, known })
            if !sent.contains_key("project") =>
        {
            let prefix = format!("{wanted}:");
            let mut err = ToolError::new(
                Code::NotFound,
                format!(
                    "{tool}: no project \"{wanted}\"; refs start with one of: {}.",
                    known.join(", ")
                ),
            )
            .see(list);
            if let Some(param) = ["ref", "a", "b"].into_iter().find(|k| {
                sent.get(*k)
                    .and_then(Value::as_str)
                    .is_some_and(|v| v.starts_with(&prefix))
            }) {
                err = err.param(param).got(sent[param].clone());
            }
            err
        }
        Some(history::Problem::UnknownProject { wanted, known }) => {
            let mut err = ToolError::new(
                Code::InvalidEnum,
                if known.is_empty() {
                    format!("{tool}: no project \"{wanted}\"; history_list shows the projects.")
                } else {
                    format!(
                        "{tool}: no project \"{wanted}\"; this target has {}.",
                        known.join(", ")
                    )
                },
            )
            .param("project")
            .got(json!(wanted))
            .allowed(known.iter().map(|k| json!(k)).collect());
            if let [only] = known.as_slice()
                && sent.contains_key("project")
            {
                let mut call = Map::new();
                call.insert("do".to_owned(), json!(tool));
                call.extend(sent.clone());
                call.insert("project".to_owned(), json!(only));
                err = err.retry(Value::Object(call));
            }
            err
        }
        None => ToolError::new(Code::ToolFailed, format!("{e:#}")),
    }
}

/// Why a history tool gave no result: its arguments were refused, or the run failed (with what
/// reading the arguments changed, which the error result still reports).
enum HistoryFailure {
    Refused(ToolError),
    Failed(anyhow::Error, Vec<String>),
}

/// Runs history tool `local` on `target` (blocking: it reads every project).
fn run_history(
    target: &Target,
    local: &LocalTool,
    arguments: Option<JsonObject>,
) -> Result<(Value, Vec<String>), HistoryFailure> {
    use HistoryFailure::{Failed, Refused};
    let to_value = |v: Result<Value, serde_json::Error>| {
        v.map_err(|e| Refused(ToolError::new(Code::Internal, e.to_string())))
    };
    match local.name {
        "history_list" => {
            let (params, notes) = local_args(local, arguments).map_err(Refused)?;
            let value =
                history::list::run(target, &params).map_err(|e| Failed(e, notes.clone()))?;
            Ok((to_value(serde_json::to_value(value))?, notes))
        }
        "history_show" => {
            let (params, notes) = local_args(local, arguments).map_err(Refused)?;
            let value =
                history::show::run(target, &params).map_err(|e| Failed(e, notes.clone()))?;
            Ok((value, notes))
        }
        "history_search" => {
            let (params, notes) = local_args(local, arguments).map_err(Refused)?;
            let value =
                history::search::run(target, &params).map_err(|e| Failed(e, notes.clone()))?;
            Ok((to_value(serde_json::to_value(value))?, notes))
        }
        "history_endpoints" => {
            let (params, notes) = local_args(local, arguments).map_err(Refused)?;
            let value =
                history::endpoints::run(target, &params).map_err(|e| Failed(e, notes.clone()))?;
            Ok((to_value(serde_json::to_value(value))?, notes))
        }
        "history_diff" => {
            let (params, notes) = local_args(local, arguments).map_err(Refused)?;
            let value =
                history::diff::run(target, &params).map_err(|e| Failed(e, notes.clone()))?;
            Ok((value, notes))
        }
        _ => {
            let (params, notes) = local_args(local, arguments).map_err(Refused)?;
            let value =
                history::export::run(target, &params).map_err(|e| Failed(e, notes.clone()))?;
            Ok((value, notes))
        }
    }
}

/// [`run_history`] on a blocking thread.
async fn run_history_blocking(
    target: Arc<Target>,
    local: &'static LocalTool,
    arguments: Option<JsonObject>,
) -> Result<(Value, Vec<String>), HistoryFailure> {
    tokio::task::spawn_blocking(move || run_history(&target, local, arguments))
        .await
        .unwrap_or_else(|e| {
            Err(HistoryFailure::Refused(ToolError::new(
                Code::Internal,
                format!("{} panicked: {e}", local.name),
            )))
        })
}

/// Whether `s` is a ref without its project: `12`, `a3` (archive) or `i4` (issue).
fn is_bare_ref(s: &str) -> bool {
    let digits = s.strip_prefix(['a', 'i']).unwrap_or(s);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Bare refs among the `ref`, `a` and `b` arguments `local` declares, read as refs of the target's
/// only project (`1` -> `main:1`); one note per rewrite. Left as given when the target has none or
/// several projects: the ref error then says which to pick.
fn bare_refs(
    target: &Target,
    local: &LocalTool,
    arguments: Option<&mut JsonObject>,
) -> Vec<String> {
    let mut notes = Vec::new();
    let Some(args) = arguments else {
        return notes;
    };
    let schema = (local.schema)();
    let declared = |k: &str| {
        schema
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|p| p.contains_key(k))
    };
    let keys: Vec<&str> = ["ref", "a", "b"]
        .into_iter()
        .filter(|k| declared(k) && args.contains_key(*k))
        .collect();
    if keys.is_empty() {
        return notes;
    }
    let known = target.known_projects();
    let [project] = known.as_slice() else {
        return notes;
    };
    for key in keys {
        let given = match &args[key] {
            Value::String(s) => s.trim().to_owned(),
            Value::Number(n) if n.is_u64() => n.to_string(),
            _ => continue,
        };
        if is_bare_ref(&given) {
            let full = format!("{project}:{given}");
            notes.push(format!("read {key} \"{given}\" as \"{full}\""));
            args.insert(key.to_owned(), json!(full));
        }
    }
    notes
}

/// `sent` with project `wanted` replaced by `hit`: the `project` argument and the project part of
/// `ref`, `a` and `b`.
fn rematched_project(mut sent: JsonObject, wanted: &str, hit: &str) -> JsonObject {
    if sent.get("project").and_then(Value::as_str) == Some(wanted) {
        sent.insert("project".to_owned(), json!(hit));
    }
    let prefix = format!("{wanted}:");
    for key in ["ref", "a", "b"] {
        if let Some(rest) = sent
            .get(key)
            .and_then(Value::as_str)
            .and_then(|v| v.strip_prefix(&prefix))
        {
            let fixed = format!("{hit}:{rest}");
            sent.insert(key.to_owned(), json!(fixed));
        }
    }
    sent
}

/// The error for `run {"do":"guide"}` or `{"do":"run"}`: the gateway's own tools are not run
/// through `run`. For `guide`, `see` is the guide call to make instead, with the topic given.
fn gateway_tool_as_do(tool: &str, arguments: Option<&JsonObject>) -> Option<CallToolResult> {
    match error::norm(tool).as_str() {
        "guide" => {
            let topic = arguments
                .and_then(|a| ["topic", "name", "tool"].iter().find_map(|k| a.get(*k)))
                .and_then(Value::as_str);
            let call = topic.map_or_else(|| json!({}), |t| json!({ "topic": t }));
            Some(
                ToolError::new(
                    Code::UnknownTool,
                    format!("guide is its own tool, not a run target: call guide {call}."),
                )
                .see(json!({ "guide": call }))
                .into_result(),
            )
        }
        "run" => Some(
            ToolError::new(
                Code::InvalidArguments,
                "run is the tool you are calling: put the tool to run in \"do\", e.g. {\"do\":\"proxy_history\",\"count\":20}.",
            )
            .param("do")
            .example(run_example())
            .see(guide_call(None))
            .into_result(),
        ),
        _ => None,
    }
}

/// One tool call as `run` resolved it.
#[derive(Debug, PartialEq)]
struct Call {
    /// What `do` named: a tool, `<tool>.<action>` or an old member name.
    tool: String,
    arguments: Option<JsonObject>,
    /// The Burp to run it on, for a tool that does not take `project` itself.
    project: Option<String>,
    /// What reading the call changed (a prefix stripped, a key read as `do`), for the result.
    notes: Vec<String>,
    /// Pieces of a `tool(k: integer)` name left out (types copied from `usage`, or a suffix that
    /// could not be read): a call that writes is not made without them.
    dropped: Vec<String>,
}

/// Keys a model wraps a tool's parameters in, in the order they are tried.
const ARGUMENT_KEYS: [&str; 5] = ["arguments", "args", "params", "parameters", "input"];

/// The wrapper key that is never a parameter name: a value that is not an object is an error.
const WRAPPER_KEY: &str = "arguments";

/// Keys that name the tool when `do` is absent, in the order they are tried (string values only).
const NAMING_KEYS: [&str; 4] = ["tool", "name", "tool_name", "function"];

/// Keys that mark a `run` call as one call rather than a batch.
const CALL_KEYS: [&str; 6] = ["do", "tool", "name", "tool_name", "function", "batch"];

/// The tool named by `raw` without `do`: a string [`NAMING_KEYS`] value, an `OpenAI` function call
/// (`{"function":{"name":..., "arguments":...}}`, its arguments merged under flat keys), or an
/// `action` that names a tool (`names_tool`). The key is removed from `raw`; the reading is noted.
fn named_without_do(
    raw: &mut JsonObject,
    names_tool: &impl Fn(&str) -> bool,
    notes: &mut Vec<String>,
) -> Option<Value> {
    if let Some(key) = NAMING_KEYS
        .into_iter()
        .find(|k| raw.get(*k).is_some_and(Value::is_string))
    {
        notes.push(format!("read '{key}' as 'do'"));
        return raw.remove(key);
    }
    if let Some(Value::Object(function)) = raw.get("function")
        && function.get("name").is_some_and(Value::is_string)
    {
        let Some(Value::Object(mut function)) = raw.remove("function") else {
            return None;
        };
        let name = function.remove("name").unwrap_or_default();
        let arguments = match function.remove("arguments") {
            Some(Value::Object(o)) => Some(o),
            Some(Value::String(s)) => serde_json::from_str::<JsonObject>(&s).ok(),
            _ => None,
        };
        for (k, v) in arguments.unwrap_or_default() {
            raw.entry(k).or_insert(v);
        }
        if raw.get("type").and_then(Value::as_str) == Some("function") {
            raw.remove("type");
        }
        notes.push(format!(
            "read OpenAI function call '{}'",
            name.as_str().unwrap_or_default()
        ));
        return Some(name);
    }
    if let Some(Value::String(action)) = raw.get("action")
        && names_tool(action)
    {
        notes.push("read 'action' as 'do'".to_owned());
        return raw.remove("action");
    }
    None
}

/// The `k=v` arguments of a `tool(k=v, ...)` name, in order.
type SuffixArgs = Vec<(String, Value)>;

/// Whether `v` is a type `usage` prints (`integer`, `integer ≥ 0`, `list of string`,
/// `"MD5"|"SHA-256"`, `true or false`) rather than a value.
fn is_type_words(v: &str) -> bool {
    const TYPES: [&str; 9] = [
        "string",
        "integer",
        "number",
        "boolean",
        "object",
        "array",
        "true or false",
        "any value",
        "values",
    ];
    let v = v.trim();
    if v.contains('|')
        && v.split('|').all(|p| {
            let p = p.trim();
            p.len() >= 2 && p.starts_with('"') && p.ends_with('"')
        })
    {
        return true;
    }
    let l = v.to_lowercase();
    TYPES.contains(&l.as_str())
        || l.starts_with("list of ")
        || l.starts_with("integer ≥")
        || l.starts_with("one of ")
        || (l.contains(" or ")
            && l.split(" or ")
                .all(|p| TYPES.contains(&p.trim()) || p.trim().starts_with("list of ")))
}

/// `k=v, k: v, k*: v` pieces (a `tool(...)` suffix, or the text after `tool `) read as arguments:
/// the key without a trailing `*`, each value as JSON, else as text without surrounding quotes.
/// A value that is a type copied from `usage` (`limit: integer`) is dropped and returned as
/// `k: v`. Pieces are split at commas outside quotes, so `data: "a,b"` stays whole. The arguments
/// are None when a piece cannot be read whole: a quote left open, or a piece without a key
/// (`a=1,2` cut at the comma): reading the rest would send a cut value.
fn piece_args(body: &str) -> (Option<SuffixArgs>, Vec<String>) {
    let Some(pieces) = split_unquoted(body) else {
        return (None, Vec::new());
    };
    read_pieces(pieces.into_iter().filter(|p| !p.trim().is_empty()))
}

/// `text` split at the commas outside `"..."` and `'...'`; None when a quote is left open.
fn split_unquoted(text: &str) -> Option<Vec<&str>> {
    let mut pieces = Vec::new();
    let mut quote: Option<char> = None;
    let mut start = 0;
    for (i, c) in text.char_indices() {
        match quote {
            Some(q) if c == q => quote = None,
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == ',' => {
                pieces.push(&text[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if quote.is_some() {
        return None;
    }
    pieces.push(&text[start..]);
    Some(pieces)
}

/// Whether `k` is a parameter name: a letter or `_`, then letters, digits and `_`.
fn is_param_key(k: &str) -> bool {
    let mut chars = k.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `pieces`, each `k=v` or `k: v`, read as [`piece_args`] says; None when one has no key.
fn read_pieces<'a>(pieces: impl Iterator<Item = &'a str>) -> (Option<SuffixArgs>, Vec<String>) {
    let mut args = Vec::new();
    let mut dropped = Vec::new();
    for piece in pieces {
        let Some(at) = piece.find(['=', ':']) else {
            return (None, Vec::new());
        };
        let k = piece[..at].trim().trim_end_matches('*').trim();
        let v = piece[at + 1..].trim();
        // `https://a.com` is a bare value, not `https: //a.com`.
        if !is_param_key(k) || (piece.as_bytes()[at] == b':' && v.starts_with("//")) {
            return (None, Vec::new());
        }
        if is_type_words(v) {
            dropped.push(format!("{k}: {v}"));
            continue;
        }
        let value = serde_json::from_str::<Value>(v).unwrap_or_else(|_| {
            let unquoted = v
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .or_else(|| v.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
                .unwrap_or(v);
            json!(unquoted)
        });
        args.push((k.to_owned(), value));
    }
    (Some(args), dropped)
}

/// Byte offsets in `text` where a `key=` or `key:` token starts: at the start or after
/// whitespace, outside quotes, and not a URL scheme (`https://`).
fn key_starts(text: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut quote: Option<char> = None;
    let mut prev_space = true;
    for (i, c) in text.char_indices() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
        } else if c == '"' || c == '\'' {
            quote = Some(c);
        } else if prev_space && (c.is_ascii_alphabetic() || c == '_') {
            let rest = &text[i..];
            let end = rest
                .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
                .unwrap_or(rest.len());
            let after = rest[end..].trim_start_matches('*').trim_start();
            if after.starts_with('=') || (after.starts_with(':') && !after[1..].starts_with("//")) {
                starts.push(i);
            }
        }
        prev_space = c.is_whitespace();
    }
    starts
}

/// `tool(k=v, ...)`, `tool(k: v, ...)` or `tool({...})` split into the tool, its arguments
/// ([`piece_args`]; a JSON object gives them all) and the pieces dropped as types. None when
/// `tool` has no parenthesised suffix.
fn parenthesised(tool: &str) -> Option<(String, Option<SuffixArgs>, Vec<String>)> {
    let t = tool.trim();
    let inner = t.strip_suffix(')')?;
    let open = inner.find('(')?;
    let name = inner[..open].trim();
    if name.is_empty() || name.contains(char::is_whitespace) || name.contains(')') {
        return None;
    }
    let body = inner[open + 1..].trim();
    if body.starts_with('{') {
        let args = serde_json::from_str::<JsonObject>(body)
            .ok()
            .map(|o| o.into_iter().collect());
        return Some((name.to_owned(), args, Vec::new()));
    }
    let (args, dropped) = piece_args(body);
    Some((name.to_owned(), args, dropped))
}

/// `tool k=v k2: v2 ...` (a name, a space, then pieces that each start with `key=` or `key:`)
/// split like [`parenthesised`]; a value runs to the next key, so it may hold spaces and commas
/// (a trailing `,` between pieces is dropped). None unless the text after the name starts with a
/// key.
fn spaced(tool: &str) -> Option<(String, Option<SuffixArgs>, Vec<String>)> {
    let (name, rest) = tool.trim().split_once(char::is_whitespace)?;
    let rest = rest.trim();
    if name.contains(['(', ')', '=', ':']) {
        return None;
    }
    let mut starts = key_starts(rest);
    if starts.first() != Some(&0) {
        return None;
    }
    starts.push(rest.len());
    let pieces = starts
        .windows(2)
        .map(|w| rest[w[0]..w[1]].trim().trim_end_matches(',').trim_end());
    let (args, dropped) = read_pieces(pieces);
    Some((name.to_owned(), args, dropped))
}

/// What names the tool of a `run` call, removed from `raw`: `do`, else [`named_without_do`]. A
/// whole call in `do` (`"{\"do\":\"history_list\",\"limit\":1}"`, or the object itself) gives its
/// `do`, and its other keys join `raw` where `raw` lacks them. Each reading is noted.
fn named_tool(
    raw: &mut JsonObject,
    names_tool: &impl Fn(&str) -> bool,
    notes: &mut Vec<String>,
) -> Option<Value> {
    let mut named = match raw.remove("do") {
        Some(Value::Object(call)) => {
            notes.push("read 'do' as a call object".to_owned());
            Some(Value::Object(call))
        }
        Some(value) => Some(value),
        None => named_without_do(raw, names_tool, notes),
    };
    if let Some(Value::String(s)) = &named
        && s.trim_start().starts_with('{')
        && let Ok(call) = serde_json::from_str::<JsonObject>(s)
    {
        notes.push("read 'do' as a JSON call".to_owned());
        named = Some(Value::Object(call));
    }
    let Some(Value::Object(inner)) = &mut named else {
        return named;
    };
    if !inner.contains_key("do") {
        return named;
    }
    let mut tool = None;
    for (k, v) in std::mem::take(inner) {
        if k == "do" {
            tool = Some(v);
        } else {
            raw.entry(k).or_insert(v);
        }
    }
    tool
}

/// `tool` without a `(k=v, ...)` or ` k=v` suffix ([`parenthesised`], [`spaced`]), its arguments
/// added to `raw` where `raw` lacks them, and the pieces dropped as types; each reading noted.
fn suffix_args(
    tool: String,
    raw: &mut JsonObject,
    notes: &mut Vec<String>,
) -> (String, Vec<String>) {
    let Some((name, args, mut dropped)) = parenthesised(&tool).or_else(|| spaced(&tool)) else {
        return (tool, Vec::new());
    };
    let mut later = Vec::new();
    let with = match args {
        None => {
            // Left out whole: a call that writes is not made without them.
            let suffix = tool[name.len()..].trim().to_owned();
            later.push(format!(
                "'{suffix}': its arguments were not read (a quote left open or a piece without a key); pass them as keys next to \"do\""
            ));
            dropped.push(suffix);
            String::new()
        }
        Some(args) => {
            let mut read = Vec::new();
            for (k, v) in args {
                match raw.get(&k) {
                    None => {
                        read.push(k.clone());
                        raw.insert(k, v);
                    }
                    Some(top) if *top != v => {
                        later.push(format!("'{k}' given twice; used the top-level {top}"));
                    }
                    Some(_) => {}
                }
            }
            later.extend(
                dropped
                    .iter()
                    .map(|piece| format!("dropped '{piece}': a type from usage, not a value")),
            );
            if read.is_empty() {
                String::new()
            } else {
                format!(" with {}", read.join(", "))
            }
        }
    };
    notes.push(format!("read '{tool}' as {name}{with}"));
    notes.extend(later);
    (name, dropped)
}

/// `tool` without surrounding quotes (`` `history_list` ``) and a server prefix (`mcp__raijin__`),
/// each reading noted.
fn bare_tool_name(tool: String, notes: &mut Vec<String>) -> String {
    let mut tool = tool;
    if let Some(inner) = error::unquote(&tool) {
        let inner = inner.trim().to_owned();
        notes.push(format!("read '{tool}' as {inner}"));
        tool = inner;
    }
    if let Some(stripped) = error::strip_server_prefix(&tool) {
        let stripped = stripped.trim().to_owned();
        notes.push(format!("read '{tool}' as {stripped}"));
        tool = stripped;
    }
    tool
}

/// Reads a `run` call: `do` (else a [`NAMING_KEYS`] string, an `OpenAI` function call, or an
/// `action` that `names_tool`) names the tool, without a server prefix (`mcp__raijin__`) and with
/// a `(k=v, ...)` suffix read as arguments. `project` picks the Burp unless the tool takes a
/// `project` itself, a wrapper object (`arguments`, `args`, ..., also as a JSON string) is
/// unwrapped unless the tool declares that key (`declares(tool, key)`), and every other key is a
/// parameter of the tool. Keys already flat win over wrapped ones. A wrapper key other than
/// `arguments` holding a non-object (`"input":"x"`) stays a parameter. Every reading is noted.
fn normalize_run(
    mut raw: JsonObject,
    declares: impl Fn(&str, &str) -> bool,
    names_tool: impl Fn(&str) -> bool,
) -> Result<Call, ToolError> {
    let mut notes = Vec::new();
    // A strict-mode client fills `project` even when it has none.
    match raw.get("project") {
        Some(Value::Null) => {
            raw.remove("project");
        }
        Some(Value::String(p)) if p.trim().is_empty() => {
            raw.remove("project");
            notes.push("ignored empty 'project'".to_owned());
        }
        _ => {}
    }
    // JSON cut or mistyped: reading it as a tool name would only say the tool is unknown.
    for key in ["do", WRAPPER_KEY] {
        if let Some(Value::String(s)) = raw.get(key)
            && s.trim_start().starts_with(['{', '['])
            && let Err(e) = serde_json::from_str::<Value>(s)
        {
            return Err(ToolError::new(
                Code::InvalidArguments,
                format!("'{key}' is not valid JSON ({e})."),
            )
            .param(key)
            .got(json!(s))
            .example(run_example()));
        }
    }
    let mut tool = match named_tool(&mut raw, &names_tool, &mut notes) {
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_owned(),
        None | Some(Value::Null | Value::String(_)) => {
            return Err(ToolError::new(Code::MissingParameter, MISSING_DO)
                .param("do")
                .example(run_example())
                .see(guide_call(None)));
        }
        Some(other) => {
            return Err(ToolError::new(
                Code::InvalidType,
                format!(
                    "run: 'do' must be a tool name string such as \"proxy_history\", got {other}."
                ),
            )
            .param("do")
            .got(other)
            .expected("string")
            .example(run_example())
            .see(guide_call(None)));
        }
    };
    tool = bare_tool_name(tool, &mut notes);
    let (tool, dropped) = suffix_args(tool, &mut raw, &mut notes);
    let project = if declares(&tool, "project") {
        None
    } else {
        match raw.remove("project") {
            Some(Value::String(p)) => Some(p),
            _ => None,
        }
    };
    if let Some(key) = ARGUMENT_KEYS
        .into_iter()
        .find(|k| raw.contains_key(*k) && !declares(&tool, k))
    {
        let wrapped = match &raw[key] {
            Value::Object(o) => Some((o.clone(), false)),
            Value::String(s) => json_object(s),
            _ => None,
        };
        match wrapped {
            Some((wrapped, twice)) => {
                raw.remove(key);
                notes.push(format!("read the parameters inside '{key}'"));
                if twice {
                    notes.push(DOUBLE_ENCODED.to_owned());
                }
                for (k, v) in wrapped {
                    raw.entry(k).or_insert(v);
                }
            }
            // `input`, `params`, ... holding a value is a parameter under another tool's name
            // (`input` for `data`): the tool's parameter check names the one it means.
            None if key != WRAPPER_KEY => {}
            None => {
                let value = raw.remove(key).unwrap_or_default();
                return Err(ToolError::new(
                    Code::InvalidType,
                    format!(
                        "run: '{key}' must be a JSON object of the tool's parameters, or leave it out and put the parameters next to \"do\"."
                    ),
                )
                .param(key)
                .got(value));
            }
        }
    }
    Ok(Call {
        tool,
        arguments: (!raw.is_empty()).then_some(raw),
        project,
        notes,
        dropped,
    })
}

/// Whether `name` is a tool `run` can run: a local tool (in any case or separators) or a name the
/// catalog resolves.
fn names_a_tool(catalog: Option<&Catalog>, name: &str) -> bool {
    local_tool(name).is_some()
        || local_tool(&error::norm(name)).is_some()
        || catalog
            .is_some_and(|c| !matches!(c.resolve_call(name), catalog::Resolved::NotFound { .. }))
}

/// Whether `tool` (a local tool, or a catalog tool or alias) declares parameter `key`.
fn tool_declares(catalog: Option<&Catalog>, tool: &str, key: &str) -> bool {
    let has = |schema: &Value| {
        schema
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|p| p.contains_key(key))
    };
    let normed = error::norm(tool);
    if let Some(local) = local_tool(tool.trim()).or_else(|| local_tool(&normed)) {
        return has(&Value::Object((local.schema)()));
    }
    catalog
        .and_then(|c| c.tool(&c.resolve(tool)?.0))
        .is_some_and(|spec| has(&spec.input_schema))
}

/// The text blocks of `result` joined, as JSON when they parse, else as a string.
fn result_value(result: &CallToolResult) -> Value {
    let joined: String = result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
        .collect::<Vec<_>>()
        .join("\n");
    serde_json::from_str(&joined).unwrap_or(Value::String(joined))
}

/// The `code` of an error result's envelope.
fn result_code(result: &CallToolResult) -> Option<String> {
    if result.is_error != Some(true) {
        return None;
    }
    result_value(result)
        .get("code")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The schema a call of `hit` (a local tool, catalog tool or `tool.action`) is checked against,
/// when `hit` names one exactly and the call removes or stops nothing.
fn safe_call_schema(catalog: &Catalog, hit: &str) -> Option<JsonObject> {
    if let Some(local) = local_tool(hit) {
        return (!local.destructive).then(|| (local.schema)());
    }
    let (name, action) = catalog.resolve(hit)?;
    if catalog.destructive(&name, action.as_deref()) {
        return None;
    }
    let spec = catalog.tool(&name)?;
    match action {
        _ if spec.actions.is_empty() => spec.input_schema.as_object().cloned(),
        Some(action) => Some(narrowed_action(
            &spec.input_schema,
            spec.actions.get(&action)?,
        )),
        None => None,
    }
}

/// `unknown_tool` for `tool`: up to three call names by intent ([`suggest_call`]) in
/// `did_you_mean`, and `retry` only when one is certain (the single hit within edit distance 2 or
/// contained in `tool`, or the only hit saying the same words) and not `tool` itself, names one
/// call exactly (an action for a grouped tool), removes or stops nothing, and takes `arguments` as
/// they are.
fn unknown_tool_error(catalog: &Catalog, tool: &str, arguments: &JsonObject) -> ToolError {
    let mut names = catalog.suggestion_names();
    names.extend(LOCAL_TOOLS.iter().map(|t| t.name.to_owned()));
    let found = suggest_call(tool, names.iter().map(String::as_str), 3);
    let mut hits: Vec<String> = found.iter().map(|s| s.name.to_owned()).collect();
    // The calls doing what the name's verb says (`remove_bcheck`) lead.
    let by_verb = verb_calls(tool, hits.iter().map(String::as_str), hits.len());
    let by_verb: Vec<String> = by_verb.into_iter().map(str::to_owned).collect();
    hits.sort_by_key(|h| by_verb.iter().position(|v| v == h).unwrap_or(usize::MAX));
    let w = error::norm(tool);
    let near = match found.as_slice() {
        [only] => {
            let h = error::norm(only.name);
            edit_distance(&w, &h) <= 2 || (w.contains(&h) && contains_near(&w, &h))
        }
        _ => false,
    };
    let same_words = found.first().is_some_and(|s| s.same_words)
        && found.iter().filter(|s| s.same_words).count() == 1;
    let certain = found.first().map(|s| s.name).filter(|_| near || same_words);
    if let Some(hit) = certain
        && hit != tool.trim()
        && is_destructive(catalog, hit)
    {
        return ToolError::new(
            Code::UnknownTool,
            format!("unknown tool \"{tool}\"; did you mean {hit}? {DESTRUCTIVE_EXACT}"),
        )
        .did_you_mean(hits)
        .see(guide_call(Some(hit)));
    }
    // Words that say what the model wants (`xss.find`, `burp_start`), when no tool is near.
    if certain.is_none()
        && let Some(intent) = intent_call(tool)
    {
        return intent_error(catalog, tool, arguments, &intent, hits);
    }
    if hits.is_empty() {
        return no_tool_error(catalog, tool);
    }
    let mut err = ToolError::new(
        Code::UnknownTool,
        format!("unknown tool \"{tool}\"; guide {{}} lists every tool."),
    )
    .see(guide_call(None));
    // The same name (an extension older than the catalog lacks it) would only fail again.
    if let Some(hit) = certain
        && error::norm(hit) != w
        && let Some(schema) = safe_call_schema(catalog, hit)
        && call_fits(&schema, arguments)
    {
        let mut call = Map::new();
        call.insert("do".to_owned(), json!(hit));
        call.extend(arguments.clone());
        err = err.retry(Value::Object(call));
    }
    hits.truncate(MAX_SUGGESTED);
    err.did_you_mean(hits)
}

/// Most names an `unknown_tool` error suggests.
const MAX_SUGGESTED: usize = 5;

/// Whether `name` (a local tool, catalog tool or `tool.action`) removes or stops something.
fn is_destructive(catalog: &Catalog, name: &str) -> bool {
    local_tool(name).map_or_else(
        || {
            catalog
                .resolve(name)
                .is_some_and(|(tool, action)| catalog.destructive(&tool, action.as_deref()))
        },
        |local| local.destructive,
    )
}

/// The domain `name` (a local tool, catalog tool or `tool.action`) belongs to.
fn domain_of_call(catalog: &Catalog, name: &str) -> Option<String> {
    if let Some(local) = local_tool(name) {
        return Some(local.domain.to_owned());
    }
    let (tool, _) = catalog.resolve(name)?;
    catalog.domain_of(&tool).map(|d| d.name.clone())
}

/// `unknown_tool` for a name whose words say what it wants ([`intent_call`]): the intended call
/// first in `did_you_mean`, then the near names; `retry` with its arguments when it is certain,
/// removes or stops nothing and takes `arguments`; `see` is its domain.
fn intent_error(
    catalog: &Catalog,
    tool: &str,
    arguments: &JsonObject,
    intent: &Intent,
    hits: Vec<String>,
) -> ToolError {
    let first = intent.names[0];
    let mut names: Vec<String> = intent.names.iter().map(|n| (*n).to_owned()).collect();
    for hit in hits {
        if !names.contains(&hit) {
            names.push(hit);
        }
    }
    names.truncate(MAX_SUGGESTED);
    let with = if intent.args.is_empty() {
        String::new()
    } else {
        format!(" with {}", Value::Object(intent.args.clone()))
    };
    let mut err = ToolError::new(
        Code::UnknownTool,
        format!("unknown tool \"{tool}\". Did you mean {first}{with}?"),
    )
    .did_you_mean(names);
    let domain = domain_of_call(catalog, first);
    err = err.see(guide_call(domain.as_deref()));
    if intent.certain
        && let Some(schema) = safe_call_schema(catalog, first)
    {
        let mut args = intent.args.clone();
        args.extend(arguments.clone());
        if call_fits(&schema, &args) {
            let mut call = Map::new();
            call.insert("do".to_owned(), json!(first));
            call.extend(args);
            err = err.retry(Value::Object(call));
        }
    }
    err
}

/// Every domain `guide` knows: the catalog's, then the CLI's own.
fn domain_names(catalog: &Catalog) -> Vec<String> {
    let mut domains: Vec<String> = catalog.domains.iter().map(|d| d.name.clone()).collect();
    domains.extend([LIFECYCLE, HISTORY, DATA].map(str::to_owned));
    domains
}

/// The rest of `topic` after a leading `"<domain>."` (`analysis.util.hash` -> `util.hash`), when
/// its first segment names one of `domains` (in any case).
fn strip_domain<'a>(topic: &'a str, domains: &[String]) -> Option<&'a str> {
    let (first, rest) = topic.split_once('.')?;
    (!rest.is_empty() && domains.iter().any(|d| d.eq_ignore_ascii_case(first))).then_some(rest)
}

/// The tools `guide` lists under `domain`: the catalog's, then the CLI's own.
fn domain_tools(catalog: &Catalog, domain: &str) -> Vec<String> {
    let mut tools: Vec<String> = catalog
        .domains
        .iter()
        .filter(|d| d.name == domain)
        .flat_map(|d| d.tools.iter().cloned())
        .collect();
    tools.extend(
        LOCAL_TOOLS
            .iter()
            .filter(|t| t.domain == domain)
            .map(|t| t.name.to_owned()),
    );
    tools
}

/// Nouns of a call name and the domain whose tools handle them, for an `unknown_tool` no tool or
/// domain name is near.
const NOUN_DOMAINS: &[(&str, &str)] = &[
    ("scope", "settings"),
    ("settings", "settings"),
    ("setting", "settings"),
    ("config", "settings"),
    ("finding", "findings"),
    ("findings", "findings"),
    ("issue", "findings"),
    ("issues", "findings"),
    ("cookie", "http"),
    ("cookies", "http"),
    ("request", "http"),
    ("requests", "http"),
    ("http", "http"),
    ("history", HISTORY),
];

/// `unknown_tool` for a name nothing is near: the domains to look in, `see` the nearest one (by
/// name, else by a noun of the name, else `guide {}`). A name led by a domain (`data.library.get`)
/// gets that domain's tools; one holding an action verb (`send_payload`) the calls of that verb.
fn no_tool_error(catalog: &Catalog, tool: &str) -> ToolError {
    let domains = domain_names(catalog);
    if let Some(rest) = strip_domain(tool.trim(), &domains) {
        let first = tool.trim().split('.').next().unwrap_or_default();
        let domain = domains
            .iter()
            .find(|d| d.eq_ignore_ascii_case(first))
            .cloned()
            .unwrap_or_default();
        let tools = domain_tools(catalog, &domain);
        let mut names: Vec<String> =
            suggest_call(rest, tools.iter().map(String::as_str), MAX_SUGGESTED)
                .into_iter()
                .map(|s| s.name.to_owned())
                .collect();
        for t in &tools {
            if !names.contains(t) {
                names.push(t.clone());
            }
        }
        names.truncate(MAX_SUGGESTED);
        return ToolError::new(
            Code::UnknownTool,
            format!(
                "unknown tool \"{tool}\": the domain {domain} has no such tool; guide {{\"topic\":\"{domain}\"}} lists its tools."
            ),
        )
        .did_you_mean(names)
        .see(guide_call(Some(&domain)));
    }
    let tokens: Vec<String> = error::norm(tool)
        .split('_')
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect();
    let nearest = suggest(tool, domains.iter().map(String::as_str), 1)
        .first()
        .map(|d| (*d).to_owned())
        .or_else(|| {
            tokens.iter().find_map(|t| {
                NOUN_DOMAINS
                    .iter()
                    .find(|(noun, domain)| noun == t && domains.iter().any(|d| d == domain))
                    .map(|(_, domain)| (*domain).to_owned())
            })
        });
    let mut names = catalog.suggestion_names();
    names.extend(LOCAL_TOOLS.iter().map(|t| t.name.to_owned()));
    let by_verb: Vec<String> = verb_calls(tool, names.iter().map(String::as_str), MAX_SUGGESTED)
        .into_iter()
        .map(str::to_owned)
        .collect();
    let listed: Vec<String> = domains
        .iter()
        .map(|d| {
            if d == DATA {
                format!("{DATA} (XSS/SSRF payloads, BChecks)")
            } else {
                d.clone()
            }
        })
        .collect();
    ToolError::new(
        Code::UnknownTool,
        format!(
            "unknown tool \"{tool}\". Domains: {}; call guide {{\"topic\":\"<domain>\"}}.",
            listed.join(", ")
        ),
    )
    .did_you_mean(by_verb)
    .see(guide_call(nearest.as_deref()))
}

/// `inputSchema.properties.action.enum` of a schema: a grouped tool's actions.
fn actions_of(schema: &Value) -> Vec<String> {
    schema
        .pointer("/properties/action/enum")
        .and_then(Value::as_array)
        .map_or_default(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
}

/// The first line of `description`, cut at [`SUMMARY_BYTES`].
fn summary(description: &str) -> String {
    truncate_utf8(
        description.lines().next().unwrap_or_default(),
        SUMMARY_BYTES,
    )
    .to_owned()
}

/// What `guide` and the domain listings know about one tool, live or from the catalog.
struct ToolView {
    description: String,
    schema: Value,
    annotations: Option<Value>,
}

impl ToolView {
    fn live(tool: &Tool) -> Self {
        Self {
            description: tool.description.as_deref().unwrap_or_default().to_owned(),
            schema: Value::Object((*tool.input_schema).clone()),
            annotations: tool.annotations.as_ref().map(|a| json!(a)),
        }
    }

    fn spec(spec: &ToolSpec) -> Self {
        Self {
            description: spec.description.clone().unwrap_or_default(),
            schema: spec.input_schema.clone(),
            annotations: spec.annotations.clone(),
        }
    }

    fn local(tool: &LocalTool) -> Self {
        Self {
            description: tool.description.to_owned(),
            schema: Value::Object((tool.schema)()),
            annotations: Some(tool.annotations()),
        }
    }

    /// One row of a domain listing.
    fn listing(&self, name: &str) -> Value {
        let mut out = json!({"name": name, "summary": summary(&self.description)});
        let actions = actions_of(&self.schema);
        if !actions.is_empty() {
            out["actions"] = json!(actions);
        }
        if let Some(annotations) = &self.annotations {
            out["annotations"] = annotations.clone();
        }
        out
    }
}

fn state_name(state: instance::State) -> &'static str {
    match state {
        instance::State::Stopped => "stopped",
        instance::State::Starting => "starting",
        instance::State::Running => "running",
    }
}

pub struct Gateway {
    target: Option<Arc<Target>>,
    target_error: Option<String>,
    remote: Option<Remote>,
    surface: Surface,
    inline_limit: usize,
    assets: OnceCell<Result<Arc<Assets>, String>>,
    api: ToolApi,
    /// Projects whose "is running; data may be incomplete" warning this session already gave.
    warned_live: std::sync::Mutex<BTreeSet<String>>,
    /// `~/.raijin/data`: `PortSwigger`'s data, shared by every target.
    data_root: Option<PathBuf>,
    /// Whether data calls download missing and stale sources ([`store::AUTO_UPDATE_ENV`]).
    data_auto_update: bool,
    /// Whether this session already checked for missing and stale sources.
    data_checked: tokio::sync::Mutex<bool>,
    /// The parsed upstream data, with the manifest stamps it was read at.
    data_cache: std::sync::Mutex<Option<DataCache>>,
}

/// Parsed upstream data and the [`store::stamp`] it was read at.
type DataCache = (Vec<(data::Source, u64)>, Arc<data::Library>);

/// `value`'s `warnings` without the live-project warning ([`history::source::LIVE_INCOMPLETE`]) of
/// a project already in `seen`; a project whose warning is kept is added to `seen`. Other warnings
/// stay, and an empty array stays `[]`.
fn drop_repeated_live_warnings(value: &mut Value, seen: &mut BTreeSet<String>) {
    let Some(Value::Array(warnings)) = value.get_mut("warnings") else {
        return;
    };
    warnings.retain(|w| {
        let live = w
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|e| e.ends_with(history::source::LIVE_INCOMPLETE));
        let Some(project) = w.get("project").and_then(Value::as_str) else {
            return true;
        };
        !live || seen.insert(project.to_owned())
    });
}

pub async fn serve(surface: Surface, remote_flag: Option<String>) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let (target, target_error) = match Target::discover_or_init(&cwd) {
        Ok(t) => (Some(Arc::new(t)), None),
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    let configured = target.as_ref().and_then(|t| t.config.remote.clone());
    let remote = match remote_flag {
        Some(url) => Some(Remote {
            url,
            token_env: configured.and_then(|r| r.token_env),
        }),
        None => configured,
    };
    let inline_kb = target
        .as_ref()
        .map_or(crate::config::Mcp::default().inline_limit_kb, |t| {
            t.config.mcp.inline_limit_kb
        });
    let gateway = Gateway {
        target,
        target_error,
        remote,
        surface,
        inline_limit: usize::try_from(inline_kb.saturating_mul(1024)).unwrap_or(usize::MAX),
        assets: OnceCell::new(),
        api: ToolApi::new(),
        warned_live: std::sync::Mutex::default(),
        data_root: crate::config::user_data_dir().ok(),
        data_auto_update: store::auto_update(),
        data_checked: tokio::sync::Mutex::new(false),
        data_cache: std::sync::Mutex::default(),
    };
    let service = gateway
        .serve((stdin::repaired_stdin(), tokio::io::stdout()))
        .await?;
    service.waiting().await?;
    Ok(())
}

impl Gateway {
    fn target(&self) -> Result<&Arc<Target>, String> {
        self.target.as_ref().ok_or_else(|| {
            self.target_error
                .clone()
                .unwrap_or_else(|| "no target".to_owned())
        })
    }

    async fn assets(&self) -> Result<Arc<Assets>, String> {
        self.assets
            .get_or_init(|| async {
                let jar = jar::resolve(self.target.as_deref())
                    .await
                    .map_err(|e| format!("{e:#}"))?;
                let jar_path = jar.clone();
                tokio::task::spawn_blocking(move || jar::read_assets(&jar_path))
                    .await
                    .map_err(|e| e.to_string())?
                    .map(Arc::new)
                    .map_err(|e| format!("{e:#}"))
            })
            .await
            .clone()
    }

    fn spill_dir(&self) -> PathBuf {
        match &self.target {
            Some(t) => t.state_dir().join("tool-results"),
            None => user_state_dir()
                .unwrap_or_else(|_| PathBuf::from(".raijin"))
                .join("tool-results"),
        }
    }

    fn spill(&self, result: CallToolResult, tool: &str) -> CallToolResult {
        spill::apply(result, tool, self.inline_limit, &self.spill_dir())
    }

    fn instructions(&self) -> String {
        let middle = if self.remote.is_some() {
            INSTRUCTIONS_REMOTE
        } else {
            INSTRUCTIONS_LOCAL
        };
        format!("{INSTRUCTIONS_HEAD}{middle}{INSTRUCTIONS_TAIL}")
    }

    fn lifecycle_tools(&self) -> Vec<&'static LocalTool> {
        LOCAL_TOOLS
            .iter()
            .filter(|t| t.domain == LIFECYCLE && (self.remote.is_none() || t.name == "burp_status"))
            .collect()
    }

    /// Where forwarded calls go: the remote, else the named running project, else the only
    /// running one, else the default project if running.
    async fn endpoint(&self, project: Option<&str>) -> Result<Endpoint, ToolError> {
        if let Some(remote) = &self.remote {
            let token = match &remote.token_env {
                Some(var) => Some(std::env::var(var).map_err(|_| {
                    ToolError::new(
                        Code::ConfigError,
                        format!("environment variable {var} ([remote] token_env) is not set."),
                    )
                })?),
                None => None,
            };
            return Ok(Endpoint {
                url: remote.url.clone(),
                token,
            });
        }
        let target = self.target_or_error()?;
        let statuses = instance::status_all(target)
            .await
            .map_err(|e| ToolError::new(Code::ToolFailed, format!("{e:#}")))?;
        let running: Vec<&instance::Status> = statuses
            .iter()
            .filter(|s| s.state == instance::State::Running)
            .collect();
        let pick =
            |s: &instance::Status| s.mcp_url.clone().map(|url| Endpoint { url, token: None });
        if let Some(project) = project {
            return running
                .iter()
                .find(|s| s.project == project)
                .and_then(|s| pick(s))
                .ok_or_else(|| {
                    ToolError::new(
                        Code::ProjectNotRunning,
                        format!(
                            "project {project} is not running; start it with {{\"do\":\"burp_up\",\"project\":\"{project}\"}}, then resend."
                        ),
                    )
                    .example(json!({"do": "burp_up", "project": project}))
                });
        }
        match running.as_slice() {
            [] => Err(ToolError::new(
                Code::BurpNotRunning,
                "no Burp running for this target; run {\"do\":\"burp_up\"} first, then resend this call.",
            )
            .example(json!({"do": "burp_up"}))),
            [only] => pick(only).ok_or_else(|| {
                ToolError::new(Code::Internal, "running instance has no MCP URL.")
            }),
            several => several
                .iter()
                .find(|s| s.project == target.config.default_project)
                .and_then(|s| pick(s))
                .ok_or_else(|| {
                    let names: Vec<&str> = several.iter().map(|s| s.project.as_str()).collect();
                    ToolError::new(
                        Code::ProjectRequired,
                        format!(
                            "several projects running ({}); add \"project\":\"<name>\" next to \"do\".",
                            names.join(", ")
                        ),
                    )
                    .allowed(names.iter().map(|n| json!(n)).collect())
                }),
        }
    }

    /// The target, or a `config_error` saying why there is none.
    fn target_or_error(&self) -> Result<&Arc<Target>, ToolError> {
        self.target()
            .map_err(|e| ToolError::new(Code::ConfigError, e))
    }

    /// Live tools of the instance `run` would use without a project, when one answers.
    async fn live_tools(&self) -> Option<Vec<Tool>> {
        let endpoint = self.endpoint(None).await.ok()?;
        self.api.tools(&endpoint).await.ok()
    }

    /// `run`: one call, or a batch of them.
    async fn run(&self, raw: Option<JsonObject>) -> CallToolResult {
        let mut raw = raw.unwrap_or_default();
        let mut notes = Vec::new();
        if let Some(guide) = read_pasted_calls(&mut raw, &mut notes) {
            return error::with_notes(self.guide_tool(Some(guide)).await, &notes);
        }
        let assets = self.assets().await.ok();
        let catalog = assets.as_deref().map(|a| &a.catalog);
        // `steps` is what other tools call a batch, unless a tool is named (`action` naming one
        // too: `{"action":"http_send_request_chain","steps":[...]}`).
        let action_names_tool = raw
            .get("action")
            .and_then(Value::as_str)
            .is_some_and(|a| names_a_tool(catalog, a));
        if !action_names_tool
            && !CALL_KEYS
                .iter()
                .any(|k| raw.get(*k).is_some_and(|v| !v.is_null()))
            && let Some(steps) = raw.remove("steps")
        {
            notes.push("read 'steps' as 'batch'".to_owned());
            raw.insert("batch".to_owned(), steps);
        }
        let bail_given = raw.get("bail").is_some_and(|v| !v.is_null());
        let bail = match read_bail(raw.remove("bail")) {
            Ok((bail, note)) => {
                notes.extend(note);
                bail
            }
            Err(e) => return e.into_result(),
        };
        if let Some(batch) = raw.remove("batch") {
            if CALL_KEYS
                .iter()
                .any(|k| *k != "batch" && raw.contains_key(*k))
            {
                return ToolError::new(
                    Code::InvalidArguments,
                    "run: pass either do or batch, not both: drop \"batch\" to run one tool, or move the \"do\" call into batch.",
                )
                .param("batch")
                .into_result();
            }
            if let Some(extra) = raw.keys().find(|k| k.as_str() != "project") {
                return ToolError::new(
                    Code::UnknownParameter,
                    "run with batch takes only batch, bail and project; put each tool's parameters inside its step.",
                )
                .param(extra.as_str())
                .into_result();
            }
            let steps = match batch {
                Value::Array(steps) => steps,
                Value::String(s) => match serde_json::from_str::<Vec<Value>>(&s) {
                    Ok(steps) => {
                        notes.push("parsed 'batch' from a JSON string".to_owned());
                        steps
                    }
                    Err(_) => return batch_type_error("a string", Value::String(s)),
                },
                Value::Object(step) => {
                    notes.push("read 'batch' object as a one-step batch".to_owned());
                    vec![Value::Object(step)]
                }
                other => {
                    let kind = match &other {
                        Value::Bool(_) => "a boolean",
                        Value::Number(_) => "a number",
                        _ => "another value",
                    };
                    return batch_type_error(kind, other);
                }
            };
            if steps.is_empty() {
                return ToolError::new(
                    Code::MissingParameter,
                    "run: batch must list at least one {\"do\":\"<tool>\", ...} step.",
                )
                .param("batch")
                .example(json!({"batch": [run_example()]}))
                .into_result();
            }
            let project = raw
                .get("project")
                .and_then(Value::as_str)
                .map(str::to_owned);
            return self.batch(steps, bail, bail_given, project, &notes).await;
        }
        let result = match normalize_run(
            raw,
            |tool, key| tool_declares(catalog, tool, key),
            |name| names_a_tool(catalog, name),
        ) {
            Ok(call) => self.run_one(call).await,
            Err(e) => e.into_result(),
        };
        error::with_notes(result, &notes)
    }

    /// Steps in order; each result inline (no per-step spill), the whole batch spilled once. A
    /// failure surfaces at the top: `failed_steps`, an error result when every step failed or
    /// `bail` stopped the batch, and `retry` (a batch of each failed step's `retry`, then the steps
    /// not run) when every failed step has one.
    async fn batch(
        &self,
        steps: Vec<Value>,
        mut bail: bool,
        bail_given: bool,
        project: Option<String>,
        notes: &[String],
    ) -> CallToolResult {
        let assets = self.assets().await.ok();
        let catalog = assets.as_deref().map(|a| &a.catalog);
        let total = steps.len();
        let mut notes = notes.to_vec();
        // A bare name is a step without parameters: "burp_status" is {"do":"burp_status"}.
        let mut steps: Vec<Value> = steps
            .into_iter()
            .map(|step| match step {
                Value::String(name) => json!({ "do": name }),
                Value::Object(mut step) => {
                    if let Some(project) = &project
                        && !step.contains_key("batch")
                        && !step.contains_key("project")
                    {
                        step.insert("project".to_owned(), json!(project));
                    }
                    Value::Object(step)
                }
                other => other,
            })
            .collect();
        match take_step_bail(&mut steps, bail_given, &mut notes) {
            Ok(Some(step_bail)) => bail = step_bail,
            Ok(None) => {}
            Err(e) => return error::with_notes(e.into_result(), &notes),
        }
        let mut out = Vec::with_capacity(total);
        let mut failures: Vec<(usize, Value)> = Vec::new();
        let mut stopped_after = None;
        for (i, step) in steps.iter().enumerate() {
            let named = CALL_KEYS
                .iter()
                .find_map(|k| step.get(*k).cloned())
                .unwrap_or(Value::Null);
            let (ok, result) = match step.clone() {
                Value::Object(mut step) if !step.contains_key("batch") => {
                    let mut read = Vec::new();
                    if let Some(guide) = read_pasted_calls(&mut step, &mut read) {
                        let result = error::with_notes(self.guide_tool(Some(guide)).await, &read);
                        (result.is_error != Some(true), result_value(&result))
                    } else {
                        match normalize_run(
                            step,
                            |tool, key| tool_declares(catalog, tool, key),
                            |name| names_a_tool(catalog, name),
                        ) {
                            Ok(mut call) => {
                                read.append(&mut call.notes);
                                call.notes = read;
                                let (_, result) = self.run_raw(call).await;
                                (result.is_error != Some(true), result_value(&result))
                            }
                            Err(e) => (
                                false,
                                result_value(&error::with_notes(e.into_result(), &read)),
                            ),
                        }
                    }
                }
                Value::Object(_) => (
                    false,
                    ToolError::new(
                        Code::InvalidArguments,
                        "a batch step cannot hold another batch; list every call as its own {\"do\":\"<tool>\", ...} step.",
                    )
                    .example(run_example())
                    .to_value(),
                ),
                other => (
                    false,
                    ToolError::new(
                        Code::InvalidType,
                        format!(
                            "each batch step is a {{\"do\":\"<tool>\", ...}} object or a tool name, got {other}."
                        ),
                    )
                    .got(other)
                    .example(run_example())
                    .to_value(),
                ),
            };
            if !ok {
                failures.push((i + 1, result.clone()));
            }
            out.push(json!({"step": i + 1, "do": named, "ok": ok, "result": result}));
            if !ok && bail {
                stopped_after = Some(i + 1);
                break;
            }
        }
        let not_run: &[Value] = stopped_after.map_or(&[], |k| &steps[k..]);
        let retry = batch_retry(&failures, not_run, bail);
        let result = batch_result(out, &failures, stopped_after, total, retry);
        self.spill(error::with_notes(result, &notes), "batch")
    }

    async fn run_one(&self, call: Call) -> CallToolResult {
        let (tool, result) = self.run_raw(call).await;
        self.spill(result, &tool)
    }
}

/// A batch's result from its step results `out`: an error when `bail` stopped it after step
/// `stopped_after` or every step failed, else the steps with `failed_steps` and `retry` when some
/// failed.
fn batch_result(
    out: Vec<Value>,
    failures: &[(usize, Value)],
    stopped_after: Option<usize>,
    total: usize,
    retry: Option<Value>,
) -> CallToolResult {
    let mut value = Map::new();
    let all_failed = failures.len() == total;
    match (stopped_after, failures.first()) {
        (Some(k), Some((_, failed))) => {
            let mut message = format!("step {k} of {total} failed: {}", failure_reason(failed));
            let retryable = failed.get("retryable").and_then(Value::as_bool) == Some(true);
            if !retryable && !message.ends_with(error::FINAL_SENTENCE) {
                message.push_str(error::FINAL_SENTENCE);
            }
            value.insert("error".to_owned(), json!(message));
            value.insert("code".to_owned(), json!(failure_code(failed)));
            value.insert("steps".to_owned(), Value::Array(out));
            value.insert("stopped_after".to_owned(), json!(k));
            let not_run: Vec<usize> = ((k + 1)..=total).collect();
            value.insert("not_run".to_owned(), json!(not_run));
            if let Some(retry) = retry {
                value.insert("retry".to_owned(), retry);
            }
            value.insert("retryable".to_owned(), json!(retryable));
            CallToolResult::error(vec![ContentBlock::text(Value::Object(value).to_string())])
        }
        (None, Some((_, first))) if all_failed => {
            let retryable = failures
                .iter()
                .any(|(_, f)| f.get("retryable").and_then(Value::as_bool) == Some(true));
            let mut message = format!(
                "all {total} steps failed; step 1: {}",
                failure_reason(first)
            );
            if !retryable && !message.ends_with(error::FINAL_SENTENCE) {
                message.push_str(error::FINAL_SENTENCE);
            }
            let failed_steps: Vec<usize> = failures.iter().map(|(n, _)| *n).collect();
            value.insert("error".to_owned(), json!(message));
            value.insert("code".to_owned(), json!(failure_code(first)));
            value.insert("failed_steps".to_owned(), json!(failed_steps));
            value.insert("steps".to_owned(), Value::Array(out));
            if let Some(retry) = retry {
                value.insert("retry".to_owned(), retry);
            }
            value.insert("retryable".to_owned(), json!(retryable));
            CallToolResult::error(vec![ContentBlock::text(Value::Object(value).to_string())])
        }
        _ => {
            if !failures.is_empty() {
                let failed_steps: Vec<usize> = failures.iter().map(|(n, _)| *n).collect();
                value.insert("failed_steps".to_owned(), json!(failed_steps));
                if let Some(retry) = retry {
                    value.insert("retry".to_owned(), retry);
                }
            }
            value.insert("steps".to_owned(), Value::Array(out));
            text(&Value::Object(value))
        }
    }
}

impl Gateway {
    /// Runs one call ([`Self::run_resolved`]) and adds what reading it changed to the result's notes.
    async fn run_raw(&self, mut call: Call) -> (String, CallToolResult) {
        let notes = std::mem::take(&mut call.notes);
        let (tool, result) = self.run_resolved(call).await;
        (tool, error::with_notes(result, &notes))
    }

    /// Runs one call: a local tool (also named in another case or with `-`/`.`/`/` separators)
    /// runs here, anything else goes to Raijin under the name as given, which the extension
    /// resolves. Returns the tool that ran and its result.
    async fn run_resolved(&self, call: Call) -> (String, CallToolResult) {
        let Call {
            tool,
            mut arguments,
            project,
            notes: _,
            dropped,
        } = call;
        if let Some(result) = gateway_tool_as_do(&tool, arguments.as_ref()) {
            return (tool, result);
        }
        if !dropped.is_empty() && !self.reads_only(&tool).await {
            let listed: Vec<String> = dropped.iter().map(|d| format!("'{d}'")).collect();
            let result = ToolError::new(
                Code::InvalidArguments,
                format!(
                    "{tool}: {} could not be read as arguments; this call writes, so it was not made. Put each value as a key next to \"do\".",
                    listed.join(", ")
                ),
            )
            .example(run_example())
            .see(guide_call(Some(&tool)))
            .into_result();
            return (tool, result);
        }
        let (local, note) = match local_tool(&tool) {
            Some(local) => (Some(local), None),
            None => match LOCAL_TOOLS.iter().find(|t| t.name == error::norm(&tool)) {
                Some(local) if local.destructive => {
                    let result = ToolError::new(
                        Code::UnknownTool,
                        format!(
                            "unknown tool \"{tool}\"; did you mean {}? {DESTRUCTIVE_EXACT}",
                            local.name
                        ),
                    )
                    .did_you_mean(vec![local.name.to_owned()])
                    .into_result();
                    return (tool, result);
                }
                Some(local) => (Some(local), Some(format!("ran '{tool}' as {}", local.name))),
                None => (None, None),
            },
        };
        let Some(local) = local else {
            let result = self.forward(&tool, arguments, project.as_deref()).await;
            return (tool, result);
        };
        let mut notes: Vec<String> = note.into_iter().collect();
        if let Some(project) = project {
            if (local.schema)()
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|p| p.contains_key("project"))
            {
                arguments
                    .get_or_insert_with(JsonObject::new)
                    .entry("project")
                    .or_insert_with(|| json!(project));
            } else if local.domain == DATA {
                notes.push(format!(
                    "ignored 'project': {} does not use Burp",
                    local.name
                ));
            }
        }
        let result = match local.domain {
            LIFECYCLE => self.lifecycle(local, arguments).await,
            DATA => self.data(local, arguments).await,
            _ => self.history(local, arguments).await,
        };
        let result = error::mirror_warnings(error::with_notes(result, &notes));
        (local.name.to_owned(), result)
    }

    /// Whether a call of `name` only reads: a read-only local tool, or a catalog call marked
    /// `readOnlyHint` that removes or stops nothing. Unknown names count as writes.
    async fn reads_only(&self, name: &str) -> bool {
        if let Some(local) = local_tool(name.trim()).or_else(|| local_tool(&error::norm(name))) {
            return local.read_only;
        }
        let Ok(assets) = self.assets().await else {
            return false;
        };
        let catalog = &assets.catalog;
        catalog.resolve(name).is_some_and(|(tool, action)| {
            !catalog.destructive(&tool, action.as_deref())
                && catalog.tool(&tool).is_some_and(|spec| {
                    spec.annotations
                        .as_ref()
                        .and_then(|a| a.get("readOnlyHint"))
                        .and_then(Value::as_bool)
                        == Some(true)
                })
        })
    }

    /// Whether `run` can run `name`: a local tool, a catalog tool or a resolvable alias.
    async fn runnable(&self, name: &str) -> bool {
        local_tool(name.trim()).is_some()
            || self
                .assets()
                .await
                .is_ok_and(|a| a.catalog.resolve(name).is_some())
    }

    /// The project of this target `wanted` means: itself when the target has it, else the one
    /// project equal to it ignoring ASCII case (with a note), else `invalid_enum` listing the
    /// known projects, so a misspelled project never starts a new Burp. Remote mode takes `wanted`
    /// as given.
    fn resolve_project(&self, wanted: &str) -> Result<(String, Option<String>), ToolError> {
        if self.remote.is_some() {
            return Ok((wanted.to_owned(), None));
        }
        let Ok(target) = self.target() else {
            return Ok((wanted.to_owned(), None));
        };
        let known = target.known_projects();
        if known.iter().any(|k| k == wanted) {
            return Ok((wanted.to_owned(), None));
        }
        let hits: Vec<&String> = known
            .iter()
            .filter(|k| k.eq_ignore_ascii_case(wanted))
            .collect();
        if let [hit] = hits.as_slice() {
            return Ok((
                (*hit).clone(),
                Some(format!("matched project \"{wanted}\" to \"{hit}\"")),
            ));
        }
        let message = if known.is_empty() {
            format!("no project \"{wanted}\" in this target; start one with burp_up.")
        } else {
            format!(
                "no project \"{wanted}\" in this target; it has {}.",
                known.join(", ")
            )
        };
        Err(ToolError::new(Code::InvalidEnum, message)
            .param("project")
            .got(json!(wanted))
            .allowed(known.iter().map(|k| json!(k)).collect()))
    }

    /// Sends `tool` to Raijin as named; the extension resolves the name. `project` is first
    /// matched to one of this target ([`Self::resolve_project`]); an unknown name the extension
    /// reports is answered from the catalog ([`unknown_tool_error`]).
    async fn forward(
        &self,
        tool: &str,
        arguments: Option<JsonObject>,
        project: Option<&str>,
    ) -> CallToolResult {
        let mut notes = Vec::new();
        // A `/` would split the API path: `scope/check` means `scope.check`.
        let dotted;
        let tool = if tool.contains('/') {
            dotted = tool.replace('/', ".");
            notes.push(format!("read '{tool}' as {dotted}"));
            dotted.as_str()
        } else {
            tool
        };
        let project: Option<String> = match project {
            None => None,
            Some(wanted) => match self.resolve_project(wanted) {
                Ok((name, note)) => {
                    notes.extend(note);
                    Some(name)
                }
                Err(mut e) => {
                    let safe = self.assets().await.is_ok_and(|a| {
                        a.catalog.resolve(tool).is_some_and(|(name, action)| {
                            !a.catalog.destructive(&name, action.as_deref())
                        })
                    });
                    if let [only] = e.allowed.as_slice()
                        && safe
                    {
                        let mut call = Map::new();
                        call.insert("do".to_owned(), json!(tool));
                        call.extend(arguments.unwrap_or_default());
                        call.insert("project".to_owned(), only.clone());
                        e = e.retry(Value::Object(call));
                    }
                    return e.into_result();
                }
            },
        };
        let project = project.as_deref();
        let result = match self.endpoint(project).await {
            Err(e) => self.unreached(e, tool, arguments, project).await,
            Ok(endpoint) => match self.api.call(&endpoint, tool, arguments.as_ref()).await {
                Ok(result) if result_code(&result).as_deref() == Some("unknown_tool") => match self
                    .assets()
                    .await
                {
                    Ok(assets) => {
                        unknown_tool_error(&assets.catalog, tool, &arguments.unwrap_or_default())
                            .into_result()
                    }
                    Err(_) => result,
                },
                Ok(result) => result,
                Err(ApiError::Unreachable(msg)) => ToolError::new(
                    Code::RaijinUnreachable,
                    format!("{msg}; check run {{\"do\":\"burp_status\"}}."),
                )
                .into_result(),
                Err(ApiError::Other(msg)) => ToolError::new(Code::Internal, msg).into_result(),
            },
        };
        let result = match project {
            Some(project) => with_project(result, project),
            None => result,
        };
        error::with_notes(result, &notes)
    }

    /// The answer to a call no Burp can take (`burp_not_running`, `project_not_running`): a name
    /// the catalog does not know is `unknown_tool` right away, so no Burp is started for it; a known
    /// one gets `retry`, a batch that starts Burp and then makes the call (left out for a
    /// destructive call, which is only made as sent).
    async fn unreached(
        &self,
        error: ToolError,
        tool: &str,
        arguments: Option<JsonObject>,
        project: Option<&str>,
    ) -> CallToolResult {
        if !matches!(error.code, Code::BurpNotRunning | Code::ProjectNotRunning) {
            return error.into_result();
        }
        let Ok(assets) = self.assets().await else {
            return error.into_result();
        };
        let catalog = &assets.catalog;
        let arguments = arguments.unwrap_or_default();
        match catalog.resolve_call(tool) {
            catalog::Resolved::NotFound { .. } => {
                unknown_tool_error(catalog, tool, &arguments).into_result()
            }
            catalog::Resolved::Found {
                tool: name, action, ..
            } => {
                if catalog.destructive(&name, action.as_deref()) {
                    return error.into_result();
                }
                // A call missing a required parameter would only fail after Burp is up.
                let resolved = action
                    .as_deref()
                    .map_or_else(|| name.clone(), |a| format!("{name}.{a}"));
                let missing_required = safe_call_schema(catalog, &resolved).is_some_and(|schema| {
                    schema
                        .get("required")
                        .and_then(Value::as_array)
                        .is_some_and(|required| {
                            required.iter().filter_map(Value::as_str).any(|k| {
                                k != "project" && arguments.get(k).is_none_or(Value::is_null)
                            })
                        })
                });
                if missing_required {
                    return error.into_result();
                }
                let mut up = Map::new();
                up.insert("do".to_owned(), json!("burp_up"));
                let mut call = Map::new();
                call.insert("do".to_owned(), json!(tool));
                call.extend(arguments);
                if let Some(project) = project {
                    up.insert("project".to_owned(), json!(project));
                    call.entry("project").or_insert_with(|| json!(project));
                }
                error
                    .retry(json!({"batch": [up, call], "bail": true}))
                    .into_result()
            }
        }
    }

    /// The `guide` tool: its arguments read leniently ([`topic_alias`], [`only_topic`]), each
    /// reading noted.
    async fn guide_tool(&self, arguments: Option<JsonObject>) -> CallToolResult {
        let (arguments, renamed) = topic_alias(arguments);
        let (arguments, ignored) = only_topic(arguments);
        match parse_args::<GuideArgs>("guide", arguments, &json!({"topic": "overview"}), false) {
            Ok((args, mut notes)) => {
                notes.extend(renamed);
                notes.extend(ignored);
                error::with_notes(self.guide(args).await, &notes)
            }
            Err(e) => e
                .clear_example()
                .see(guide_call(Some("overview")))
                .into_result(),
        }
    }

    /// `guide`: the overview without a topic, else a tool, a domain, a playbook or a playbook file.
    async fn guide(&self, args: GuideArgs) -> CallToolResult {
        let assets = self.assets().await;
        let catalog = assets.as_ref().ok().map(|a| &a.catalog);
        let catalog_error = assets.as_ref().err();
        let live = self.live_tools().await;
        let other: Vec<String> = match (&live, catalog) {
            (Some(live), Some(c)) => live
                .iter()
                .map(|t| t.name.to_string())
                .filter(|n| c.domain_of(n).is_none())
                .collect(),
            (Some(live), None) => live.iter().map(|t| t.name.to_string()).collect(),
            _ => Vec::new(),
        };
        let cleaned = args.topic.as_deref().map(clean_topic);
        let topic = cleaned.as_deref().filter(|t| !t.is_empty());
        let result = match topic {
            None => plain(
                self.overview(catalog, live.as_deref(), &other, catalog_error)
                    .await,
            ),
            Some(topic) if matches!(error::norm(topic).as_str(), "run" | "guide") => {
                plain(format!("{GUIDE_HEAD}\n\nrun: {RUN_DESCRIPTION}"))
            }
            Some(topic) => {
                let names = topic_names(catalog, live.as_deref(), &other);
                let domains = catalog.map_or_else(
                    || [LIFECYCLE, HISTORY, DATA].map(str::to_owned).to_vec(),
                    domain_names,
                );
                let first_segment = topic.split('.').next().unwrap_or_default();
                self.topic(topic, catalog, live.as_deref(), &other)
                    .or_else(|| {
                        // `analysis.util.hash`: the domain before the tool.
                        let rest = strip_domain(topic, &domains)?;
                        let found = self.topic(rest, catalog, live.as_deref(), &other).or_else(|| {
                            let same = normalized_topic(rest, &names, catalog)?;
                            self.topic(same, catalog, live.as_deref(), &other)
                        })?;
                        Some(error::with_notes(
                            found,
                            &[format!("dropped the domain '{first_segment}' from the topic")],
                        ))
                    })
                    .or_else(|| {
                        let same = normalized_topic(topic, &names, catalog)?;
                        self.topic(same, catalog, live.as_deref(), &other)
                    })
                    .unwrap_or_else(|| {
                        let by_words = if topic.contains(char::is_whitespace) {
                            sentence_topics(topic, catalog)
                        } else {
                            Vec::new()
                        };
                        let mut did_you_mean: Vec<String> = if by_words.is_empty() {
                            suggest(topic, names.iter().map(String::as_str), 3)
                                .into_iter()
                                .map(str::to_owned)
                                .collect()
                        } else {
                            by_words
                        };
                        // An old member name (`scope_list`) is suggested as its current call.
                        if let Some(c) = catalog {
                            let mut seen = BTreeSet::new();
                            did_you_mean = did_you_mean
                                .into_iter()
                                .map(|n| match c.aliases.get(&n) {
                                    Some(alias) => format!("{}.{}", alias.tool, alias.action),
                                    None => n,
                                })
                                .filter(|n| seen.insert(n.clone()))
                                .collect();
                        }
                        // Words that say what the model wants (`xss`, `BCheck`): their domain first.
                        let domain = catalog.and_then(|c| {
                            let intent = intent_call(topic)?;
                            domain_of_call(c, intent.names[0])
                        });
                        if let Some(d) = &domain {
                            did_you_mean.retain(|n| n != d);
                            did_you_mean.insert(0, d.clone());
                        }
                        // `data.nope`: the domain the topic already names is no suggestion.
                        if topic.contains('.') {
                            did_you_mean.retain(|n| n != first_segment);
                        }
                        ToolError::new(
                            Code::UnknownTopic,
                            format!(
                                "unknown topic \"{topic}\"; guide {{}} lists every tool, domain and playbook."
                            ),
                        )
                        .did_you_mean(did_you_mean)
                        .see(guide_call(domain.as_deref()))
                        .into_result()
                    })
            }
        };
        self.spill(result, "guide")
    }

    /// `guide()` without a topic: how to call, where Burp runs, every tool by domain, the playbooks.
    async fn overview(
        &self,
        catalog: Option<&Catalog>,
        live: Option<&[Tool]>,
        other: &[String],
        catalog_error: Option<&String>,
    ) -> String {
        let mut lines = vec![GUIDE_HEAD.to_owned()];
        let mut warnings = Vec::new();
        if let Some(e) = catalog_error {
            warnings.push(format!("tool catalog unavailable: {e}"));
        }
        let target = match (&self.target, &self.target_error) {
            (Some(t), _) => t.root.display().to_string(),
            (None, e) => format!("none ({})", e.as_deref().unwrap_or("no target")),
        };
        lines.push(match &self.remote {
            Some(remote) => format!("Target: {target} | Remote: {}", remote.url),
            None => format!("Target: {target}"),
        });
        let burp = match (&self.remote, &self.target) {
            (Some(remote), _) => format!("remote {}", remote.url),
            (None, Some(target)) => match instance::status_all(target).await {
                Ok(all) if !all.is_empty() => all
                    .iter()
                    .map(|s| match &s.mcp_url {
                        Some(url) => format!("{} {} {url}", s.project, state_name(s.state)),
                        None => format!("{} {}", s.project, state_name(s.state)),
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
                Ok(_) => "no projects".to_owned(),
                Err(e) => {
                    warnings.push(format!("Burp status: {e:#}"));
                    "unknown".to_owned()
                }
            },
            (None, None) => "none".to_owned(),
        };
        lines.push(format!("Burp: {burp}"));
        if !warnings.is_empty() {
            lines.push(format!("Warnings: {}", warnings.join("; ")));
        }

        lines.push(String::new());
        lines.push("Tools by domain:".to_owned());
        let live_names: Option<BTreeSet<&str>> =
            live.map(|l| l.iter().map(|t| t.name.as_ref()).collect());
        let entry = |name: &str, view: Option<ToolView>| {
            let actions = view.map_or_default(|v| actions_of(&v.schema));
            if actions.is_empty() {
                name.to_owned()
            } else {
                format!("{name}({})", actions.join("|"))
            }
        };
        for d in catalog.map_or_default(|c| c.domains.as_slice()) {
            let tools: Vec<String> = d
                .tools
                .iter()
                .filter(|t| live_names.as_ref().is_none_or(|n| n.contains(t.as_str())))
                .map(|t| entry(t, tool_view(t, catalog, live)))
                .collect();
            lines.push(domain_line(&d.name, &d.description, &tools.join(", ")));
        }
        if !other.is_empty() {
            let tools: Vec<String> = other
                .iter()
                .map(|t| entry(t, tool_view(t, catalog, live)))
                .collect();
            lines.push(domain_line(OTHER, OTHER_DESCRIPTION, &tools.join(", ")));
        }
        let lifecycle: Vec<&str> = self.lifecycle_tools().iter().map(|t| t.name).collect();
        lines.push(domain_line(
            LIFECYCLE,
            LIFECYCLE_DESCRIPTION,
            &lifecycle.join(", "),
        ));
        let history_tools: Vec<&str> = LOCAL_TOOLS
            .iter()
            .filter(|t| t.domain == HISTORY)
            .map(|t| t.name)
            .collect();
        lines.push(domain_line(
            HISTORY,
            HISTORY_DESCRIPTION,
            &history_tools.join(", "),
        ));
        let data_tools: Vec<&str> = LOCAL_TOOLS
            .iter()
            .filter(|t| t.domain == DATA)
            .map(|t| t.name)
            .collect();
        lines.push(domain_line(DATA, DATA_DESCRIPTION, &data_tools.join(", ")));

        lines.push(String::new());
        lines.push("Playbooks (guide {\"topic\":\"<name>\"}):".to_owned());
        for skill in catalog::skills() {
            lines.push(format!("{} — {}", skill.name, skill.description));
        }
        lines.join("\n")
    }

    /// `guide(topic)`: a tool, a domain, a playbook or a playbook file; None when nothing matches.
    /// A name that is both a tool and a domain (`scanner`, `recon`, `findings`) gives the tool with
    /// the domain's listing as `domain_tools`.
    fn topic(
        &self,
        topic: &str,
        catalog: Option<&Catalog>,
        live: Option<&[Tool]>,
        other: &[String],
    ) -> Option<CallToolResult> {
        let tool = tool_topic(topic, catalog, live);
        let domain = self.domain_topic(topic, catalog, live, other);
        match (tool, domain) {
            (Some(mut tool), Some(mut domain)) => {
                tool["domain_tools"] = domain["tools"].take();
                Some(text(&tool))
            }
            (Some(found), None) | (None, Some(found)) => Some(text(&found)),
            (None, None) => playbook_topic(topic),
        }
    }

    /// A domain's tools, one summary line each and no schemas.
    fn domain_topic(
        &self,
        topic: &str,
        catalog: Option<&Catalog>,
        live: Option<&[Tool]>,
        other: &[String],
    ) -> Option<Value> {
        let domain = topic.to_lowercase();
        let listing = |names: &mut dyn Iterator<Item = (&str, Option<ToolView>)>| -> Vec<Value> {
            names
                .filter_map(|(name, view)| view.map(|v| v.listing(name)))
                .collect()
        };
        let (description, notes, playbook, tools) =
            if domain == LIFECYCLE || domain == HISTORY || domain == DATA {
                let of = |d: &str| -> Vec<&LocalTool> {
                    LOCAL_TOOLS.iter().filter(|t| t.domain == d).collect()
                };
                let (tools, description, notes): (Vec<&LocalTool>, _, _) = match domain.as_str() {
                    LIFECYCLE => (
                        self.lifecycle_tools(),
                        LIFECYCLE_DESCRIPTION,
                        LIFECYCLE_NOTES,
                    ),
                    HISTORY => (of(HISTORY), HISTORY_DESCRIPTION, HISTORY_NOTES),
                    _ => (of(DATA), DATA_DESCRIPTION, DATA_NOTES),
                };
                (
                    description.to_owned(),
                    notes.to_owned(),
                    local_playbook(&domain).to_owned(),
                    listing(&mut tools.iter().map(|t| (t.name, Some(ToolView::local(t))))),
                )
            } else if domain == OTHER && !other.is_empty() {
                (
                    OTHER_DESCRIPTION.to_owned(),
                    OTHER_NOTES.to_owned(),
                    local_playbook(OTHER).to_owned(),
                    listing(
                        &mut other
                            .iter()
                            .map(|t| (t.as_str(), tool_view(t, catalog, live))),
                    ),
                )
            } else {
                let d = catalog?.domain(&domain)?;
                let live_names: Option<BTreeSet<&str>> =
                    live.map(|l| l.iter().map(|t| t.name.as_ref()).collect());
                (
                    d.description.clone(),
                    d.notes.clone(),
                    d.skill.clone(),
                    listing(
                        &mut d
                            .tools
                            .iter()
                            .filter(|t| live_names.as_ref().is_none_or(|n| n.contains(t.as_str())))
                            .map(|t| (t.as_str(), tool_view(t, catalog, live))),
                    ),
                )
            };
        // The domain's own advice is `hint`: `notes` holds only what the server read differently.
        let mut value = json!({"domain": domain, "description": description});
        if !notes.is_empty() {
            value["hint"] = json!(notes);
        }
        value["playbook"] = json!(playbook);
        value["tools"] = json!(tools);
        Some(value)
    }

    async fn lifecycle(&self, local: &LocalTool, arguments: Option<JsonObject>) -> CallToolResult {
        match self.lifecycle_inner(local, arguments).await {
            Ok((value, notes)) => error::with_notes(text(&value), &notes),
            Err(e) => e.into_result(),
        }
    }

    async fn lifecycle_inner(
        &self,
        local: &LocalTool,
        arguments: Option<JsonObject>,
    ) -> Result<(Value, Vec<String>), ToolError> {
        let err = |e: anyhow::Error| ToolError::new(Code::ToolFailed, format!("{e:#}"));
        let tool = local.name;
        if let Some(remote) = &self.remote {
            if tool != "burp_status" {
                return Err(ToolError::new(
                    Code::NotSupported,
                    format!(
                        "target uses remote {}; Burp is not CLI-managed here, only burp_status works.",
                        remote.url
                    ),
                ));
            }
            let (_, notes): (StatusArgs, _) = local_args(local, arguments)?;
            let endpoint = self.endpoint(None).await?;
            let value = match self.api.server_version(&endpoint).await {
                Ok(version) => {
                    json!({"remote": remote.url, "reachable": true, "server_version": version})
                }
                Err(e) => json!({"remote": remote.url, "reachable": false, "error": e}),
            };
            return Ok((value, notes));
        }
        let target = self.target_or_error()?.clone();
        // A host given as project (`example.com`) is the usual mistake: say what a project is.
        let project_of = |requested: Option<&str>| {
            target.project_or_default(requested).map_err(|e| {
                let known = target.known_projects();
                let names = if known.is_empty() {
                    target.config.default_project.clone()
                } else {
                    known.join(", ")
                };
                ToolError::new(
                    Code::InvalidArguments,
                    format!(
                        "{e:#}. project is a Burp project name of this target ({names}), not a host; scope.include takes hosts."
                    ),
                )
                .param("project")
                .got(json!(requested.unwrap_or_default()))
            })
        };
        match tool {
            "burp_up" => {
                let (args, notes): (UpArgs, _) = local_args(local, arguments)?;
                let project = project_of(args.project.as_deref())?;
                let requested = args.wait_seconds.unwrap_or(DEFAULT_WAIT);
                let wait = requested.min(MAX_WAIT);
                let report = launch::up(
                    &target,
                    &project,
                    args.mode.unwrap_or(target.config.mode),
                    Duration::from_secs(wait),
                )
                .await
                .map_err(err)?;
                let mut value = serde_json::to_value(&report)
                    .map_err(|e| ToolError::new(Code::Internal, e.to_string()))?;
                if requested != wait {
                    value["wait_seconds_clamped_to"] = json!(wait);
                }
                Ok((value, notes))
            }
            "burp_down" => {
                let (args, notes): (DownArgs, _) = local_args(local, arguments)?;
                let projects = if args.all {
                    target.known_projects()
                } else {
                    vec![project_of(args.project.as_deref())?]
                };
                let mut stopped = Vec::new();
                for project in projects {
                    let result = instance::stop(&target, &project).await.map_err(err)?;
                    if !args.all || result["was_running"].as_bool() == Some(true) {
                        stopped.push(result);
                    }
                }
                Ok((json!({"stopped": stopped}), notes))
            }
            _ => {
                let (_, notes): (StatusArgs, _) = local_args(local, arguments)?;
                let all = instance::status_all(&target).await.map_err(err)?;
                Ok((
                    json!({"target": target.root.display().to_string(), "instances": all}),
                    notes,
                ))
            }
        }
    }

    async fn data(&self, local: &LocalTool, arguments: Option<JsonObject>) -> CallToolResult {
        let result = if local.name == "data_import" {
            self.data_import(local, arguments).await
        } else {
            self.data_inner(local, arguments).await
        };
        match result {
            Ok((value, notes)) => error::with_notes(value, &notes),
            Err(e) => e.into_result(),
        }
    }

    fn data_root(&self) -> Result<&Path, ToolError> {
        self.data_root.as_deref().ok_or_else(|| {
            ToolError::new(Code::ConfigError, "no home directory for ~/.raijin/data")
        })
    }

    /// Downloads missing and stale sources, once per session and only when automatic updates are
    /// on; a note per source says what happened.
    async fn data_refresh(&self, root: &Path) -> Vec<String> {
        let mut checked = self.data_checked.lock().await;
        if *checked || !self.data_auto_update {
            return Vec::new();
        }
        *checked = true;
        let due = store::due(root, crate::util::now_ms());
        if due.is_empty() {
            return Vec::new();
        }
        let results =
            futures::future::join_all(due.iter().map(|(up, _)| store::fetch(root, up))).await;
        let mut notes = Vec::new();
        for ((up, old), result) in due.iter().zip(results) {
            let name = up.source.as_str();
            notes.push(match (result, old) {
                (Ok(m), old) => format!(
                    "{} {name} ({})",
                    if old.is_some() {
                        "refreshed"
                    } else {
                        "downloaded"
                    },
                    store::short_commit(m.commit.as_deref())
                ),
                (Err(e), Some(old)) => format!(
                    "could not refresh {name}: {e:#}; using data from {}",
                    day_of(old.fetched_at_ms)
                ),
                (Err(e), None) => format!(
                    "{name} not downloaded: {e:#}; run {{\"do\":\"data_update\"}} when online"
                ),
            });
        }
        if let Ok(mut cache) = self.data_cache.lock() {
            *cache = None;
        }
        notes
    }

    /// The upstream library (reparsed only when a manifest changed) and this target's own data.
    async fn data_libraries(
        &self,
        root: &Path,
    ) -> Result<(Arc<data::Library>, data::Library), ToolError> {
        let internal = |e: tokio::task::JoinError| ToolError::new(Code::Internal, e.to_string());
        let stamp = store::stamp(root);
        let cached = self.data_cache.lock().ok().and_then(|c| {
            c.as_ref()
                .filter(|(s, _)| *s == stamp)
                .map(|(_, lib)| lib.clone())
        });
        let upstream = if let Some(lib) = cached {
            lib
        } else {
            let dir = root.to_path_buf();
            let lib = Arc::new(
                tokio::task::spawn_blocking(move || store::load_upstream(&dir))
                    .await
                    .map_err(internal)?,
            );
            if let Ok(mut cache) = self.data_cache.lock() {
                *cache = Some((stamp, lib.clone()));
            }
            lib
        };
        let custom = match &self.target {
            Some(t) => {
                let dir = t.data_dir();
                tokio::task::spawn_blocking(move || data::custom::load_custom(&dir))
                    .await
                    .map_err(internal)?
            }
            None => data::Library::default(),
        };
        Ok((upstream, custom))
    }

    async fn data_inner(
        &self,
        local: &LocalTool,
        arguments: Option<JsonObject>,
    ) -> Result<(CallToolResult, Vec<String>), ToolError> {
        use data::tools;
        let root = self.data_root()?;
        let value = match local.name {
            "data_add" => {
                let (args, mut notes): (tools::AddArgs, _) = local_args(local, arguments)?;
                let dir = self.target_or_error()?.data_dir();
                let (value, more) =
                    tokio::task::spawn_blocking(move || data::custom::add(&dir, &args))
                        .await
                        .map_err(|e| ToolError::new(Code::Internal, e.to_string()))??;
                notes.extend(more);
                return Ok((text(&value), notes));
            }
            "data_update" => {
                let (args, notes): (tools::UpdateArgs, _) = local_args(local, arguments)?;
                let source = args.source.map(data::Source::from);
                return Ok((text(&self.data_update(root, source).await?), notes));
            }
            "data_list" => {
                let (args, mut notes): (tools::ListArgs, _) = local_args(local, arguments)?;
                notes.extend(self.data_refresh(root).await);
                let (upstream, custom) = self.data_libraries(root).await?;
                let custom_dir = self.target.as_ref().map(|t| t.data_dir());
                let value = tools::list(
                    root,
                    custom_dir.as_deref(),
                    &upstream,
                    &custom,
                    crate::util::now_ms(),
                    args.source,
                );
                (value, notes)
            }
            "data_search" => {
                let (args, mut notes): (tools::SearchArgs, _) = local_args(local, arguments)?;
                notes.extend(self.data_refresh(root).await);
                let (upstream, custom) = self.data_libraries(root).await?;
                let entries = data_view(&upstream, &custom);
                let (mut value, more) = tools::search(&entries, &args)?;
                notes.extend(more);
                if let Some(source) = args.filters.source
                    && source != data::Source::Custom
                    && store::manifest(root, source).is_none()
                {
                    value["missing"] = json!([source]);
                }
                (value, notes)
            }
            "data_get" => {
                let (args, mut notes): (tools::GetArgs, _) = local_args(local, arguments)?;
                notes.extend(self.data_refresh(root).await);
                let (upstream, custom) = self.data_libraries(root).await?;
                let (value, note) = tools::get(&data_view(&upstream, &custom), &args.id)?;
                notes.extend(note);
                (value, notes)
            }
            _ => {
                let (args, mut notes): (tools::PayloadsArgs, _) = local_args(local, arguments)?;
                notes.extend(self.data_refresh(root).await);
                let (upstream, custom) = self.data_libraries(root).await?;
                let (value, more) = tools::payloads(&data_view(&upstream, &custom), &args)?;
                notes.extend(more);
                (value, notes)
            }
        };
        Ok((text(&value.0), value.1))
    }

    /// `data_import`: a `BCheck` or Bambda of the library sent to the running Burp.
    async fn data_import(
        &self,
        local: &LocalTool,
        arguments: Option<JsonObject>,
    ) -> Result<(CallToolResult, Vec<String>), ToolError> {
        let root = self.data_root()?;
        let (args, mut notes): (data::tools::ImportArgs, _) = local_args(local, arguments)?;
        notes.extend(self.data_refresh(root).await);
        let (upstream, custom) = self.data_libraries(root).await?;
        let entries = data_view(&upstream, &custom);
        let (entry, note) = data::tools::find(&entries, &args.id, "data_import")?;
        notes.extend(note);
        let tool = match entry.kind {
            data::Kind::Bcheck => "custom_check.bcheck_import",
            data::Kind::Bambda => "bambda_import",
            data::Kind::Payload => {
                return Err(ToolError::new(
                    Code::InvalidArguments,
                    format!(
                        "{} is a payload, not a script; use data_payloads or data_get",
                        entry.id
                    ),
                )
                .param("id")
                .see(json!({"do": "data_get", "id": entry.id})));
            }
        };
        let mut call = JsonObject::new();
        call.insert("script".to_owned(), json!(entry.payload));
        let mut result = self
            .forward(tool, Some(call), args.project.as_deref())
            .await;
        if matches!(
            result_code(&result).as_deref(),
            Some("burp_not_running" | "project_not_running")
        ) {
            // Burp's own retry would resend the whole script under the import tool's name.
            let mut up = json!({"do": "burp_up"});
            let mut again = json!({"do": "data_import", "id": entry.id});
            if let Some(project) = &args.project {
                up["project"] = json!(project);
                again["project"] = json!(project);
            }
            result = with_retry(result, json!({"batch": [up, again], "bail": true}));
        }
        if result.is_error != Some(true) {
            notes.push(format!("imported {}", entry.id));
            notes.push(if entry.kind == data::Kind::Bcheck {
                "remove it with custom_check.bcheck_remove, then delete it in Extensions > Custom scan checks".to_owned()
            } else {
                "no MCP action removes a Bambda; delete it in Burp's Bambda library".to_owned()
            });
        }
        Ok((result, notes))
    }

    /// `data_update`: downloads `source`, or every upstream source, now.
    async fn data_update(
        &self,
        root: &Path,
        source: Option<data::Source>,
    ) -> Result<Value, ToolError> {
        let ups: Vec<&'static store::Upstream> = store::UPSTREAM
            .iter()
            .filter(|u| source.is_none_or(|s| s == u.source))
            .collect();
        // Held across the downloads, so an automatic refresh never installs the same source at once.
        let mut checked = self.data_checked.lock().await;
        let previous: Vec<Option<store::Manifest>> = ups
            .iter()
            .map(|u| store::manifest(root, u.source))
            .collect();
        let results = futures::future::join_all(ups.iter().map(|u| store::fetch(root, u))).await;
        let mut updated = Vec::new();
        let mut failed = Vec::new();
        for ((up, before), result) in ups.iter().zip(previous).zip(results) {
            match result {
                Ok(m) => updated.push(json!({
                    "source": up.source,
                    "commit": m.commit,
                    "previous_commit": before.and_then(|b| b.commit),
                    "files": m.files,
                })),
                Err(e) => failed.push(json!({"source": up.source, "error": format!("{e:#}")})),
            }
        }
        if let Ok(mut cache) = self.data_cache.lock() {
            *cache = None;
        }
        // One source updated leaves the others to the automatic check.
        if source.is_none() {
            *checked = true;
        }
        drop(checked);
        if updated.is_empty() {
            let errors: Vec<String> = failed
                .iter()
                .map(|f| {
                    format!(
                        "{}: {}",
                        f["source"].as_str().unwrap_or_default(),
                        f["error"].as_str().unwrap_or_default()
                    )
                })
                .collect();
            return Err(ToolError::new(
                Code::ToolFailed,
                format!("no data source downloaded ({})", errors.join("; ")),
            ));
        }
        Ok(json!({"updated": updated, "failed": failed}))
    }

    async fn history(
        &self,
        local: &'static LocalTool,
        arguments: Option<JsonObject>,
    ) -> CallToolResult {
        let target = match self.target_or_error() {
            Ok(t) => t.clone(),
            Err(e) => return e.into_result(),
        };
        let mut arguments = arguments;
        let mut notes = bare_refs(&target, local, arguments.as_mut());
        let mut sent = arguments.clone().unwrap_or_default();
        let mut outcome = run_history_blocking(target.clone(), local, arguments).await;
        // A project named in another case (`MAIN` for `main`): run once more on the one it means.
        let rematch = match &outcome {
            Err(HistoryFailure::Failed(e, _)) => match history::Problem::of(e) {
                Some(history::Problem::UnknownProject { wanted, known }) => {
                    let hits: Vec<&String> = known
                        .iter()
                        .filter(|k| k.eq_ignore_ascii_case(wanted))
                        .collect();
                    match hits.as_slice() {
                        [hit] => Some((wanted.clone(), (*hit).clone())),
                        _ => None,
                    }
                }
                _ => None,
            },
            _ => None,
        };
        if let Some((wanted, hit)) = rematch {
            sent = rematched_project(sent, &wanted, &hit);
            notes.push(format!("matched project \"{wanted}\" to \"{hit}\""));
            outcome = run_history_blocking(target, local, Some(sent.clone())).await;
        }
        let result = match outcome {
            Ok((mut value, parsed)) => {
                notes.extend(parsed);
                if let Ok(mut seen) = self.warned_live.lock() {
                    drop_repeated_live_warnings(&mut value, &mut seen);
                }
                text(&value)
            }
            Err(HistoryFailure::Refused(e)) => e.into_result(),
            Err(HistoryFailure::Failed(e, parsed)) => {
                notes.extend(parsed);
                history_error(local.name, &e, &sent).into_result()
            }
        };
        error::with_notes(result, &notes)
    }

    fn gateway_tools() -> Vec<Tool> {
        let annotated = |tool: Tool, title: &str, annotations: Value| {
            let tool = tool.with_title(title);
            match serde_json::from_value::<ToolAnnotations>(annotations) {
                Ok(annotations) => tool.with_annotations(annotations),
                Err(_) => tool,
            }
        };
        let run_schema = json!({
            "type": "object",
            "properties": {
                "do": {"type": "string", "description": "Tool name, <tool>.<action>, or old member name"},
                "project": {"type": "string", "description": "Project whose Burp runs the tool when several run"},
                "batch": {"type": "array", "items": {"type": "object"}},
                "bail": {"type": "boolean", "description": "batch: stop at the first failed step"}
            },
            "additionalProperties": true
        });
        vec![
            annotated(
                Tool::new(
                    "guide",
                    "Without a topic: the running Burp instances, every tool by domain (grouped tools list their actions) and the playbooks. With a topic: one tool's description and inputSchema (tool, tool.action or old member name), a domain's tools, a playbook, or a playbook file.",
                    schema_of::<GuideArgs>(),
                ),
                "Raijin tools and playbooks",
                json!({"readOnlyHint": true, "openWorldHint": false}),
            ),
            annotated(
                Tool::new_with_raw(
                    "run",
                    Some(Cow::Borrowed(RUN_DESCRIPTION)),
                    run_schema.as_object().cloned().unwrap_or_default(),
                ),
                "Run a Raijin tool",
                json!({"readOnlyHint": false, "destructiveHint": true, "openWorldHint": true}),
            ),
        ]
    }
}

/// The entries data tools see: this target's own first, then `PortSwigger`'s.
fn data_view<'a>(upstream: &'a data::Library, custom: &'a data::Library) -> Vec<&'a data::Entry> {
    custom.entries.iter().chain(&upstream.entries).collect()
}

/// `yyyy-mm-dd` (UTC) of a time in epoch milliseconds.
fn day_of(ms: u64) -> String {
    let stamp = crate::util::utc_stamp_at(ms / 1000);
    format!("{}-{}-{}", &stamp[..4], &stamp[4..6], &stamp[6..8])
}

/// One `guide()` overview line: `<domain> — <description>: <tools>`.
fn domain_line(name: &str, description: &str, tools: &str) -> String {
    format!("{name} — {}: {tools}", description.trim_end_matches('.'))
}

/// A published or live tool's description and schema: live when Burp answers, else the catalog.
fn tool_view(name: &str, catalog: Option<&Catalog>, live: Option<&[Tool]>) -> Option<ToolView> {
    live.and_then(|l| l.iter().find(|t| t.name == name))
        .map(ToolView::live)
        .or_else(|| catalog.and_then(|c| c.tool(name)).map(ToolView::spec))
}

/// One tool's description and inputSchema: a local tool, a catalog tool, alias or
/// `<tool>.<action>`, or a tool only the running Raijin has.
fn tool_topic(topic: &str, catalog: Option<&Catalog>, live: Option<&[Tool]>) -> Option<Value> {
    let (name, action, domain, playbook, view) = if let Some(local) = local_tool(topic) {
        (
            local.name.to_owned(),
            None,
            local.domain.to_owned(),
            local_playbook(local.domain).to_owned(),
            ToolView::local(local),
        )
    } else if let Some(catalog::Resolved::Found {
        tool: name, action, ..
    }) = catalog.map(|c| c.resolve_call(topic))
        && let Some(view) = tool_view(&name, catalog, live)
        && action.as_ref().is_none_or(|a| {
            let actions = actions_of(&view.schema);
            actions.is_empty() || actions.contains(a)
        })
    {
        let (domain, playbook) = catalog
            .and_then(|c| c.domain_of(&name))
            .map_or((OTHER.to_owned(), local_playbook(OTHER).to_owned()), |d| {
                (d.name.clone(), d.skill.clone())
            });
        (name, action, domain, playbook, view)
    } else {
        let tool = live?.iter().find(|t| t.name == topic)?;
        (
            tool.name.to_string(),
            None,
            OTHER.to_owned(),
            local_playbook(OTHER).to_owned(),
            ToolView::live(tool),
        )
    };
    let spec = catalog.and_then(|c| c.tool(&name));
    let action_spec = action
        .as_deref()
        .and_then(|a| spec.and_then(|s| s.actions.get(a)));
    let mut out = json!({"do": name});
    if let Some(action) = &action {
        out["action"] = json!(action);
    }
    out["domain"] = json!(domain);
    out["playbook"] = json!(playbook);
    out["description"] = json!(view.description);
    out["annotations"] = view.annotations.unwrap_or(Value::Null);
    match (&action, action_spec) {
        // One action of a grouped tool: its own parameters only, with a call that works.
        (Some(action), Some(a)) => {
            let schema = narrowed_action(&view.schema, a);
            if let Some(description) = &a.description {
                out["description"] = json!(description);
            }
            out["usage"] = json!(super::args::usage(&format!("{name}.{action}"), &schema));
            out["example"] = a.example.clone();
            out["inputSchema"] = Value::Object(schema);
        }
        // A grouped tool: one call line per action; `guide tool.action` narrows to one.
        _ if spec.is_some_and(|s| !s.actions.is_empty()) => {
            let actions: Map<String, Value> = spec
                .map(|s| &s.actions)
                .into_iter()
                .flatten()
                .map(|(a, aspec)| {
                    let schema = narrowed_action(&view.schema, aspec);
                    let signature = super::args::usage(&format!("{name}.{a}"), &schema);
                    (a.clone(), json!(signature))
                })
                .collect();
            out["usage"] = json!(format!(
                "guide {{\"topic\":\"{name}.<action>\"}} shows one action"
            ));
            out["actions"] = Value::Object(actions);
            out["inputSchema"] = view.schema;
        }
        _ => {
            if let Some(schema) = view.schema.as_object() {
                out["usage"] = json!(super::args::usage(&name, schema));
            }
            let example = local_tool(&name)
                .map(LocalTool::example)
                .or_else(|| spec.and_then(|s| s.example.clone()));
            if let Some(example) = example {
                out["example"] = example;
            }
            out["inputSchema"] = view.schema;
        }
    }
    Some(out)
}

/// `schema` with only the `params` properties (in their order) and `required` as given.
fn narrowed(schema: &Value, params: &[String], required: &[String]) -> JsonObject {
    let props = schema.get("properties").and_then(Value::as_object);
    let kept: Map<String, Value> = params
        .iter()
        .filter_map(|p| {
            props
                .and_then(|all| all.get(p))
                .map(|d| (p.clone(), d.clone()))
        })
        .collect();
    let mut out = Map::new();
    out.insert("type".to_owned(), json!("object"));
    out.insert("properties".to_owned(), Value::Object(kept));
    out.insert("required".to_owned(), json!(required));
    out
}

/// One action's schema: its own parameter schemas from the catalog (in `params` order), else the
/// group's merged ones for its `params` ([`narrowed`]).
fn narrowed_action(view_schema: &Value, a: &ActionSpec) -> JsonObject {
    let Some(props) = &a.properties else {
        return narrowed(view_schema, &a.params, &a.required);
    };
    let mut kept: Map<String, Value> = a
        .params
        .iter()
        .filter_map(|p| props.get(p).map(|d| (p.clone(), d.clone())))
        .collect();
    for (k, v) in props {
        kept.entry(k.clone()).or_insert_with(|| v.clone());
    }
    let mut out = Map::new();
    out.insert("type".to_owned(), json!("object"));
    out.insert("properties".to_owned(), Value::Object(kept));
    out.insert("required".to_owned(), json!(a.required));
    out
}

/// `guide` arguments with only `topic` kept, and a note per key left out: `guide` takes nothing
/// else, so a stray key is not worth an error.
fn only_topic(arguments: Option<JsonObject>) -> (Option<JsonObject>, Vec<String>) {
    let Some(mut arguments) = arguments else {
        return (None, Vec::new());
    };
    let extra: Vec<String> = arguments
        .keys()
        .filter(|k| k.as_str() != "topic")
        .cloned()
        .collect();
    let notes = extra
        .into_iter()
        .map(|k| {
            arguments.remove(&k);
            format!("ignored '{k}': guide takes only 'topic'")
        })
        .collect();
    (Some(arguments), notes)
}

/// Words a sentence topic is matched by are those of 3+ letters outside this list.
const TOPIC_STOP_WORDS: [&str; 18] = [
    "how", "the", "and", "for", "with", "what", "which", "use", "can", "does", "from", "into",
    "this", "that", "you", "get", "want", "need",
];

/// Up to three call names a topic written as a sentence ("send a raw request") means: each word
/// equal to a part of the name (split at `_` and `.`) scores 2, each word in its description 1;
/// best first, then by name. Empty when no name scores.
fn sentence_topics(topic: &str, catalog: Option<&Catalog>) -> Vec<String> {
    let words: Vec<String> = topic
        .split(|c: char| !c.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|w| w.chars().count() >= 3 && !TOPIC_STOP_WORDS.contains(&w.as_str()))
        .collect();
    if words.is_empty() {
        return Vec::new();
    }
    let mut candidates: Vec<(String, String)> = LOCAL_TOOLS
        .iter()
        .map(|t| (t.name.to_owned(), t.description.to_lowercase()))
        .collect();
    if let Some(c) = catalog {
        for spec in &c.tools {
            let description = spec.description.as_deref().unwrap_or_default();
            candidates.push((spec.name.clone(), description.to_lowercase()));
            for (action, a) in &spec.actions {
                let own = a.description.as_deref().unwrap_or(description);
                candidates.push((format!("{}.{action}", spec.name), own.to_lowercase()));
            }
        }
    }
    let mut scored: Vec<(usize, String)> = candidates
        .into_iter()
        .filter_map(|(name, description)| {
            let parts: Vec<&str> = name.split(['_', '.']).collect();
            let score: usize = words
                .iter()
                .map(|w| {
                    2 * usize::from(parts.contains(&w.as_str()))
                        + usize::from(description.contains(w.as_str()))
                })
                .sum();
            (score > 0).then_some((score, name))
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    scored.into_iter().take(3).map(|(_, name)| name).collect()
}

/// `guide` arguments with the topic found: `name`, `tool` or `do` read as `topic` when no topic is
/// given, else the one key of the call when it holds a string (`topc`), and a server prefix
/// (`mcp__raijin__`) stripped off the topic; a note per reading.
fn topic_alias(arguments: Option<JsonObject>) -> (Option<JsonObject>, Vec<String>) {
    let Some(mut arguments) = arguments else {
        return (None, Vec::new());
    };
    let mut notes = Vec::new();
    if arguments.get("topic").is_none_or(Value::is_null) {
        let key = ["name", "tool", "do"]
            .into_iter()
            .find(|k| arguments.contains_key(*k))
            .map(str::to_owned)
            .or_else(|| match arguments.iter().next() {
                Some((k, Value::String(_))) if arguments.len() == 1 => Some(k.clone()),
                _ => None,
            });
        if let Some(key) = key {
            let value = arguments.remove(&key).unwrap_or_default();
            arguments.insert("topic".to_owned(), value);
            notes.push(format!("read '{key}' as 'topic'"));
        }
    }
    if let Some(Value::String(topic)) = arguments.get("topic")
        && let Some(stripped) = error::strip_server_prefix(topic)
    {
        let stripped = stripped.trim().to_owned();
        notes.push(format!("read '{topic}' as {stripped}"));
        arguments.insert("topic".to_owned(), json!(stripped));
    }
    (Some(arguments), notes)
}

/// A `guide` topic as written in a resource or prompt reference: without `skill://`, a leading `/`
/// (the prompt `/overview`) and a trailing `/SKILL.md`.
fn clean_topic(topic: &str) -> String {
    let t = topic.trim();
    let t = t.strip_prefix("skill://").unwrap_or(t);
    let t = t.trim_start_matches('/');
    let t = t
        .strip_suffix(SKILL_FILE)
        .map_or(t, |rest| rest.trim_end_matches('/'));
    t.to_owned()
}

/// A playbook's `SKILL.md`, or one of its files (`<playbook>/<path>`).
fn playbook_topic(topic: &str) -> Option<CallToolResult> {
    let skills = catalog::skills();
    if let Some(skill) = skills.iter().find(|s| s.name == topic) {
        return Some(plain(skill.raw()));
    }
    let (name, path) = topic.split_once('/')?;
    let body = skills.iter().find(|s| s.name == name)?.file(path)?;
    Some(plain(body))
}

/// The one name among `names` that `topic` means once case and separators are ignored, when
/// every such name stands for the same tool, action, domain or playbook.
fn normalized_topic<'a>(
    topic: &str,
    names: &'a [String],
    catalog: Option<&Catalog>,
) -> Option<&'a str> {
    let wanted = error::norm(topic);
    let identity = |name: &str| match catalog.and_then(|c| c.resolve(name)) {
        Some((tool, Some(action))) => format!("{tool}.{action}"),
        Some((tool, None)) => tool,
        None => name.to_owned(),
    };
    let hits: Vec<&String> = names.iter().filter(|n| error::norm(n) == wanted).collect();
    let identities: BTreeSet<String> = hits.iter().map(|n| identity(n)).collect();
    match (hits.first(), identities.len()) {
        (Some(first), 1) => Some(first.as_str()),
        _ => None,
    }
}

/// Every name `guide` answers: tools, `tool.action`, old member names, domains, playbooks and
/// playbook files.
fn topic_names(catalog: Option<&Catalog>, live: Option<&[Tool]>, other: &[String]) -> Vec<String> {
    let mut names: Vec<String> = LOCAL_TOOLS.iter().map(|t| t.name.to_owned()).collect();
    names.extend([LIFECYCLE.to_owned(), HISTORY.to_owned(), DATA.to_owned()]);
    if !other.is_empty() {
        names.push(OTHER.to_owned());
    }
    if let Some(c) = catalog {
        names.extend(c.tools.iter().map(|t| t.name.clone()));
        names.extend(c.tools.iter().flat_map(|t| {
            actions_of(&t.input_schema)
                .into_iter()
                .map(move |a| format!("{}.{a}", t.name))
        }));
        names.extend(c.aliases.keys().cloned());
        names.extend(c.domains.iter().map(|d| d.name.clone()));
    }
    names.extend(live.unwrap_or_default().iter().map(|t| t.name.to_string()));
    for skill in catalog::skills() {
        names.push(skill.name.to_owned());
        names.extend(
            skill
                .files
                .iter()
                .skip(1)
                .map(|(p, _)| format!("{}/{p}", skill.name)),
        );
    }
    names
}

/// The playbooks as skills-extension entries.
fn skill_entries() -> Vec<McpSkill> {
    catalog::skills()
        .iter()
        .map(|skill| {
            McpSkill::new(
                skill.uri(SKILL_FILE),
                SkillFrontmatter::new(skill.name, &skill.description),
                SkillResources::Files(
                    skill
                        .files
                        .iter()
                        .map(|(path, body)| {
                            SkillResource::from_bytes(skill.uri(path), body.as_bytes())
                        })
                        .collect(),
                ),
            )
        })
        .collect()
}

/// A `skill://<name>/<path>` file's body.
fn skill_file(uri: &str) -> Option<&'static str> {
    let (name, path) = uri.strip_prefix("skill://")?.split_once('/')?;
    catalog::skills()
        .into_iter()
        .find(|skill| skill.name == name)?
        .file(path)
}

impl ServerHandler for Gateway {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                .enable_skills()
                .build(),
        )
        .with_server_info(Implementation::new("raijin", jar::VERSION))
        .with_instructions(self.instructions())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let mut tools = Self::gateway_tools();
        if self.surface == Surface::Full
            && let Ok(assets) = self.assets().await
        {
            for spec in &assets.catalog.tools {
                let schema = spec.input_schema.as_object().cloned().unwrap_or_default();
                let mut tool = Tool::new_with_raw(
                    spec.name.clone(),
                    spec.description.clone().map(Cow::Owned),
                    schema,
                );
                if let Some(annotations) = spec
                    .annotations
                    .clone()
                    .and_then(|v| serde_json::from_value::<ToolAnnotations>(v).ok())
                {
                    tool = tool.with_annotations(annotations);
                }
                tools.push(tool);
            }
        }
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        // What the stdin repair changed in the request (`stdin::repair`); rmcp moves a request's
        // `_meta` into the context.
        let mut notes: Vec<String> = context
            .meta
            .0
            .0
            .get(stdin::NOTES_META_KEY)
            .or_else(|| {
                request
                    .meta
                    .as_ref()
                    .and_then(|m| m.0.0.get(stdin::NOTES_META_KEY))
            })
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let raw_name = request.name.to_string();
        let canonical = error::norm(error::strip_server_prefix(&raw_name).unwrap_or(&raw_name));
        let name = if matches!(canonical.as_str(), "run" | "guide") && canonical != raw_name {
            notes.push(format!("read tool '{raw_name}' as {canonical}"));
            canonical
        } else {
            raw_name
        };
        let arguments = request.arguments;
        let result = match name.as_str() {
            "guide" => self.guide_tool(arguments).await,
            "run" => self.run(arguments).await,
            // A Raijin tool called directly: run it as run would.
            _ if self.runnable(&name).await => {
                let notes = if self.surface == Surface::Full {
                    Vec::new()
                } else {
                    vec![format!(
                        "ran '{name}' through run; call run {{\"do\":\"{name}\", ...}}"
                    )]
                };
                self.run_one(Call {
                    tool: name,
                    arguments,
                    project: None,
                    notes,
                    dropped: Vec::new(),
                })
                .await
            }
            _ if self.surface == Surface::Full => {
                let result = self.forward(&name, arguments, None).await;
                self.spill(result, &name)
            }
            _ => ToolError::new(
                Code::UnknownTool,
                format!("unknown tool \"{name}\": {UNKNOWN_SURFACE_TOOL}"),
            )
            .example(run_example())
            .into_result(),
        };
        Ok(CallToolResponse::Complete(error::with_notes(
            result, &notes,
        )))
    }

    fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListPromptsResult, ErrorData>> + MaybeSendFuture + '_ {
        let prompts = catalog::skills()
            .into_iter()
            .map(|s| Prompt::new(s.name, Some(s.description), None))
            .collect();
        future::ready(Ok(ListPromptsResult::with_all_items(prompts)))
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetPromptResponse, ErrorData>> + MaybeSendFuture + '_ {
        future::ready(prompt(&request.name).map(GetPromptResponse::Complete))
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let mut resources = skill_resources();
        // The running Burp's resources (burp://...), when one answers; skills alone otherwise.
        if let Ok(endpoint) = self.endpoint(None).await
            && let Ok(live) = self.api.resources(&endpoint).await
        {
            resources.extend(live);
        }
        Ok(ListResourcesResult::with_all_items(resources))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let uri = request.uri.as_str();
        if uri.starts_with("skill://") {
            return skill_file(uri)
                .map(|body| {
                    ReadResourceResponse::Complete(ReadResourceResult::new(vec![
                        ResourceContents::text(body, uri).with_mime_type("text/markdown"),
                    ]))
                })
                .ok_or_else(|| {
                    ErrorData::resource_not_found(format!("unknown resource: {uri}"), None)
                });
        }
        let endpoint = self
            .endpoint(None)
            .await
            .map_err(|e| ErrorData::invalid_params(e.error.clone(), None))?;
        match self.api.read_resource(&endpoint, uri).await {
            Ok(Ok(result)) => Ok(ReadResourceResponse::Complete(result)),
            Ok(Err(missing)) => Err(ErrorData::resource_not_found(missing, None)),
            Err(msg) => Err(ErrorData::internal_error(msg, None)),
        }
    }

    fn list_skills(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListSkillsResult, ErrorData>> + MaybeSendFuture + '_ {
        future::ready(Ok(ListSkillsResult::with_all_items(skill_entries())))
    }

    fn get_skill(
        &self,
        request: GetSkillRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<GetSkillResult, ErrorData>> + MaybeSendFuture + '_ {
        future::ready(
            skill_entries()
                .into_iter()
                .find(|skill| skill.uri == request.uri)
                .map(GetSkillResult::new)
                .ok_or_else(|| {
                    ErrorData::invalid_params(format!("no skill at {}", request.uri), None)
                }),
        )
    }
}

/// A playbook as an MCP prompt: its `SKILL.md` without front matter.
fn prompt(name: &str) -> Result<GetPromptResult, ErrorData> {
    let skill = catalog::skills()
        .into_iter()
        .find(|s| s.name == name)
        .ok_or_else(|| ErrorData::invalid_params(format!("unknown prompt {name:?}"), None))?;
    let mut result = GetPromptResult::new(vec![PromptMessage::new_text(Role::User, skill.body())]);
    result.description = Some(skill.description);
    Ok(result)
}

/// Every playbook file as a `skill://` resource; `SKILL.md` carries the playbook's description.
fn skill_resources() -> Vec<Resource> {
    let mut resources = Vec::new();
    for skill in catalog::skills() {
        for (path, body) in &skill.files {
            let resource = Resource::new(skill.uri(path), format!("{}/{path}", skill.name))
                .with_mime_type("text/markdown")
                .with_size(body.len() as u64);
            resources.push(if *path == SKILL_FILE {
                resource.with_description(skill.description.clone())
            } else {
                resource
            });
        }
    }
    resources
}

#[cfg(test)]
mod tests {
    use regex::Regex;

    use super::*;

    fn object(value: Value) -> JsonObject {
        serde_json::from_value(value).expect("object")
    }

    #[test]
    fn a_live_project_warning_is_given_once() {
        let live =
            json!({"project": "main", "error": "project main is running; data may be incomplete"});
        let other = json!({"project": "main", "error": "could not read the archive"});
        let mut seen = BTreeSet::new();
        let mut first = json!({"rows": [], "warnings": [live.clone(), other.clone()]});
        drop_repeated_live_warnings(&mut first, &mut seen);
        assert_eq!(first["warnings"], json!([live.clone(), other.clone()]));
        let mut second = json!({"rows": [], "warnings": [live.clone(), other.clone()]});
        drop_repeated_live_warnings(&mut second, &mut seen);
        assert_eq!(second["warnings"], json!([other]));
        let mut only = json!({"warnings": [live]});
        drop_repeated_live_warnings(&mut only, &mut seen);
        assert_eq!(only["warnings"], json!([]));
    }

    #[test]
    fn normalize_run_unwraps_and_routes_project() {
        let read = |raw: Value| {
            normalize_run(
                object(raw),
                |tool: &str, key: &str| tool == "t" && key == "input",
                |_: &str| false,
            )
        };
        let own = read(json!({"do": "t", "input": {"a": 1}})).expect("normalized");
        assert_eq!(own.arguments, Some(object(json!({"input": {"a": 1}}))));
        let wrapped = read(json!({"do": "u", "input": {"a": 1}})).expect("normalized");
        assert_eq!(wrapped.arguments, Some(object(json!({"a": 1}))));
        let routed = read(json!({"do": "t", "project": "p", "x": 1})).expect("normalized");
        assert_eq!(routed.project.as_deref(), Some("p"));
        assert_eq!(routed.arguments, Some(object(json!({"x": 1}))));
        let flat_wins =
            read(json!({"tool": "u", "a": 2, "args": "{\"a\":1,\"b\":3}"})).expect("normalized");
        assert_eq!(flat_wins.tool, "u");
        assert_eq!(flat_wins.arguments, Some(object(json!({"a": 2, "b": 3}))));
        let no_do = read(json!({"limit": 1})).expect_err("no do");
        assert_eq!(no_do.code, Code::MissingParameter);
        assert_eq!(no_do.param.as_deref(), Some("do"));
    }

    fn local(name: &str) -> &'static LocalTool {
        local_tool(name).expect("local tool")
    }

    fn args_err<T: serde::de::DeserializeOwned + JsonSchema + std::fmt::Debug>(
        tool: &str,
        arguments: Value,
    ) -> ToolError {
        local_args::<T>(local(tool), Some(object(arguments))).expect_err("refused")
    }

    #[test]
    fn local_arguments_are_read_leniently_and_refused_with_a_fix() {
        let (list, notes): (history::list::ListParams, _) =
            local_args(local("history_list"), Some(object(json!({"limit": "1"})))).expect("read");
        assert_eq!(list.limit, Some(1));
        assert_eq!(notes, ["coerced 'limit' from string \"1\" to integer"]);

        let all = args_err::<DownArgs>("burp_down", json!({"all": "maybe"}));
        assert_eq!(
            (all.code, all.param.as_deref()),
            (Code::InvalidType, Some("all"))
        );

        let show = args_err::<history::show::ShowParams>("history_show", json!({}));
        assert_eq!(
            (show.code, show.param.as_deref()),
            (Code::MissingParameter, Some("ref"))
        );
        assert_eq!(
            show.example,
            Some(json!({"do": "history_show", "ref": "main:1"}))
        );

        let mode = args_err::<UpArgs>("burp_up", json!({"mode": "sideways"}));
        assert_eq!(mode.code, Code::InvalidEnum);
        assert_eq!(mode.allowed, [json!("headless"), json!("ui")]);
        let (up, notes): (UpArgs, _) =
            local_args(local("burp_up"), Some(object(json!({"mode": "UI"})))).expect("read");
        assert_eq!(up.mode, Some(Mode::Ui));
        assert_eq!(notes, ["matched 'mode' \"UI\" to \"ui\""]);

        let negative = args_err::<history::list::ListParams>("history_list", json!({"limit": -1}));
        assert_eq!(negative.code, Code::OutOfRange);

        // Only spelled near `limit`: suggested, never retried.
        let typo = args_err::<history::list::ListParams>("history_list", json!({"lmit": 1}));
        assert_eq!(typo.code, Code::UnknownParameter);
        assert_eq!(typo.did_you_mean, ["limit"]);
        assert_eq!(typo.retry, None);

        let destructive = args_err::<DownArgs>("burp_down", json!({"al": true}));
        assert_eq!(destructive.code, Code::UnknownParameter);
        assert_eq!(
            destructive.retry, None,
            "burp_down is destructive: no ready retry"
        );
    }

    /// Parses `call` (a local tool's `run` call) as that tool's arguments.
    fn local_call_fits(call: &JsonObject) -> Result<(), ToolError> {
        let tool = call.get("do").and_then(Value::as_str).unwrap_or_default();
        let mut arguments = call.clone();
        arguments.remove("do");
        let local = local(tool);
        let arguments = Some(arguments);
        match tool {
            "burp_up" => local_args::<UpArgs>(local, arguments).map(drop),
            "burp_down" => local_args::<DownArgs>(local, arguments).map(drop),
            "burp_status" => local_args::<StatusArgs>(local, arguments).map(drop),
            "history_list" => local_args::<history::list::ListParams>(local, arguments).map(drop),
            "history_show" => local_args::<history::show::ShowParams>(local, arguments).map(drop),
            "history_search" => {
                local_args::<history::search::SearchParams>(local, arguments).map(drop)
            }
            "history_endpoints" => {
                local_args::<history::endpoints::EndpointsParams>(local, arguments).map(drop)
            }
            "history_diff" => local_args::<history::diff::DiffParams>(local, arguments).map(drop),
            "history_export" => {
                local_args::<history::export::ExportParams>(local, arguments).map(drop)
            }
            "data_list" => local_args::<data::tools::ListArgs>(local, arguments).map(drop),
            "data_search" => local_args::<data::tools::SearchArgs>(local, arguments).map(drop),
            "data_get" => local_args::<data::tools::GetArgs>(local, arguments).map(drop),
            "data_payloads" => local_args::<data::tools::PayloadsArgs>(local, arguments).map(drop),
            "data_add" => local_args::<data::tools::AddArgs>(local, arguments).map(drop),
            "data_import" => local_args::<data::tools::ImportArgs>(local, arguments).map(drop),
            "data_update" => local_args::<data::tools::UpdateArgs>(local, arguments).map(drop),
            other => panic!("no parser for local tool {other}"),
        }
    }

    #[test]
    fn a_strict_client_filling_every_property_is_read_as_unset() {
        for local in LOCAL_TOOLS {
            let mut call = super::super::args::strict_fill(&(local.schema)());
            call.insert("do".to_owned(), json!(local.name));
            if let Err(e) = local_call_fits(&call) {
                assert!(
                    !matches!(
                        e.code,
                        Code::InvalidEnum | Code::UnknownParameter | Code::OutOfRange
                    ),
                    "{}: {}",
                    local.name,
                    e.error
                );
            }
        }
        let (_, notes): (data::tools::PayloadsArgs, _) = local_args(
            local("data_payloads"),
            Some(object(json!({"attacker": "", "kind": "", "limit": 5}))),
        )
        .expect("read");
        assert_eq!(notes, ["ignored empty optional 'attacker', 'kind'"]);
    }

    #[test]
    fn every_example_in_the_gateway_text_runs() {
        let catalog = Catalog::parse(include_str!(
            "../../../../src/main/resources/catalog/tools.json"
        ))
        .expect("repo catalog");
        let mut texts: Vec<String> = [
            INSTRUCTIONS_HEAD,
            INSTRUCTIONS_LOCAL,
            INSTRUCTIONS_REMOTE,
            INSTRUCTIONS_TAIL,
            GUIDE_HEAD,
            RUN_DESCRIPTION,
            RUN_EXAMPLE,
            MISSING_DO,
            UNKNOWN_SURFACE_TOOL,
        ]
        .map(str::to_owned)
        .to_vec();
        texts.extend(LOCAL_TOOLS.iter().map(|t| t.example.to_owned()));
        let mut checked = 0;
        for text in &texts {
            for (at, _) in text.match_indices("{\"do\":\"") {
                if text[at + 7..].starts_with('<') {
                    continue;
                }
                let call: JsonObject = serde_json::Deserializer::from_str(&text[at..])
                    .into_iter::<JsonObject>()
                    .next()
                    .and_then(Result::ok)
                    .unwrap_or_else(|| panic!("not a JSON call at {:?}", &text[at..]));
                let tool = call["do"].as_str().expect("string do");
                if local_tool(tool).is_some() {
                    local_call_fits(&call).unwrap_or_else(|e| panic!("{tool}: {}", e.error));
                } else {
                    let (name, action) = catalog
                        .resolve(tool)
                        .unwrap_or_else(|| panic!("{tool} is not in the catalog"));
                    let schema = &catalog.tool(&name).expect("catalog tool").input_schema;
                    if let Some(action) = &action {
                        assert!(
                            actions_of(schema).contains(action),
                            "{tool}: {name} has no action {action}"
                        );
                    }
                    let properties = schema["properties"].as_object().expect("properties");
                    for key in call
                        .keys()
                        .filter(|k| !matches!(k.as_str(), "do" | "project"))
                    {
                        assert!(
                            properties.contains_key(key),
                            "{tool} takes no parameter {key}"
                        );
                    }
                    for key in schema["required"].as_array().into_iter().flatten() {
                        let key = key.as_str().expect("string");
                        assert!(
                            key == "action" || call.contains_key(key),
                            "{tool} needs parameter {key}"
                        );
                    }
                }
                checked += 1;
            }
        }
        assert!(
            checked >= 8,
            "only {checked} example calls found in the gateway text"
        );
    }

    #[test]
    fn every_cli_tool_call_in_the_skills_fits() {
        let code = Regex::new(r"`([^`\n]+)`").expect("regex");
        let mut checked = 0;
        for skill in catalog::skills() {
            for (path, body) in &skill.files {
                for found in code.captures_iter(body) {
                    let inline = found[1].trim();
                    let Some(rest) = inline.strip_prefix("run ").filter(|r| r.starts_with('{'))
                    else {
                        continue;
                    };
                    let where_ = format!("{}/{path}: `{inline}`", skill.name);
                    let call: JsonObject = serde_json::from_str(rest)
                        .unwrap_or_else(|e| panic!("{where_}: not a JSON object: {e}"));
                    let tool = call
                        .get("do")
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| panic!("{where_}: no string \"do\""));
                    let Some(local) = local_tool(tool) else {
                        continue;
                    };
                    let schema = (local.schema)();
                    let properties = schema
                        .get("properties")
                        .and_then(Value::as_object)
                        .expect("local tool schema has properties");
                    for key in call.keys().filter(|k| *k != "do" && *k != "project") {
                        assert!(
                            properties.contains_key(key),
                            "{where_}: {tool} takes no parameter {key}"
                        );
                    }
                    let required = schema.get("required").and_then(Value::as_array);
                    for key in required.into_iter().flatten().filter_map(Value::as_str) {
                        assert!(
                            call.contains_key(key),
                            "{where_}: {tool} needs parameter {key}"
                        );
                    }
                    checked += 1;
                }
            }
        }
        assert!(checked > 0, "the skills show no call of a CLI tool");
    }
}

/// The calls weak models make (docs/dev/mcp-gateway-smoke-2.4.1-fixes.md, "Eval weak-model"), and
/// what the gateway must make of them.
#[cfg(test)]
mod weak_model {
    use std::path::Path;

    use super::*;
    use crate::history::list::ListParams;
    use crate::history::search::SearchParams;

    fn catalog() -> Catalog {
        Catalog::parse(include_str!(
            "../../../../src/main/resources/catalog/tools.json"
        ))
        .expect("repo catalog")
    }

    fn object(value: Value) -> JsonObject {
        serde_json::from_value(value).expect("object")
    }

    fn local(name: &str) -> &'static LocalTool {
        local_tool(name).expect("local tool")
    }

    /// A gateway on a target in `dir` with one project, `main`.
    fn gateway(dir: &Path) -> Gateway {
        let target = Target::discover_or_init(dir).expect("target");
        std::fs::create_dir_all(target.projects_dir()).expect("projects dir");
        std::fs::write(target.project_file("main"), b"").expect("main.burp");
        Gateway {
            target: Some(Arc::new(target)),
            target_error: None,
            remote: None,
            surface: Surface::Lean,
            inline_limit: 1 << 20,
            assets: OnceCell::new(),
            api: ToolApi::new(),
            warned_live: std::sync::Mutex::default(),
            data_root: Some(dir.join("cache")),
            data_auto_update: false,
            data_checked: tokio::sync::Mutex::new(false),
            data_cache: std::sync::Mutex::default(),
        }
    }

    #[test]
    fn every_way_of_naming_a_tool_reads_as_the_tool() {
        let catalog = catalog();
        let cases = [
            (json!({"do": "mcp__raijin__history_list", "limit": 1}), true),
            (json!({"do": "raijin.history_list"}), true),
            (json!({"do": "history_list()"}), true),
            (json!({"do": "history_list(limit=1)"}), true),
            (json!({"do": "history/list", "limit": 1}), false),
            (json!({"function": "history_list"}), true),
            (json!({"tool_name": "history_list", "limit": 1}), true),
            (json!({"action": "history_list"}), true),
            (
                json!({"type": "function", "function": {"name": "history_list", "arguments": "{\"limit\":1}"}}),
                true,
            ),
        ];
        for (raw, noted) in cases {
            let call = normalize_run(
                object(raw.clone()),
                |tool, key| tool_declares(Some(&catalog), tool, key),
                |name| names_a_tool(Some(&catalog), name),
            )
            .unwrap_or_else(|e| panic!("{raw}: {}", e.error));
            assert_eq!(
                local_tool(&error::norm(&call.tool)).map(|t| t.name),
                Some("history_list"),
                "{raw}"
            );
            let wants_limit = raw.to_string().contains("limit");
            let limit = call.arguments.as_ref().and_then(|a| a.get("limit"));
            assert_eq!(limit.is_some(), wants_limit, "{raw}");
            if wants_limit {
                assert_eq!(limit, Some(&json!(1)), "{raw}");
            }
            assert_eq!(!call.notes.is_empty(), noted, "{raw}: {:?}", call.notes);
        }
    }

    #[test]
    fn unknown_names_suggest_only_near_tools() {
        let catalog = catalog();
        for name in ["email", "catalog", "details"] {
            let e = unknown_tool_error(&catalog, name, &JsonObject::new());
            assert!(
                !e.did_you_mean.iter().any(|n| n == "ai" || n == "log"),
                "{name}: {:?}",
                e.did_you_mean
            );
            assert_eq!(e.retry, None, "{name}");
        }
        // A running extension older than the catalog: resending the same name fails the same way.
        let same = unknown_tool_error(&catalog, "burp_status", &JsonObject::new());
        assert_eq!(same.retry, None, "{same:?}");
    }

    #[test]
    fn a_quoted_value_with_a_comma_is_not_cut() {
        let (name, args, _) =
            parenthesised("scope.include(url=\"https://a.com/x,y\")").expect("call");
        assert_eq!(name, "scope.include");
        assert_eq!(
            args,
            Some(vec![("url".to_owned(), json!("https://a.com/x,y"))])
        );
        let (_, args, _) =
            parenthesised("util.hash(data: \"a,b\", algorithm: \"MD5\")").expect("call");
        assert_eq!(
            args,
            Some(vec![
                ("data".to_owned(), json!("a,b")),
                ("algorithm".to_owned(), json!("MD5"))
            ])
        );
        let (_, args, _) = parenthesised("scope.include(url=\"https://a.com/x)").expect("call");
        assert_eq!(args, None);
        let (_, args, _) = parenthesised("history_list(limit=1, project='main')").expect("call");
        assert_eq!(
            args,
            Some(vec![
                ("limit".to_owned(), json!(1)),
                ("project".to_owned(), json!("main"))
            ])
        );
    }

    #[test]
    fn usage_shaped_names_are_read_and_types_dropped() {
        let (name, args, dropped) =
            parenthesised("util.hash(data: \"x\", algorithm*: \"MD5\")").expect("call");
        assert_eq!(name, "util.hash");
        assert_eq!(
            args,
            Some(vec![
                ("data".to_owned(), json!("x")),
                ("algorithm".to_owned(), json!("MD5"))
            ])
        );
        assert_eq!(dropped, Vec::<String>::new());
        let (_, args, dropped) = parenthesised("history_list(limit: integer)").expect("call");
        assert_eq!(args, Some(Vec::new()));
        assert_eq!(dropped, ["limit: integer"]);
        let (_, args, _) = parenthesised("history_list({\"limit\":1})").expect("call");
        assert_eq!(args, Some(vec![("limit".to_owned(), json!(1))]));
        let (_, args, _) =
            parenthesised("util.hash(algorithm: \"MD5\"|\"SHA-256\", data: \"x\")").expect("call");
        assert_eq!(args, Some(vec![("data".to_owned(), json!("x"))]));
        let (name, args, _) = spaced("history_list limit=1 offset: 2").expect("spaced");
        assert_eq!(name, "history_list");
        assert_eq!(
            args,
            Some(vec![
                ("limit".to_owned(), json!(1)),
                ("offset".to_owned(), json!(2))
            ])
        );
        let (_, args, _) = spaced("scope.include url=https://a.com/?a=1,2 note=x y").expect("url");
        assert_eq!(
            args,
            Some(vec![
                ("url".to_owned(), json!("https://a.com/?a=1,2")),
                ("note".to_owned(), json!("x y"))
            ])
        );
        assert_eq!(spaced("history list"), None);
        // Cut at a comma: not read at all, rather than sent cut.
        let (_, args, _) = parenthesised("scope.include(url=https://a.com/?a=1,2)").expect("call");
        assert_eq!(args, None);

        let catalog = catalog();
        let call = normalize_run(
            object(json!({"do": "history_list(limit: integer)"})),
            |tool, key| tool_declares(Some(&catalog), tool, key),
            |name| names_a_tool(Some(&catalog), name),
        )
        .expect("read");
        assert_eq!(call.tool, "history_list");
        assert_eq!(call.arguments, None);
        assert_eq!(call.dropped, ["limit: integer"]);
        assert!(
            call.notes
                .contains(&"dropped 'limit: integer': a type from usage, not a value".to_owned()),
            "{:?}",
            call.notes
        );
    }

    #[test]
    fn calls_pasted_in_other_shapes_run() {
        let catalog = catalog();
        let read = |raw: Value| {
            let mut raw = object(raw);
            let mut notes = Vec::new();
            assert_eq!(read_pasted_calls(&mut raw, &mut notes), None, "{raw:?}");
            let call = normalize_run(
                raw,
                |tool, key| tool_declares(Some(&catalog), tool, key),
                |name| names_a_tool(Some(&catalog), name),
            )
            .expect("call");
            assert_ne!(notes, Vec::<String>::new());
            call
        };
        let retry = read(json!({"retry": {"do": "history_list", "limit": 1}}));
        assert_eq!(
            (retry.tool.as_str(), retry.arguments),
            ("history_list", Some(object(json!({"limit": 1}))))
        );
        assert_eq!(read(json!({"see": "history_list"})).tool, "history_list");
        assert_eq!(
            read(json!({"example": {"do": "burp_status"}})).tool,
            "burp_status"
        );
        assert_eq!(
            read(json!({"arguments": "{\"do\":\"burp_status\"}"})).tool,
            "burp_status"
        );
        let openai = read(json!({"tool_calls": [{"function": {
            "name": "functions.history_list", "arguments": "{\"limit\":1}"}}]}));
        assert_eq!(openai.tool, "history_list");
        assert_eq!(openai.arguments, Some(object(json!({"limit": 1}))));
        let uses = read(
            json!({"tool_uses": [{"recipient_name": "functions.history_list",
            "parameters": {"limit": 1}}]}),
        );
        assert_eq!(uses.tool, "history_list");

        let mut step = object(json!({"guide": {"topic": "util.hash"}}));
        assert_eq!(
            read_pasted_calls(&mut step, &mut Vec::new()),
            Some(object(json!({"topic": "util.hash"})))
        );

        let broken = normalize_run(
            object(json!({"arguments": "{bad json"})),
            |_: &str, _: &str| false,
            |_: &str| false,
        )
        .expect_err("broken");
        assert_eq!(
            (broken.code, broken.param.as_deref()),
            (Code::InvalidArguments, Some("arguments"))
        );
        assert!(broken.error.contains("line 1 column"), "{}", broken.error);
    }

    #[test]
    fn several_tool_calls_a_duplicate_and_double_encoded_arguments_are_read() {
        let catalog = catalog();
        let normalize = |raw: JsonObject| {
            normalize_run(
                raw,
                |tool, key| tool_declares(Some(&catalog), tool, key),
                |name| names_a_tool(Some(&catalog), name),
            )
            .expect("call")
        };
        let mut raw = object(json!({"tool_calls": [
            {"function": {"name": "history_list", "arguments": "{\"limit\":1}"}},
            {"function": {"name": "burp_status", "arguments": "{}"}}
        ]}));
        let mut notes = Vec::new();
        assert_eq!(read_pasted_calls(&mut raw, &mut notes), None);
        assert_eq!(
            raw.get("batch"),
            Some(&json!([{"do": "history_list", "limit": 1}, {"do": "burp_status"}]))
        );
        assert!(
            notes.contains(&"read 'tool_calls' as a batch".to_owned()),
            "{notes:?}"
        );

        let mut raw = object(json!({"arguments": "\"{\\\"do\\\":\\\"burp_status\\\"}\""}));
        let mut notes = Vec::new();
        assert_eq!(read_pasted_calls(&mut raw, &mut notes), None);
        assert_eq!(normalize(raw).tool, "burp_status");
        assert!(notes.contains(&DOUBLE_ENCODED.to_owned()), "{notes:?}");

        let wrapped = normalize(object(json!({
            "do": "history_list", "arguments": "\"{\\\"limit\\\":1}\""
        })));
        assert_eq!(wrapped.arguments, Some(object(json!({"limit": 1}))));
        assert!(
            wrapped.notes.contains(&DOUBLE_ENCODED.to_owned()),
            "{:?}",
            wrapped.notes
        );

        let twice = normalize(object(json!({"do": "util.hash(data: \"x\")", "data": "y"})));
        assert_eq!(twice.arguments, Some(object(json!({"data": "y"}))));
        assert!(
            twice
                .notes
                .contains(&"'data' given twice; used the top-level \"y\"".to_owned()),
            "{:?}",
            twice.notes
        );

        let open = normalize(object(
            json!({"do": "scope.include(url: \"https://a.com/x)"}),
        ));
        assert_eq!(open.dropped, ["(url: \"https://a.com/x)"]);
        assert!(
            !open.notes.iter().any(|n| n.contains("a type from usage")),
            "{:?}",
            open.notes
        );
    }

    #[test]
    fn source_all_is_read_as_no_source() {
        let (args, notes): (data::tools::SearchArgs, _) = local_args(
            local("data_search"),
            Some(object(json!({"source": "ALL", "query": "svg"}))),
        )
        .expect("search");
        assert_eq!(args.filters.source, None);
        assert_eq!(notes, ["read 'source' \"all\" as unset"]);
    }

    #[test]
    fn a_verb_leads_and_the_fallback_is_never_the_data_domain() {
        let catalog = catalog();
        for name in [
            "remove_bcheck",
            "delete_scope",
            "delete_finding",
            "send_payload",
            "fuzz_xss",
            "clear_history",
            "drop_request",
            "nope_tool",
        ] {
            let e = unknown_tool_error(&catalog, name, &JsonObject::new());
            assert!(
                e.retry
                    .as_ref()
                    .is_none_or(|r| r["do"] != json!("data_search")),
                "{name}: {:?}",
                e.retry
            );
            assert_ne!(e.see, Some(guide_call(Some(DATA))), "{name}");
        }
        let first = |name: &str| {
            unknown_tool_error(&catalog, name, &JsonObject::new())
                .did_you_mean
                .first()
                .cloned()
                .unwrap_or_default()
        };
        assert_eq!(first("remove_bcheck"), "custom_check.bcheck_remove");
        assert_eq!(first("delete_scope"), "scope.remove");
        assert_eq!(first("delete_finding"), "findings.remove");
        assert_eq!(first("send_payload"), "http_send_request");
        assert_eq!(first("scan_xss"), "scanner.start_audit");
        assert_eq!(first("forward_request"), "proxy_intercept.forward");
        assert_eq!(first("intercept_on"), "proxy_intercept.enable");
        assert!(first("fuzz_xss").contains("fuzz"), "{}", first("fuzz_xss"));
        // A remove verb suggests only the removal of what the other words name.
        for name in ["clear_history", "delete_all", "remove_all"] {
            let e = unknown_tool_error(&catalog, name, &JsonObject::new());
            assert!(
                e.did_you_mean
                    .iter()
                    .all(|h| !["remove", "clear", "delete", "drop"]
                        .iter()
                        .any(|v| h.contains(v))),
                "{name}: {:?}",
                e.did_you_mean
            );
        }
        let drop = unknown_tool_error(&catalog, "drop_request", &JsonObject::new());
        assert_eq!(
            drop.did_you_mean.first().map(String::as_str),
            Some("proxy_intercept.drop")
        );
        assert_eq!(drop.retry, None);
        let scope = unknown_tool_error(&catalog, "delete_scope", &JsonObject::new());
        assert_eq!(scope.retry, None);

        let library = unknown_tool_error(&catalog, "data.library.get", &JsonObject::new());
        assert!(
            library.did_you_mean.contains(&"data_get".to_owned()),
            "{library:?}"
        );
        assert_eq!(library.see, Some(guide_call(Some(DATA))));
        assert_eq!(library.retry, None);
    }

    #[tokio::test]
    async fn a_guide_topic_led_by_its_domain_reads_as_the_tool() {
        let dir = tempfile::tempdir().expect("temp dir");
        let gateway = gateway(dir.path());
        gateway
            .assets
            .set(Ok(Arc::new(Assets { catalog: catalog() })))
            .expect("assets");
        let text_of =
            |r: &CallToolResult| r.content[0].as_text().map_or_default(|t| t.text.clone());
        for (topic, domain) in [
            ("analysis.util.hash", "analysis"),
            ("data.data_search", DATA),
        ] {
            let result = gateway
                .guide(GuideArgs {
                    topic: Some(topic.to_owned()),
                })
                .await;
            let text = text_of(&result);
            assert_ne!(result.is_error, Some(true), "{topic}: {text}");
            assert!(
                text.contains(&format!("dropped the domain '{domain}' from the topic")),
                "{topic}: {text}"
            );
        }
        for topic in ["data.nope_nothing", "analysis.nope_nothing"] {
            let result = gateway
                .guide(GuideArgs {
                    topic: Some(topic.to_owned()),
                })
                .await;
            assert_eq!(result.is_error, Some(true), "{topic}");
            let value: Value = serde_json::from_str(&text_of(&result)).expect("json");
            let domain = topic.split('.').next().unwrap_or_default();
            assert!(
                !value["did_you_mean"]
                    .as_array()
                    .is_some_and(|names| names.contains(&json!(domain))),
                "{topic}: {value}"
            );
        }
    }

    #[test]
    fn invented_names_suggest_the_call_they_mean() {
        let catalog = catalog();
        let first = |name: &str| {
            let e = unknown_tool_error(&catalog, name, &JsonObject::new());
            (e.did_you_mean.first().cloned().unwrap_or_default(), e)
        };
        let (hit, xss) = first("xss.find");
        assert_eq!(hit, "data_search");
        assert_eq!(
            xss.retry,
            Some(json!({"do": "data_search", "source": "xss"}))
        );
        assert_eq!(xss.see, Some(guide_call(Some(DATA))));
        let (hit, up) = first("burp_start");
        assert_eq!(hit, "burp_up");
        assert_eq!(up.retry, Some(json!({"do": "burp_up"})));
        assert_eq!(
            first("stop_burp").1.retry,
            None,
            "burp_down is never retried"
        );
        assert_eq!(first("md5.compute").0, "util.hash");
        assert_eq!(first("bchecks").0, "data_search");
        assert_eq!(first("url_bypass").0, "data_payloads");
        assert_eq!(first("get_status").0, "burp_status");
        let (hit, data) = first("data");
        assert_eq!(hit, "data_search");
        assert_eq!(data.retry, None);
        let (_, nothing) = first("qwertyzxcv");
        assert!(nothing.error.contains("Domains:"), "{}", nothing.error);
        assert!(nothing.see.is_some());
        let (hit, remove) = first("Scope.Remove");
        assert_eq!(hit, "scope.remove");
        assert_eq!(remove.retry, None);
        assert!(remove.error.contains(DESTRUCTIVE_EXACT), "{}", remove.error);
    }

    #[test]
    fn every_retry_for_a_typo_runs_as_sent() {
        let catalog = catalog();
        let mut retries = 0;
        for name in [
            "scope.chek",
            "util.hsah",
            "proxy_histroy",
            "histroy_list",
            "burp_stauts",
        ] {
            let e = unknown_tool_error(&catalog, name, &JsonObject::new());
            let Some(retry) = e.retry.as_ref().and_then(Value::as_object) else {
                continue;
            };
            retries += 1;
            let tool = retry["do"].as_str().expect("string do");
            if local_tool(tool).is_none() {
                let (resolved, action) = catalog.resolve(tool).expect("resolves");
                let grouped = !catalog.tool(&resolved).expect("tool").actions.is_empty();
                assert!(
                    !grouped || action.is_some(),
                    "{name}: {tool} needs an action"
                );
            }
            let schema = safe_call_schema(&catalog, tool).expect("a safe exact call");
            let mut args = retry.clone();
            args.remove("do");
            assert!(call_fits(&schema, &args), "{name}: {retry:?}");
        }
        assert!(retries >= 2, "only {retries} typos got a retry");
    }

    #[test]
    fn parameter_names_are_read_as_declared() {
        let list = local("history_list");
        let (plain, _): (ListParams, _) =
            local_args(list, Some(object(json!({"limit": 2})))).expect("limit");
        assert_eq!(plain.limit, Some(2));
        for raw in [json!({"maxResults": 1}), json!({"Limit*": 1})] {
            let (params, notes): (ListParams, _) =
                local_args(list, Some(object(raw.clone()))).expect("renamed");
            assert_eq!(params.limit, Some(1), "{raw}");
            assert!(
                notes.iter().any(|n| n.starts_with("read '")),
                "{raw}: {notes:?}"
            );
        }
        let both = local_args::<ListParams>(list, Some(object(json!({"count": 1, "limit": 2}))))
            .expect_err("count and limit");
        assert_eq!(both.code, Code::UnknownParameter);
        assert_eq!(both.retry, None);

        let (search, notes): (SearchParams, _) = local_args(
            local("history_search"),
            Some(object(json!({"query": "(", "regex": true}))),
        )
        .expect("search");
        assert_eq!(search.pattern, "(");
        assert!(
            notes.contains(&"read 'query' as 'pattern'".to_owned()),
            "{notes:?}"
        );
        assert!(
            notes.contains(&"dropped 'regex': 'pattern' is always a regex here".to_owned()),
            "{notes:?}"
        );
        assert!(read_bail(Some(json!(1))).expect("bail").0);
    }

    #[test]
    fn a_project_in_another_case_is_matched_and_an_unknown_one_never_starts_burp() {
        let dir = tempfile::tempdir().expect("temp dir");
        let gateway = gateway(dir.path());
        let (name, note) = gateway.resolve_project("MAIN").expect("matched");
        assert_eq!(name, "main");
        assert_eq!(
            note.as_deref(),
            Some("matched project \"MAIN\" to \"main\"")
        );
        let e = gateway.resolve_project("nope").expect_err("unknown");
        assert_eq!(e.code, Code::InvalidEnum);
        assert_eq!(e.allowed, [json!("main")]);
        assert!(!e.to_value().to_string().contains("burp_up"), "{}", e.error);

        let target = gateway.target.as_ref().expect("target");
        let mut args = object(json!({"ref": 1}));
        let notes = bare_refs(target, local("history_show"), Some(&mut args));
        assert_eq!(args["ref"], json!("main:1"));
        assert_eq!(notes, ["read ref \"1\" as \"main:1\""]);
    }

    #[tokio::test]
    async fn data_tools_search_and_save_without_network() {
        let dir = tempfile::tempdir().expect("temp dir");
        let gateway = gateway(dir.path());
        let xss = dir.path().join("cache/xss");
        std::fs::create_dir_all(xss.join("json")).expect("xss dir");
        let manifest = store::Manifest {
            source: data::Source::Xss,
            repo: "PortSwigger/xss-cheatsheet-data".into(),
            branch: "master".into(),
            commit: None,
            fetched_at_ms: crate::util::now_ms(),
            files: 1,
        };
        std::fs::write(
            xss.join("manifest.json"),
            serde_json::to_vec(&manifest).expect("manifest"),
        )
        .expect("write manifest");
        std::fs::write(
            xss.join("json/events.json"),
            r#"{"onload":{"description":"Fires on load","tags":[{"tag":"svg","code":"<svg onload=alert(1)>","browsers":["chrome"],"interaction":false}]}}"#,
        )
        .expect("events");
        // run_resolved, not run: run reads the jar's catalog, which may need the network.
        let call = |v: Value| {
            let gateway = &gateway;
            async move {
                let mut arguments = object(v);
                let tool = arguments
                    .remove("do")
                    .and_then(|t| t.as_str().map(str::to_owned))
                    .expect("do");
                let call = Call {
                    tool,
                    arguments: Some(arguments),
                    project: None,
                    notes: Vec::new(),
                    dropped: Vec::new(),
                };
                let (_, result) = gateway.run_resolved(call).await;
                (result.is_error == Some(true), result_value(&result))
            }
        };

        let (failed, found) = call(json!({"do": "data_search", "query": "svg onload"})).await;
        assert!(!failed, "{found}");
        assert_eq!(found["total"], 1, "{found}");
        assert_eq!(found["rows"][0]["id"], "xss:events/onload/svg");

        let (failed, plural) = call(json!({"do": "data_search", "category": "Event"})).await;
        assert!(!failed, "{plural}");
        assert_eq!(plural["total"], 1, "{plural}");
        assert_eq!(
            plural["notes"],
            json!(["matched 'category' \"Event\" to \"events\""])
        );
        let (failed, nope) = call(json!({"do": "data_search", "category": "nope"})).await;
        assert!(failed);
        assert_eq!(nope["code"], "invalid_enum", "{nope}");
        assert_eq!(nope["allowed"], json!(["events"]));
        let (failed, got) = call(json!({"do": "data_get", "id": "events/onload/svg"})).await;
        assert!(!failed, "{got}");
        assert_eq!(got["id"], "xss:events/onload/svg");

        let (failed, added) =
            call(json!({"do": "data_add", "category": "waf", "payload": "<x>"})).await;
        assert!(!failed, "{added}");
        assert_eq!(added["added"], true);
        assert!(dir.path().join("data/payloads/waf.json").is_file());
        let (_, again) = call(json!({"do": "data_add", "category": "waf", "payload": "<x>"})).await;
        assert_eq!(again["added"], false, "{again}");

        let (_, payloads) = call(json!({"do": "data_payloads", "source": "custom"})).await;
        assert_eq!(payloads["payloads"], json!(["<x>"]), "{payloads}");

        let (failed, refused) =
            call(json!({"do": "data_import", "id": "xss:events/onload/svg"})).await;
        assert!(failed);
        assert_eq!(refused["code"], "invalid_arguments", "{refused}");
    }

    #[test]
    fn one_action_shows_its_own_parameters() {
        let catalog = catalog();
        let topic = tool_topic("util.hash", Some(&catalog), None).expect("util.hash");
        let usage = topic["usage"].as_str().expect("usage");
        assert!(!usage.contains("GZIP"), "{usage}");
    }
}
