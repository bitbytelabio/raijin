//! `raijin mcp`: a stdio MCP server (rmcp; MCP 2026-07-28 and the legacy initialize era) with two tools, `guide` and `run`, in front of Raijin's tool API, the Burp lifecycle and the offline history engine; playbooks as prompts, skills and `skill://` resources.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::future::{self, Future};
use std::path::PathBuf;
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
use super::args::{parse_args, schema_of};
use super::error::{self, Code, ToolError};
use super::spill;
use crate::burp::{instance, launch};
use crate::catalog::{self, Catalog, SKILL_FILE, ToolSpec};
use crate::config::{Mode, Remote, Target, user_state_dir};
use crate::history;
use crate::jar::{self, Assets};
use crate::util::{suggest, truncate_utf8};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Surface {
    /// guide and run only.
    Lean,
    /// Also every Raijin tool, callable directly.
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
inline limit come back as {saved_to, preview}: parse the file with jq/python, never read it whole. Read the \
overview playbook first: guide({\"topic\":\"overview\"}), also the prompt /overview and skill://overview/SKILL.md.";

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
const OTHER_DESCRIPTION: &str =
    "Tools the running Raijin has that this CLI's catalog does not list.";
const OTHER_NOTES: &str = "";

/// Bytes of a tool's first description line shown in a domain listing.
const SUMMARY_BYTES: usize = 200;

/// The playbook of a domain the CLI owns.
fn local_playbook(domain: &str) -> &'static str {
    if domain == HISTORY {
        "offline-history"
    } else {
        "overview"
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
        description: "amber JSON export of each project (plus the archive files) under .raijin/exports/.",
        schema: schema_of::<history::export::ExportParams>,
        example: r#"{"do":"history_export"}"#,
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

/// A local tool's arguments read as `T`, with `local`'s example and destructiveness for errors.
fn local_args<T: serde::de::DeserializeOwned + JsonSchema>(
    local: &LocalTool,
    arguments: Option<JsonObject>,
) -> Result<(T, Vec<String>), ToolError> {
    parse_args(local.name, arguments, &local.example(), local.destructive)
}

fn run_example() -> Value {
    serde_json::from_str(RUN_EXAMPLE).unwrap_or_default()
}

/// An error envelope's `retry` and `example` calls with `"project"` added, so resending them reaches
/// the same Burp; any other result is returned as is.
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
    for key in ["retry", "example"] {
        if let Some(Value::Object(call)) = envelope.get_mut(key)
            && call.contains_key("do")
        {
            call.entry("project").or_insert_with(|| json!(project));
        }
    }
    result.content[0] = ContentBlock::text(Value::Object(envelope).to_string());
    result
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

/// One tool call as `run` resolved it.
#[derive(Debug, PartialEq)]
struct Call {
    /// What `do` named: a tool, `<tool>.<action>` or an old member name.
    tool: String,
    arguments: Option<JsonObject>,
    /// The Burp to run it on, for a tool that does not take `project` itself.
    project: Option<String>,
}

/// Keys a model wraps a tool's parameters in, in the order they are tried.
const ARGUMENT_KEYS: [&str; 5] = ["arguments", "args", "params", "parameters", "input"];

/// Reads a `run` call: `do` (else `tool`, else `name`) names the tool, `project` picks the Burp
/// unless the tool takes a `project` itself, a wrapper object (`arguments`, `args`, ..., also as a
/// JSON string) is unwrapped unless the tool declares that key (`declares(tool, key)`), and every
/// other key is a parameter of the tool. Keys already flat win over wrapped ones.
fn normalize_run(
    mut raw: JsonObject,
    declares: impl Fn(&str, &str) -> bool,
) -> Result<Call, ToolError> {
    let named = match raw.remove("do") {
        Some(value) => Some(value),
        None => ["tool", "name"]
            .into_iter()
            .find(|k| raw.get(*k).is_some_and(Value::is_string))
            .and_then(|k| raw.remove(k)),
    };
    let tool = match named {
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_owned(),
        _ => {
            return Err(ToolError::new(Code::MissingParameter, MISSING_DO)
                .param("do")
                .example(run_example())
                .see("guide {}"));
        }
    };
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
        let value = raw.remove(key).unwrap_or_default();
        let wrapped = match &value {
            Value::Object(o) => Some(o.clone()),
            Value::String(s) => serde_json::from_str::<JsonObject>(s).ok(),
            _ => None,
        };
        let Some(wrapped) = wrapped else {
            return Err(ToolError::new(
                Code::InvalidType,
                format!(
                    "run: '{key}' must be a JSON object of the tool's parameters, or leave it out and put the parameters next to \"do\"."
                ),
            )
            .param(key)
            .got(value));
        };
        for (k, v) in wrapped {
            raw.entry(k).or_insert(v);
        }
    }
    Ok(Call {
        tool,
        arguments: (!raw.is_empty()).then_some(raw),
        project,
    })
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

/// `inputSchema.properties.action.enum` of a schema: a grouped tool's actions.
fn actions_of(schema: &Value) -> Vec<String> {
    schema
        .pointer("/properties/action/enum")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
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
    };
    let service = gateway.serve(rmcp::transport::stdio()).await?;
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
        // A client may fill every declared property; a null `batch` means no batch.
        if let Some(batch) = raw.remove("batch").filter(|b| !b.is_null()) {
            if ["do", "tool", "name"].iter().any(|k| raw.contains_key(*k)) {
                return ToolError::new(
                    Code::InvalidArguments,
                    "run: pass either do or batch, not both.",
                )
                .into_result();
            }
            if let Some(extra) = raw
                .keys()
                .find(|k| !matches!(k.as_str(), "bail" | "project"))
            {
                return ToolError::new(
                    Code::UnknownParameter,
                    "run with batch takes only batch, bail and project; put each tool's parameters inside its step.",
                )
                .param(extra.as_str())
                .into_result();
            }
            let mut notes = Vec::new();
            let steps = match batch {
                Value::Array(steps) => steps,
                Value::String(s) => match serde_json::from_str::<Vec<Value>>(&s) {
                    Ok(steps) => {
                        notes.push("parsed 'batch' from a JSON string".to_owned());
                        steps
                    }
                    Err(_) => return batch_type_error("a string", Value::String(s)),
                },
                other => {
                    let kind = match &other {
                        Value::Object(_) => "an object",
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
            let bail = raw.get("bail").and_then(Value::as_bool).unwrap_or(false);
            let project = raw
                .get("project")
                .and_then(Value::as_str)
                .map(str::to_owned);
            return self.batch(steps, bail, project, &notes).await;
        }
        // `bail` is run's own (batch) key, not a tool parameter.
        if raw
            .get("bail")
            .is_some_and(|b| b.is_boolean() || b.is_null())
        {
            raw.remove("bail");
        }
        let assets = self.assets().await.ok();
        let catalog = assets.as_deref().map(|a| &a.catalog);
        match normalize_run(raw, |tool, key| tool_declares(catalog, tool, key)) {
            Ok(call) => self.run_one(call).await,
            Err(e) => e.into_result(),
        }
    }

    /// Steps in order; each result inline (no per-step spill), the whole batch spilled once.
    async fn batch(
        &self,
        steps: Vec<Value>,
        bail: bool,
        project: Option<String>,
        notes: &[String],
    ) -> CallToolResult {
        let assets = self.assets().await.ok();
        let catalog = assets.as_deref().map(|a| &a.catalog);
        let total = steps.len();
        let mut out = Vec::with_capacity(total);
        let mut stopped_after = None;
        for (i, step) in steps.into_iter().enumerate() {
            let named = ["do", "tool", "name"]
                .iter()
                .find_map(|k| step.get(*k).cloned())
                .unwrap_or(Value::Null);
            let (ok, result) = match step {
                Value::Object(mut step) if !step.contains_key("batch") => {
                    if let Some(project) = &project
                        && !step.contains_key("project")
                    {
                        step.insert("project".to_owned(), json!(project));
                    }
                    match normalize_run(step, |tool, key| tool_declares(catalog, tool, key)) {
                        Ok(call) => {
                            let (_, result) = self.run_raw(call).await;
                            (result.is_error != Some(true), result_value(&result))
                        }
                        Err(e) => (false, e.to_value()),
                    }
                }
                _ => (
                    false,
                    ToolError::new(
                        Code::InvalidArguments,
                        "each step is one {\"do\":\"<tool>\", ...}; batch cannot nest.",
                    )
                    .example(run_example())
                    .to_value(),
                ),
            };
            let failed = (!ok).then(|| result.clone());
            out.push(json!({"step": i + 1, "do": named, "ok": ok, "result": result}));
            if let Some(failed) = failed
                && bail
            {
                stopped_after = Some((i + 1, failed));
                break;
            }
        }
        let mut value = Map::new();
        let result = if let Some((k, failed)) = stopped_after {
            let reason = failed.get("error").and_then(Value::as_str).map_or_else(
                || match &failed {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                },
                str::to_owned,
            );
            let code = failed
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("tool_failed")
                .to_owned();
            let retryable = failed
                .get("retryable")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let mut message = format!("step {k} of {total} failed: {reason}");
            if !retryable && !message.ends_with(error::FINAL_SENTENCE) {
                message.push_str(error::FINAL_SENTENCE);
            }
            value.insert("error".to_owned(), json!(message));
            value.insert("code".to_owned(), json!(code));
            value.insert("steps".to_owned(), json!(out));
            value.insert("stopped_after".to_owned(), json!(k));
            value.insert(
                "not_run".to_owned(),
                json!(((k + 1)..=total).collect::<Vec<_>>()),
            );
            value.insert("retryable".to_owned(), json!(retryable));
            CallToolResult::error(vec![ContentBlock::text(Value::Object(value).to_string())])
        } else {
            value.insert("steps".to_owned(), json!(out));
            text(&Value::Object(value))
        };
        self.spill(error::with_notes(result, notes), "batch")
    }

    async fn run_one(&self, call: Call) -> CallToolResult {
        let (tool, result) = self.run_raw(call).await;
        self.spill(result, &tool)
    }

    /// Runs one call: a local tool (also named in another case or with `-`/`.` separators) runs
    /// here, anything else goes to Raijin under the name as given, which the extension resolves.
    /// Returns the tool that ran and its result.
    async fn run_raw(&self, call: Call) -> (String, CallToolResult) {
        let Call {
            tool,
            mut arguments,
            project,
        } = call;
        let (local, note) = match local_tool(&tool) {
            Some(local) => (Some(local), None),
            None => match LOCAL_TOOLS.iter().find(|t| t.name == error::norm(&tool)) {
                Some(local) if local.destructive => {
                    let mut retry = Map::new();
                    retry.insert("do".to_owned(), json!(local.name));
                    retry.extend(arguments.unwrap_or_default());
                    let result = ToolError::new(
                        Code::UnknownTool,
                        format!(
                            "unknown tool \"{tool}\"; did you mean {}? It is destructive, so it runs only under its exact name.",
                            local.name
                        ),
                    )
                    .did_you_mean(vec![local.name.to_owned()])
                    .retry(Value::Object(retry))
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
        if let Some(project) = project
            && (local.schema)()
                .get("properties")
                .and_then(Value::as_object)
                .is_some_and(|p| p.contains_key("project"))
        {
            arguments
                .get_or_insert_with(JsonObject::new)
                .entry("project")
                .or_insert_with(|| json!(project));
        }
        let result = if local.domain == LIFECYCLE {
            self.lifecycle(local, arguments).await
        } else {
            self.history(local, arguments).await
        };
        let notes: Vec<String> = note.into_iter().collect();
        (local.name.to_owned(), error::with_notes(result, &notes))
    }

    /// Whether `run` can run `name`: a local tool, a catalog tool or a resolvable alias.
    async fn runnable(&self, name: &str) -> bool {
        local_tool(name.trim()).is_some()
            || self
                .assets()
                .await
                .is_ok_and(|a| a.catalog.resolve(name).is_some())
    }

    /// Sends `tool` to Raijin as named; the extension resolves the name and reports unknown ones.
    async fn forward(
        &self,
        tool: &str,
        arguments: Option<JsonObject>,
        project: Option<&str>,
    ) -> CallToolResult {
        let endpoint = match self.endpoint(project).await {
            Ok(e) => e,
            Err(e) => return e.into_result(),
        };
        match self.api.call(&endpoint, tool, arguments).await {
            Ok(result) => match project {
                Some(project) => with_project(result, project),
                None => result,
            },
            Err(ApiError::Unreachable(msg)) => ToolError::new(
                Code::RaijinUnreachable,
                format!("{msg}; check run {{\"do\":\"burp_status\"}}."),
            )
            .into_result(),
            Err(ApiError::Other(msg)) => ToolError::new(Code::Internal, msg).into_result(),
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
        let topic = args
            .topic
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty());
        let result = match topic {
            None => plain(
                self.overview(catalog, live.as_deref(), &other, catalog_error)
                    .await,
            ),
            Some(topic) => {
                let names = topic_names(catalog, live.as_deref(), &other);
                self.topic(topic, catalog, live.as_deref(), &other)
                    .or_else(|| {
                        let same = normalized_topic(topic, &names, catalog)?;
                        self.topic(same, catalog, live.as_deref(), &other)
                    })
                    .unwrap_or_else(|| {
                        ToolError::new(
                            Code::UnknownTopic,
                            format!(
                                "unknown topic \"{topic}\"; guide {{}} lists every tool, domain and playbook."
                            ),
                        )
                        .did_you_mean(
                            suggest(topic, names.iter().map(String::as_str), 3)
                                .into_iter()
                                .map(str::to_owned)
                                .collect(),
                        )
                        .see("guide {}")
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
            let actions = view.map(|v| actions_of(&v.schema)).unwrap_or_default();
            if actions.is_empty() {
                name.to_owned()
            } else {
                format!("{name}({})", actions.join("|"))
            }
        };
        for d in catalog.map(|c| c.domains.as_slice()).unwrap_or_default() {
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
        let (description, notes, playbook, tools) = if domain == LIFECYCLE || domain == HISTORY {
            let (tools, description, notes): (Vec<&LocalTool>, _, _) = if domain == LIFECYCLE {
                (
                    self.lifecycle_tools(),
                    LIFECYCLE_DESCRIPTION,
                    LIFECYCLE_NOTES,
                )
            } else {
                (
                    LOCAL_TOOLS.iter().filter(|t| t.domain == HISTORY).collect(),
                    HISTORY_DESCRIPTION,
                    HISTORY_NOTES,
                )
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
        Some(json!({
            "domain": domain,
            "description": description,
            "notes": notes,
            "playbook": playbook,
            "tools": tools,
        }))
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
        match tool {
            "burp_up" => {
                let (args, notes): (UpArgs, _) = local_args(local, arguments)?;
                let project = target
                    .project_or_default(args.project.as_deref())
                    .map_err(err)?;
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
                    vec![
                        target
                            .project_or_default(args.project.as_deref())
                            .map_err(err)?,
                    ]
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

    async fn history(
        &self,
        local: &'static LocalTool,
        arguments: Option<JsonObject>,
    ) -> CallToolResult {
        let target = match self.target_or_error() {
            Ok(t) => t.clone(),
            Err(e) => return e.into_result(),
        };
        let run = move || -> Result<(Value, Vec<String>), ToolError> {
            let failed = |e: anyhow::Error| ToolError::new(Code::ToolFailed, format!("{e:#}"));
            let to_value = |v: Result<Value, serde_json::Error>| {
                v.map_err(|e| ToolError::new(Code::Internal, e.to_string()))
            };
            match local.name {
                "history_list" => {
                    let (params, notes) = local_args(local, arguments)?;
                    let value = history::list::run(&target, &params).map_err(failed)?;
                    Ok((to_value(serde_json::to_value(value))?, notes))
                }
                "history_show" => {
                    let (params, notes) = local_args(local, arguments)?;
                    Ok((history::show::run(&target, &params).map_err(failed)?, notes))
                }
                "history_search" => {
                    let (params, notes) = local_args(local, arguments)?;
                    let value = history::search::run(&target, &params).map_err(failed)?;
                    Ok((to_value(serde_json::to_value(value))?, notes))
                }
                "history_endpoints" => {
                    let (params, notes) = local_args(local, arguments)?;
                    let value = history::endpoints::run(&target, &params).map_err(failed)?;
                    Ok((to_value(serde_json::to_value(value))?, notes))
                }
                "history_diff" => {
                    let (params, notes) = local_args(local, arguments)?;
                    Ok((history::diff::run(&target, &params).map_err(failed)?, notes))
                }
                _ => {
                    let (params, notes) = local_args(local, arguments)?;
                    Ok((
                        history::export::run(&target, &params).map_err(failed)?,
                        notes,
                    ))
                }
            }
        };
        match tokio::task::spawn_blocking(run).await {
            Ok(Ok((value, notes))) => error::with_notes(text(&value), &notes),
            Ok(Err(e)) => e.into_result(),
            Err(e) => ToolError::new(Code::Internal, format!("{} panicked: {e}", local.name))
                .into_result(),
        }
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
    } else if let Some((name, action)) = catalog.and_then(|c| c.resolve(topic))
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
    let mut out = json!({"do": name});
    if let Some(action) = action {
        out["action"] = json!(action);
    }
    out["domain"] = json!(domain);
    out["playbook"] = json!(playbook);
    out["description"] = json!(view.description);
    out["annotations"] = view.annotations.unwrap_or(Value::Null);
    out["inputSchema"] = view.schema;
    Some(out)
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
    names.extend([LIFECYCLE.to_owned(), HISTORY.to_owned()]);
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
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.to_string();
        let arguments = request.arguments;
        let result = match name.as_str() {
            "guide" => {
                match parse_args::<GuideArgs>(
                    &name,
                    arguments,
                    &json!({"topic": "overview"}),
                    false,
                ) {
                    Ok((args, notes)) => error::with_notes(self.guide(args).await, &notes),
                    Err(e) => e.into_result(),
                }
            }
            "run" => self.run(arguments).await,
            // A Raijin tool called directly: run it as run would.
            _ if self.runnable(&name).await => {
                self.run_one(Call {
                    tool: name,
                    arguments,
                    project: None,
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
        Ok(CallToolResponse::Complete(result))
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
                    ErrorData::invalid_params(format!("unknown resource: {uri}"), None)
                });
        }
        let endpoint = self
            .endpoint(None)
            .await
            .map_err(|e| ErrorData::invalid_params(e.error.clone(), None))?;
        self.api
            .read_resource(&endpoint, uri)
            .await
            .map(ReadResourceResponse::Complete)
            .map_err(|msg| ErrorData::internal_error(msg, None))
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
    fn normalize_run_unwraps_and_routes_project() {
        let declares = |tool: &str, key: &str| tool == "t" && key == "input";
        let own = normalize_run(object(json!({"do": "t", "input": {"a": 1}})), declares)
            .expect("normalized");
        assert_eq!(own.arguments, Some(object(json!({"input": {"a": 1}}))));
        let wrapped = normalize_run(object(json!({"do": "u", "input": {"a": 1}})), declares)
            .expect("normalized");
        assert_eq!(wrapped.arguments, Some(object(json!({"a": 1}))));
        let routed = normalize_run(object(json!({"do": "t", "project": "p", "x": 1})), declares)
            .expect("normalized");
        assert_eq!(routed.project.as_deref(), Some("p"));
        assert_eq!(routed.arguments, Some(object(json!({"x": 1}))));
        let flat_wins = normalize_run(
            object(json!({"tool": "u", "a": 2, "args": "{\"a\":1,\"b\":3}"})),
            declares,
        )
        .expect("normalized");
        assert_eq!(flat_wins.tool, "u");
        assert_eq!(flat_wins.arguments, Some(object(json!({"a": 2, "b": 3}))));
        let no_do = normalize_run(object(json!({"limit": 1})), declares).expect_err("no do");
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

        let typo = args_err::<history::list::ListParams>("history_list", json!({"lmit": 1}));
        assert_eq!(typo.code, Code::UnknownParameter);
        assert_eq!(typo.retry, Some(json!({"do": "history_list", "limit": 1})));

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
            other => panic!("no parser for local tool {other}"),
        }
    }

    #[test]
    fn every_example_in_the_gateway_text_runs() {
        let catalog = Catalog::parse(include_str!(
            "../../../../../src/main/resources/catalog/tools.json"
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
