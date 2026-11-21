//! `raijin mcp`: a stdio MCP server with three gateway tools (`discover`, `execute`, `skill`) in
//! front of Raijin, the Burp lifecycle and the offline history engine.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, GetPromptRequestParams,
    GetPromptResponse, GetPromptResult, Implementation, JsonObject, ListPromptsResult,
    ListToolsResult, PaginatedRequestParams, Prompt, PromptMessage, Role, ServerCapabilities,
    ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, ServiceExt};
use schemars::JsonSchema;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use tokio::sync::OnceCell;

use super::spill;
use super::upstream::{Endpoint, Pool};
use crate::burp::{instance, launch};
use crate::catalog::{Catalog, Skill, ToolSpec, cli_skills};
use crate::config::{Mode, Remote, Target, user_state_dir};
use crate::history;
use crate::jar::{self, Assets};
use crate::util::closest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Surface {
    /// discover, execute and skill only.
    Lean,
    /// Also every Raijin tool, callable directly.
    Full,
}

const INSTRUCTIONS_HEAD: &str = "Raijin drives Burp Suite through three gateway tools. 1) discover() lists domains, \
running Burp instances and routing notes; pick ONE domain by what you want to do. 2) discover(domain) gives exact tool \
names and parameter schemas; never guess parameters. 3) execute(tool, arguments, project?) runs a tool. ";
const INSTRUCTIONS_LOCAL: &str =
    "Burp tools need a running Burp: execute('burp_up', {project}) first; ";
const INSTRUCTIONS_REMOTE: &str = "Burp is remote and not managed here; burp_status checks it; ";
const INSTRUCTIONS_TAIL: &str = "offline .burp review (history domain) needs no Burp. 4) Results over the inline limit \
come back as {saved_to, preview}: parse the file with jq/python or a subagent, never read it whole. Read \
skill('raijin-gateway') first; skill() lists playbooks, and tool names inside them run through execute.";

const LIFECYCLE: &str = "lifecycle";
const HISTORY: &str = "history";
const OTHER: &str = "other";

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct DiscoverArgs {
    /// Domain to describe; omit for the overview of every domain and running instance.
    domain: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ExecuteArgs {
    /// Exact tool name from discover(domain).
    tool: String,
    /// The tool's own parameters, as its inputSchema describes.
    #[serde(default)]
    arguments: Option<JsonObject>,
    /// Project whose Burp runs the tool (needed when several are running). For `burp_up`, `burp_down`
    /// and the history tools it fills their own `project` argument when `arguments` has none.
    project: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct SkillArgs {
    /// Skill name; omit to list every skill.
    name: Option<String>,
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

fn schema_of<T: JsonSchema>() -> JsonObject {
    let mut value = serde_json::to_value(schemars::schema_for!(T))
        .unwrap_or_else(|_| json!({"type": "object"}));
    if let Some(obj) = value.as_object_mut() {
        obj.remove("$schema");
        obj.remove("title");
        if !obj.contains_key("properties") {
            obj.insert("properties".to_owned(), json!({}));
        }
        return obj.clone();
    }
    Map::new()
}

/// A tool the gateway itself implements.
struct LocalTool {
    name: &'static str,
    domain: &'static str,
    description: &'static str,
    schema: fn() -> JsonObject,
}

const LOCAL_TOOLS: &[LocalTool] = &[
    LocalTool {
        name: "burp_up",
        domain: LIFECYCLE,
        description: "Start Burp with Raijin for a project of this target (detached; survives this session).",
        schema: schema_of::<UpArgs>,
    },
    LocalTool {
        name: "burp_down",
        domain: LIFECYCLE,
        description: "Stop a project's Burp (graceful, then SIGTERM, then SIGKILL), or every one with all=true.",
        schema: schema_of::<DownArgs>,
    },
    LocalTool {
        name: "burp_status",
        domain: LIFECYCLE,
        description: "Every project of this target and its Burp state; in remote mode, whether the remote Raijin answers.",
        schema: schema_of::<StatusArgs>,
    },
    LocalTool {
        name: "history_list",
        domain: HISTORY,
        description: "Exchanges (Proxy history of every .burp project + Raijin's archive of tool traffic) or scanner issues, oldest first, filtered and paged.",
        schema: schema_of::<history::list::ListParams>,
    },
    LocalTool {
        name: "history_show",
        domain: HISTORY,
        description: "One exchange or issue by ref (<project>:<id>, <project>:a<seq>, <project>:i<seq>): headers whole, bodies cut at max_body.",
        schema: schema_of::<history::show::ShowParams>,
    },
    LocalTool {
        name: "history_search",
        domain: HISTORY,
        description: "Regex over raw requests/responses of every project; up to 3 hits per entry with context.",
        schema: schema_of::<history::search::SearchParams>,
    },
    LocalTool {
        name: "history_endpoints",
        domain: HISTORY,
        description: "API map: exchanges grouped by host + method + path, with query/body parameter names, statuses and projects.",
        schema: schema_of::<history::endpoints::EndpointsParams>,
    },
    LocalTool {
        name: "history_diff",
        domain: HISTORY,
        description: "Unified diff of two exchanges (response by default).",
        schema: schema_of::<history::diff::DiffParams>,
    },
    LocalTool {
        name: "history_export",
        domain: HISTORY,
        description: "amber JSON export of each project (plus the archive files) under .raijin/exports/.",
        schema: schema_of::<history::export::ExportParams>,
    },
];

fn local_tool(name: &str) -> Option<&'static LocalTool> {
    LOCAL_TOOLS.iter().find(|t| t.name == name)
}

/// `execute`'s `project` for a local tool that takes one (`burp_up`, `burp_down`, history selection),
/// unless `arguments` already names it.
fn with_project(
    tool: &LocalTool,
    arguments: Option<JsonObject>,
    project: Option<String>,
) -> Option<JsonObject> {
    let Some(project) = project else {
        return arguments;
    };
    let takes_project = (tool.schema)()
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|p| p.contains_key("project"));
    let mut arguments = arguments.unwrap_or_default();
    if takes_project && !arguments.contains_key("project") {
        arguments.insert("project".to_owned(), json!(project));
    }
    Some(arguments)
}

fn text(value: &Value) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(value.to_string())])
}

fn fail(message: impl Into<String>) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(message.into())])
}

/// Deserializes `arguments` into `T`, refusing keys its schema does not list.
fn parse_args<T: DeserializeOwned + JsonSchema>(
    tool: &str,
    arguments: Option<JsonObject>,
) -> Result<T, String> {
    let arguments = arguments.unwrap_or_default();
    let schema = schema_of::<T>();
    let known: HashSet<&str> = schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|p| p.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let unknown: Vec<&str> = arguments
        .keys()
        .map(String::as_str)
        .filter(|k| !known.contains(k))
        .collect();
    if !unknown.is_empty() {
        let mut expected: Vec<&str> = known.into_iter().collect();
        expected.sort_unstable();
        return Err(format!(
            "{tool}: unknown parameter(s) {}; expected {}",
            unknown.join(", "),
            expected.join(", ")
        ));
    }
    serde_json::from_value(Value::Object(arguments)).map_err(|e| format!("{tool}: {e}"))
}

pub struct Gateway {
    target: Option<Arc<Target>>,
    target_error: Option<String>,
    remote: Option<Remote>,
    surface: Surface,
    inline_limit: usize,
    assets: OnceCell<Result<Arc<Assets>, String>>,
    upstream: Pool,
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
        upstream: Pool::default(),
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
    async fn endpoint(&self, project: Option<&str>) -> Result<Endpoint, String> {
        if let Some(remote) = &self.remote {
            let token = match &remote.token_env {
                Some(var) => Some(std::env::var(var).map_err(|_| {
                    format!("environment variable {var} ([remote] token_env) is not set")
                })?),
                None => None,
            };
            return Ok(Endpoint {
                url: remote.url.clone(),
                token,
            });
        }
        let target = self.target()?;
        let statuses = instance::status_all(target)
            .await
            .map_err(|e| format!("{e:#}"))?;
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
                .ok_or_else(|| format!("project {project} is not running; execute('burp_up', {{\"project\":\"{project}\"}})"));
        }
        match running.as_slice() {
            [] => Err("no Burp running for this target; execute('burp_up', {})".to_owned()),
            [only] => pick(only).ok_or_else(|| "running instance has no MCP URL".to_owned()),
            several => several
                .iter()
                .find(|s| s.project == target.config.default_project)
                .and_then(|s| pick(s))
                .ok_or_else(|| {
                    let names: Vec<&str> = several.iter().map(|s| s.project.as_str()).collect();
                    format!(
                        "several projects running ({}); pass project",
                        names.join(", ")
                    )
                }),
        }
    }

    /// Live tools of the instance `execute` would use without a project, when one answers.
    async fn live_tools(&self) -> Option<Vec<Tool>> {
        let endpoint = self.endpoint(None).await.ok()?;
        self.upstream.tools(&endpoint).await.ok()
    }

    async fn discover(&self, args: DiscoverArgs) -> CallToolResult {
        let assets = self.assets().await;
        let live = self.live_tools().await;
        let catalog = assets.as_ref().ok().map(|a| &a.catalog);
        let live_names: Option<BTreeSet<String>> = live
            .as_ref()
            .map(|t| t.iter().map(|t| t.name.to_string()).collect());
        let other: Vec<String> = match (&live_names, catalog) {
            (Some(names), Some(c)) => names
                .iter()
                .filter(|n| c.domain_of(n).is_none() && !c.excluded.contains(n))
                .cloned()
                .collect(),
            (Some(names), None) => names.iter().cloned().collect(),
            _ => Vec::new(),
        };
        let mut warnings = Vec::new();
        if let Err(e) = &assets {
            warnings.push(format!("tool catalog unavailable: {e}"));
        }

        let Some(domain) = args.domain else {
            return self
                .overview(catalog, live_names.as_ref(), &other, warnings)
                .await;
        };
        self.describe_domain(
            catalog,
            live.as_deref(),
            &other,
            &domain,
            assets.as_ref().err(),
        )
    }

    /// `discover()` without a domain.
    async fn overview(
        &self,
        catalog: Option<&Catalog>,
        live_names: Option<&BTreeSet<String>>,
        other: &[String],
        mut warnings: Vec<String>,
    ) -> CallToolResult {
        let mut domains = Vec::new();
        for d in catalog.map(|c| c.domains.as_slice()).unwrap_or_default() {
            let tools: Vec<&String> = d
                .tools
                .iter()
                .filter(|t| live_names.is_none_or(|names| names.contains(*t)))
                .collect();
            domains.push(json!({"name": d.name, "description": d.description, "notes": d.notes, "skill": d.skill, "tools": tools}));
        }
        if !other.is_empty() {
            domains.push(json!({"name": OTHER, "description": "Tools the running Raijin has that this CLI's catalog does not list.", "notes": "", "skill": "overview", "tools": other}));
        }
        let lifecycle: Vec<&str> = self.lifecycle_tools().iter().map(|t| t.name).collect();
        domains.push(json!({"name": LIFECYCLE, "description": "Start, stop and inspect this target's CLI-managed Burp instances.", "notes": "Remote mode: only burp_status.", "skill": "raijin-gateway", "tools": lifecycle}));
        let history_tools: Vec<&str> = LOCAL_TOOLS
            .iter()
            .filter(|t| t.domain == HISTORY)
            .map(|t| t.name)
            .collect();
        domains.push(json!({"name": HISTORY, "description": "Offline review of this target's .burp projects plus the Raijin archive, without starting Burp; reads all projects in parallel.", "notes": "Live data of a running Burp is proxy.", "skill": "offline-history", "tools": history_tools}));

        let instances: Vec<Value> = match (&self.target, &self.remote) {
                (Some(t), None) => instance::status_all(t)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|s| json!({"project": s.project, "state": s.state, "mode": s.mode, "mcp_url": s.mcp_url}))
                    .collect(),
                _ => Vec::new(),
            };
        if self.target.is_none() {
            warnings.push(self.target_error.clone().unwrap_or_default());
        }
        let mut out = json!({
            "target": self.target.as_ref().map(|t| t.root.display().to_string()),
            "remote": self.remote.as_ref().map(|r| r.url.clone()),
            "instances": instances,
            "domains": domains,
        });
        if !warnings.is_empty() {
            out["warnings"] = json!(warnings);
        }
        text(&out)
    }

    /// `discover(domain)`: exact tool names and schemas, live when Burp answers.
    fn describe_domain(
        &self,
        catalog: Option<&Catalog>,
        live: Option<&[Tool]>,
        other: &[String],
        domain: &str,
        catalog_error: Option<&String>,
    ) -> CallToolResult {
        let tool_json = |name: &str, description: Option<&str>, schema: Value| json!({"name": name, "description": description, "inputSchema": schema});
        let (skill, tools): (String, Vec<Value>) = if domain == LIFECYCLE || domain == HISTORY {
            let tools = if domain == LIFECYCLE {
                self.lifecycle_tools()
            } else {
                LOCAL_TOOLS.iter().filter(|t| t.domain == HISTORY).collect()
            };
            let skill = if domain == LIFECYCLE {
                "raijin-gateway"
            } else {
                "offline-history"
            };
            (
                skill.to_owned(),
                tools
                    .iter()
                    .map(|t| tool_json(t.name, Some(t.description), Value::Object((t.schema)())))
                    .collect(),
            )
        } else if domain == OTHER && !other.is_empty() {
            let live = live.unwrap_or_default();
            (
                "overview".to_owned(),
                live.iter()
                    .filter(|t| other.contains(&t.name.to_string()))
                    .map(live_json)
                    .collect(),
            )
        } else if let Some(d) = catalog.and_then(|c| c.domain(domain)) {
            let mut tools = Vec::new();
            for name in &d.tools {
                match live {
                    Some(live) => {
                        if let Some(t) = live.iter().find(|t| t.name == name.as_str()) {
                            tools.push(live_json(t));
                        }
                    }
                    None => {
                        if let Some(spec) = catalog.and_then(|c| c.tool(name)) {
                            tools.push(spec_json(spec));
                        }
                    }
                }
            }
            (d.skill.clone(), tools)
        } else {
            let mut valid: Vec<String> = catalog
                .map(|c| c.domains.iter().map(|d| d.name.clone()).collect())
                .unwrap_or_default();
            if !other.is_empty() {
                valid.push(OTHER.to_owned());
            }
            valid.extend([LIFECYCLE.to_owned(), HISTORY.to_owned()]);
            let unavailable = catalog_error
                .map(|e| format!(" (tool catalog unavailable: {e})"))
                .unwrap_or_default();
            return fail(format!(
                "unknown domain {domain:?}; valid: {}{unavailable}",
                valid.join(", ")
            ));
        };
        text(&json!({"domain": domain, "skill": skill, "tools": tools}))
    }

    async fn all_skills(&self) -> Vec<Skill> {
        let mut skills = self
            .assets()
            .await
            .map(|a| a.skills.clone())
            .unwrap_or_default();
        skills.extend(cli_skills());
        skills
    }

    async fn skill(&self, args: SkillArgs) -> CallToolResult {
        let skills = self.all_skills().await;
        match args.name {
            None => text(&json!(skills)),
            Some(name) => {
                if let Some(skill) = skills.iter().find(|s| s.name == name) {
                    CallToolResult::success(vec![ContentBlock::text(skill.body.clone())])
                } else {
                    let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
                    fail(format!(
                        "unknown skill {name:?}; available: {}",
                        names.join(", ")
                    ))
                }
            }
        }
    }

    async fn execute(&self, args: ExecuteArgs) -> CallToolResult {
        let tool = args.tool.clone();
        let result = if let Some(local) = local_tool(&tool) {
            let arguments = with_project(local, args.arguments, args.project);
            if local.domain == LIFECYCLE {
                self.lifecycle(&tool, arguments).await
            } else {
                self.history(&tool, arguments).await
            }
        } else {
            self.forward(&tool, args.arguments, args.project.as_deref())
                .await
        };
        spill::apply(result, &tool, self.inline_limit, &self.spill_dir())
    }

    async fn forward(
        &self,
        tool: &str,
        arguments: Option<JsonObject>,
        project: Option<&str>,
    ) -> CallToolResult {
        let assets = self.assets().await;
        let in_catalog = assets.as_ref().ok().map(|a| a.catalog.tool(tool).is_some());
        if in_catalog == Some(false) {
            let live = self.live_tools().await.unwrap_or_default();
            if !live.iter().any(|t| t.name == tool) {
                let mut names: Vec<String> =
                    LOCAL_TOOLS.iter().map(|t| t.name.to_owned()).collect();
                if let Ok(a) = &assets {
                    names.extend(a.catalog.tools.iter().map(|t| t.name.clone()));
                }
                names.extend(live.iter().map(|t| t.name.to_string()));
                let near = closest(tool, names.iter().map(String::as_str), 3);
                let domain = near
                    .first()
                    .and_then(|n| {
                        local_tool(n).map(|t| t.domain.to_owned()).or_else(|| {
                            assets
                                .as_ref()
                                .ok()?
                                .catalog
                                .domain_of(n)
                                .map(|d| d.name.clone())
                        })
                    })
                    .unwrap_or_default();
                return fail(format!(
                    "unknown tool {tool:?}; closest: {}; re-run discover({domain:?})",
                    near.join(", ")
                ));
            }
        }
        let endpoint = match self.endpoint(project).await {
            Ok(e) => e,
            Err(e) => return fail(e),
        };
        match self.upstream.call(&endpoint, tool, arguments).await {
            Ok(result) => result,
            Err(e) => fail(e),
        }
    }

    async fn lifecycle(&self, tool: &str, arguments: Option<JsonObject>) -> CallToolResult {
        match self.lifecycle_inner(tool, arguments).await {
            Ok(value) => text(&value),
            Err(e) => fail(e),
        }
    }

    async fn lifecycle_inner(
        &self,
        tool: &str,
        arguments: Option<JsonObject>,
    ) -> Result<Value, String> {
        let err = |e: anyhow::Error| format!("{e:#}");
        if let Some(remote) = &self.remote {
            if tool != "burp_status" {
                return Err(format!(
                    "target uses remote {}; Burp is not CLI-managed",
                    remote.url
                ));
            }
            parse_args::<StatusArgs>(tool, arguments)?;
            let endpoint = self.endpoint(None).await?;
            return Ok(match self.upstream.server_version(&endpoint).await {
                Ok(version) => {
                    json!({"remote": remote.url, "reachable": true, "server_version": version})
                }
                Err(e) => json!({"remote": remote.url, "reachable": false, "error": e}),
            });
        }
        let target = self.target()?.clone();
        match tool {
            "burp_up" => {
                let args: UpArgs = parse_args(tool, arguments)?;
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
                let mut value = serde_json::to_value(&report).map_err(|e| e.to_string())?;
                if requested != wait {
                    value["wait_seconds_clamped_to"] = json!(wait);
                }
                Ok(value)
            }
            "burp_down" => {
                let args: DownArgs = parse_args(tool, arguments)?;
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
                Ok(json!({"stopped": stopped}))
            }
            _ => {
                parse_args::<StatusArgs>(tool, arguments)?;
                let all = instance::status_all(&target).await.map_err(err)?;
                Ok(json!({"target": target.root.display().to_string(), "instances": all}))
            }
        }
    }

    async fn history(&self, tool: &str, arguments: Option<JsonObject>) -> CallToolResult {
        let target = match self.target() {
            Ok(t) => t.clone(),
            Err(e) => return fail(e),
        };
        let arguments = arguments.unwrap_or_default();
        let tool_name = tool.to_owned();
        let run = move || -> Result<Value, String> {
            let err = |e: anyhow::Error| format!("{e:#}");
            let to_value = |v: Result<Value, serde_json::Error>| v.map_err(|e| e.to_string());
            match tool_name.as_str() {
                "history_list" => to_value(serde_json::to_value(
                    history::list::run(&target, &parse_args(&tool_name, Some(arguments))?)
                        .map_err(err)?,
                )),
                "history_show" => {
                    history::show::run(&target, &parse_args(&tool_name, Some(arguments))?)
                        .map_err(err)
                }
                "history_search" => to_value(serde_json::to_value(
                    history::search::run(&target, &parse_args(&tool_name, Some(arguments))?)
                        .map_err(err)?,
                )),
                "history_endpoints" => to_value(serde_json::to_value(
                    history::endpoints::run(&target, &parse_args(&tool_name, Some(arguments))?)
                        .map_err(err)?,
                )),
                "history_diff" => {
                    history::diff::run(&target, &parse_args(&tool_name, Some(arguments))?)
                        .map_err(err)
                }
                _ => history::export::run(&target, &parse_args(&tool_name, Some(arguments))?)
                    .map_err(err),
            }
        };
        match tokio::task::spawn_blocking(run).await {
            Ok(Ok(value)) => text(&value),
            Ok(Err(e)) => fail(e),
            Err(e) => fail(format!("{tool} panicked: {e}")),
        }
    }

    fn gateway_tools() -> Vec<Tool> {
        vec![
            Tool::new(
                "discover",
                "Start here. No domain: domains, running Burp instances, routing notes. With a domain: exact tool names and parameter schemas.",
                schema_of::<DiscoverArgs>(),
            ),
            Tool::new(
                "execute",
                "Run one tool by exact name (from discover(domain)) with its arguments object; project picks the Burp when several run.",
                schema_of::<ExecuteArgs>(),
            ),
            Tool::new(
                "skill",
                "Playbooks: no name lists them; a name returns its markdown.",
                schema_of::<SkillArgs>(),
            ),
        ]
    }
}

fn live_json(tool: &Tool) -> Value {
    json!({"name": tool.name, "description": tool.description, "inputSchema": Value::Object((*tool.input_schema).clone())})
}

fn spec_json(spec: &ToolSpec) -> Value {
    json!({"name": spec.name, "description": spec.description, "inputSchema": spec.input_schema})
}

impl ServerHandler for Gateway {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
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
                tools.push(Tool::new_with_raw(
                    spec.name.clone(),
                    spec.description.clone().map(Cow::Owned),
                    schema,
                ));
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
            "discover" => match parse_args::<DiscoverArgs>(&name, arguments) {
                Ok(args) => self.discover(args).await,
                Err(e) => fail(e),
            },
            "execute" => match parse_args::<ExecuteArgs>(&name, arguments) {
                Ok(args) => self.execute(args).await,
                Err(e) => fail(e),
            },
            "skill" => match parse_args::<SkillArgs>(&name, arguments) {
                Ok(args) => self.skill(args).await,
                Err(e) => fail(e),
            },
            _ if self.surface == Surface::Full => {
                let result = self.forward(&name, arguments, None).await;
                spill::apply(result, &name, self.inline_limit, &self.spill_dir())
            }
            _ => fail(format!(
                "unknown tool {name:?}; this server has discover, execute and skill"
            )),
        };
        Ok(CallToolResponse::Complete(result))
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        let prompts = self
            .all_skills()
            .await
            .into_iter()
            .map(|s| Prompt::new(s.name, Some(s.description), None))
            .collect();
        Ok(ListPromptsResult::with_all_items(prompts))
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let skills = self.all_skills().await;
        let skill = skills
            .into_iter()
            .find(|s| s.name == request.name)
            .ok_or_else(|| {
                ErrorData::invalid_params(format!("unknown prompt {:?}", request.name), None)
            })?;
        let mut result =
            GetPromptResult::new(vec![PromptMessage::new_text(Role::User, skill.body)]);
        result.description = Some(skill.description);
        Ok(GetPromptResponse::Complete(result))
    }
}
