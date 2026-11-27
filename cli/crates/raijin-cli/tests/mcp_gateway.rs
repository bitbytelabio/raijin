mod common;

use rmcp::model::{
    CallToolRequestParams, CallToolResult, JsonObject, ProtocolVersion, ReadResourceRequestParams,
    ResourceContents,
};
use rmcp::service::{ClientLifecycleMode, ClientServiceExt, RunningService};
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use rmcp::{RoleClient, ServiceExt};
use serde_json::{Value, json};
use tokio::process::Command;

fn command(fixture: &common::Fixture, args: &[&str]) -> Command {
    Command::new(env!("CARGO_BIN_EXE_raijin")).configure(|c| {
        c.args(args)
            .current_dir(fixture.root())
            .env("HOME", fixture.root())
            .env("RAIJIN_JAR", &fixture.jar);
    })
}

async fn connect(fixture: &common::Fixture) -> RunningService<RoleClient, ()> {
    ().serve(TokioChildProcess::new(command(fixture, &["mcp"])).expect("spawn raijin mcp"))
        .await
        .expect("initialize")
}

async fn call(
    client: &RunningService<RoleClient, ()>,
    name: &str,
    arguments: Value,
) -> CallToolResult {
    let mut params = CallToolRequestParams::new(name.to_owned());
    params.arguments = Some(serde_json::from_value::<JsonObject>(arguments).expect("object"));
    client.call_tool(params).await.expect("tools/call")
}

fn text(result: &CallToolResult) -> &str {
    result.content[0]
        .as_text()
        .map(|t| t.text.as_str())
        .expect("text content")
}

fn json_of(result: &CallToolResult) -> Value {
    serde_json::from_str(text(result)).expect("json text")
}

fn rows(result: &CallToolResult) -> usize {
    assert_ne!(result.is_error, Some(true), "{}", text(result));
    json_of(result)["rows"].as_array().map_or(0, Vec::len)
}

#[tokio::test]
async fn lean_surface_lists_guide_and_run() {
    let fixture = common::target("");
    let client = connect(&fixture).await;

    let tools: Vec<String> = client
        .list_all_tools()
        .await
        .expect("tools/list")
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(tools, ["guide", "run"]);
    let info = client.peer_info().expect("server info");
    assert!(
        info.instructions
            .as_deref()
            .is_some_and(|i| i.contains("run({\"do\":\"burp_up\"})")),
        "{:?}",
        info.instructions
    );

    let overview = call(&client, "guide", json!({})).await;
    assert_ne!(overview.is_error, Some(true));
    let overview = text(&overview);
    for wanted in [
        "Burp: p1 stopped, p2 stopped",
        "Tools by domain:",
        "scope(check|include|exclude|get_config|list|remove)",
        "Playbooks",
    ] {
        assert!(overview.contains(wanted), "no {wanted:?} in:\n{overview}");
    }
    assert!(
        overview.lines().any(|l| l.starts_with("lifecycle — ")),
        "{overview}"
    );

    let http = json_of(&call(&client, "guide", json!({"topic": "http"})).await);
    assert_eq!(http["domain"], "http");
    let send = http["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .find(|t| t["name"] == "http_send_request")
        .expect("http_send_request listed");
    assert!(
        send["summary"].as_str().is_some_and(|s| !s.is_empty()),
        "{send}"
    );
    assert!(send.get("inputSchema").is_none(), "{send}");

    let bad = call(&client, "guide", json!({"topic": "nope"})).await;
    assert_eq!(bad.is_error, Some(true));
    assert_eq!(json_of(&bad)["code"], "unknown_topic", "{}", text(&bad));
    assert!(!text(&bad).contains("Tools by domain"), "{}", text(&bad));
    client.cancel().await.expect("close");
}

#[tokio::test]
async fn run_runs_local_tools_and_reports_routing_errors() {
    let fixture = common::target("");
    let client = connect(&fixture).await;

    let listed = json_of(&call(&client, "run", json!({"do": "history_list", "limit": 2})).await);
    assert_eq!(listed["total"], 6);
    assert_eq!(listed["rows"].as_array().map(Vec::len), Some(2));
    let scoped = json_of(
        &call(
            &client,
            "run",
            json!({"do": "history_list", "project": "p2"}),
        )
        .await,
    );
    assert_eq!(scoped["total"], 2, "project selects the history project");
    let down = json_of(&call(&client, "run", json!({"do": "burp_down", "project": "p2"})).await);
    assert_eq!(
        down["stopped"][0]["project"], "p2",
        "project reaches burp_down instead of default_project: {down}"
    );

    let proxy = call(&client, "run", json!({"do": "proxy_history"})).await;
    assert_eq!(proxy.is_error, Some(true));
    assert!(
        text(&proxy).contains("no Burp running for this target"),
        "{}",
        text(&proxy)
    );

    // While Burp is down the catalog answers for names it does not know: no Burp start for a typo.
    let unknown = call(&client, "run", json!({"do": "proxy_histroy"})).await;
    assert_eq!(unknown.is_error, Some(true));
    let unknown = json_of(&unknown);
    assert_eq!(unknown["code"], "unknown_tool", "{unknown}");
    assert_eq!(unknown["did_you_mean"][0], "proxy_history", "{unknown}");

    let wrong_param = call(
        &client,
        "run",
        json!({"do": "history_list", "hostname": "x"}),
    )
    .await;
    assert_eq!(
        json_of(&wrong_param)["code"],
        "unknown_parameter",
        "{}",
        text(&wrong_param)
    );

    let prompts = client.list_all_prompts().await.expect("prompts/list");
    assert_eq!(prompts.len(), 9);

    let skills = client.list_all_skills().await.expect("skills/list");
    assert_eq!(skills.len(), 9);
    assert_eq!(skills[0].uri, "skill://overview/SKILL.md");
    assert!(
        skills.iter().all(|s| s.uri.ends_with("/SKILL.md")),
        "{skills:?}"
    );

    let resources = client.list_all_resources().await.expect("resources/list");
    assert!(
        resources
            .iter()
            .any(|r| r.uri == "skill://http-testing/references/pipeline.md"),
        "{resources:?}"
    );
    let read = client
        .read_resource(ReadResourceRequestParams::new(
            "skill://offline-history/SKILL.md",
        ))
        .await
        .expect("resources/read");
    let ResourceContents::TextResourceContents { text: body, .. } = &read.contents[0] else {
        panic!("text resource expected: {read:?}");
    };
    assert!(body.contains("# Offline history review"), "{body}");

    let file = call(
        &client,
        "guide",
        json!({"topic": "http-testing/references/pipeline.md"}),
    )
    .await;
    assert_ne!(file.is_error, Some(true), "{}", text(&file));
    client.cancel().await.expect("close");
}

#[tokio::test]
async fn large_results_are_saved_to_a_file() {
    let fixture = common::target("[mcp]\ninline_limit_kb = 1\n");
    let client = connect(&fixture).await;
    let result = call(&client, "run", json!({"do": "history_list"})).await;
    assert_ne!(result.is_error, Some(true));
    let summary = json_of(&result);
    let saved = summary["saved_to"].as_str().expect("saved_to");
    let root = std::fs::canonicalize(fixture.root()).expect("canonical root");
    assert!(
        std::path::Path::new(saved).starts_with(root.join(".raijin/tool-results")),
        "{saved}"
    );
    let body: Value = serde_json::from_str(&std::fs::read_to_string(saved).expect("saved file"))
        .expect("saved json");
    assert_eq!(body["total"], 6);
    assert!(summary["preview"].as_str().expect("preview").len() <= 2048);
    client.cancel().await.expect("close");
}

#[tokio::test]
async fn full_surface_lists_every_catalog_tool() {
    let fixture = common::target("");
    let client = ()
        .serve(
            TokioChildProcess::new(command(&fixture, &["mcp", "--surface", "full"]))
                .expect("spawn"),
        )
        .await
        .expect("initialize");
    let tools = client.list_all_tools().await.expect("tools/list");
    assert_eq!(tools.len(), 2 + 43);
    let direct = call(&client, "proxy_history", json!({})).await;
    assert!(
        text(&direct).contains("no Burp running for this target"),
        "{}",
        text(&direct)
    );
    client.cancel().await.expect("close");
}

#[tokio::test]
async fn run_accepts_common_wrong_shapes() {
    let fixture = common::target("");
    let client = connect(&fixture).await;

    for shape in [
        json!({"do": "history_list", "arguments": "{\"limit\":2}"}),
        json!({"tool": "history_list", "limit": 2}),
        json!({"name": "history_list", "args": {"limit": 2}}),
    ] {
        assert_eq!(
            rows(&call(&client, "run", shape.clone()).await),
            2,
            "{shape}"
        );
    }
    let bad = call(
        &client,
        "run",
        json!({"do": "history_list", "arguments": "nope"}),
    )
    .await;
    assert_eq!(bad.is_error, Some(true));
    assert!(
        text(&bad).contains("must be a JSON object"),
        "{}",
        text(&bad)
    );

    let typo = call(&client, "run", json!({"do": "history_list", "limt": 1})).await;
    assert_eq!(
        json_of(&typo)["retry"],
        json!({"do": "history_list", "limit": 1}),
        "{}",
        text(&typo)
    );

    let legacy = call(
        &client,
        "run",
        json!({"do": "scanner_start_crawl", "urls": ["https://a"]}),
    )
    .await;
    assert!(
        text(&legacy).contains("no Burp running for this target"),
        "routed to scanner, not unknown: {}",
        text(&legacy)
    );

    // Lean surface: a Raijin tool called directly runs as run would.
    assert_eq!(
        rows(&call(&client, "history_list", json!({"limit": 2})).await),
        2
    );
    let nope = call(&client, "nope", json!({})).await;
    assert_eq!(nope.is_error, Some(true));
    assert!(
        text(&nope).contains("Run Raijin tools through run"),
        "{}",
        text(&nope)
    );
    client.cancel().await.expect("close");
}

#[tokio::test]
async fn guide_resolves_tools_aliases_and_actions() {
    let fixture = common::target("");
    let client = connect(&fixture).await;

    let local = json_of(&call(&client, "guide", json!({"topic": "history_list"})).await);
    assert_eq!(local["do"], "history_list");
    assert_eq!(local["domain"], "history");
    assert!(
        local["inputSchema"]["properties"]["limit"].is_object(),
        "{local}"
    );

    let alias = json_of(&call(&client, "guide", json!({"topic": "scope_list"})).await);
    assert_eq!(alias["do"], "scope");
    assert_eq!(alias["action"], "list");
    assert_eq!(alias["domain"], "settings");

    let dotted = json_of(&call(&client, "guide", json!({"topic": "scope.check"})).await);
    assert_eq!(dotted["action"], "check");

    let send = json_of(&call(&client, "guide", json!({"topic": "http_send_request"})).await);
    assert_eq!(send["annotations"]["openWorldHint"], true, "{send}");

    // `scanner` is a tool and a domain: the tool, plus the domain's other tools.
    let scanner = json_of(&call(&client, "guide", json!({"topic": "scanner"})).await);
    assert_eq!(scanner["do"], "scanner");
    assert!(
        scanner["domain_tools"]
            .as_array()
            .is_some_and(|t| t.iter().any(|t| t["name"] == "scanner_task")),
        "{scanner}"
    );
    client.cancel().await.expect("close");
}

#[tokio::test]
async fn batch_runs_steps_in_order_and_bails() {
    let fixture = common::target("");
    let client = connect(&fixture).await;
    let steps = json!([
        {"do": "history_list", "limit": 1},
        {"do": "proxy_history"},
        {"do": "history_list", "limit": 2}
    ]);

    let bailed = call(&client, "run", json!({"batch": steps, "bail": true})).await;
    assert_eq!(bailed.is_error, Some(true));
    let out = json_of(&bailed);
    let done = out["steps"].as_array().expect("steps");
    assert_eq!(done.len(), 2, "{out}");
    assert_eq!(done[0]["result"]["rows"].as_array().map(Vec::len), Some(1));
    assert_eq!(done[1]["ok"], false);
    assert_eq!(out["stopped_after"], 2);

    let all = call(&client, "run", json!({"batch": steps})).await;
    assert_ne!(all.is_error, Some(true));
    assert_eq!(json_of(&all)["steps"].as_array().map(Vec::len), Some(3));

    // A client that fills every property run declares still makes a single call.
    let filled = call(
        &client,
        "run",
        json!({"do": "history_list", "limit": 1, "batch": null, "bail": false}),
    )
    .await;
    assert_eq!(rows(&filled), 1);

    let empty = call(&client, "run", json!({"batch": []})).await;
    assert!(text(&empty).contains("at least one"), "{}", text(&empty));
    let both = call(&client, "run", json!({"do": "x", "batch": [{}]})).await;
    assert!(
        text(&both).contains("either do or batch"),
        "{}",
        text(&both)
    );
    client.cancel().await.expect("close");
}

/// An error result: JSON with a string `code` and a boolean `retryable`.
fn envelope(result: &CallToolResult) -> Value {
    assert_eq!(result.is_error, Some(true), "{}", text(result));
    let value = json_of(result);
    assert!(value["code"].is_string(), "{value}");
    assert!(value["retryable"].is_boolean(), "{value}");
    value
}

fn notes(result: &CallToolResult) -> Vec<String> {
    serde_json::from_value(json_of(result)["notes"].clone()).unwrap_or_default()
}

#[tokio::test]
async fn weak_model_calls_get_json_errors_or_run() {
    let fixture = common::target("");
    let client = connect(&fixture).await;

    let stringly = call(&client, "run", json!({"do": "history_list", "limit": "1"})).await;
    assert_eq!(rows(&stringly), 1);
    assert_eq!(
        notes(&stringly),
        ["coerced 'limit' from string \"1\" to integer"]
    );

    let no_do = envelope(&call(&client, "run", json!({})).await);
    assert_eq!(no_do["code"], "missing_parameter");
    assert!(no_do["example"]["count"].is_number(), "{no_do}");

    let maybe = envelope(&call(&client, "run", json!({"do": "burp_down", "all": "maybe"})).await);
    assert_eq!(maybe["code"], "invalid_type");

    let show = envelope(&call(&client, "run", json!({"do": "history_show"})).await);
    assert_eq!(show["code"], "missing_parameter");

    let stringly_batch = call(
        &client,
        "run",
        json!({"batch": "[{\"do\":\"history_list\",\"limit\":1}]"}),
    )
    .await;
    let out = json_of(&stringly_batch);
    assert_eq!(out["steps"][0]["ok"], true, "{out}");
    assert_eq!(
        notes(&stringly_batch),
        ["parsed 'batch' from a JSON string"]
    );

    let cased = call(&client, "run", json!({"do": "History.List", "limit": 1})).await;
    assert_eq!(rows(&cased), 1);
    assert_eq!(notes(&cased), ["ran 'History.List' as history_list"]);

    let down = envelope(&call(&client, "run", json!({"do": "Burp-Down", "project": "p2"})).await);
    assert_eq!(down["code"], "unknown_tool");
    assert_eq!(down["retry"], json!({"do": "burp_down", "project": "p2"}));

    let filled = call(
        &client,
        "run",
        json!({"do": "history_list", "project": null, "limit": 1}),
    )
    .await;
    assert_eq!(
        rows(&filled),
        1,
        "a null optional parameter counts as unset"
    );
    assert!(
        down.get("stopped").is_none(),
        "burp_down did not run: {down}"
    );

    let topic = json_of(&call(&client, "guide", json!({"topic": "HTTP_SEND_REQUEST"})).await);
    assert_eq!(topic["do"], "http_send_request", "{topic}");

    let steps = json!([
        {"do": "history_list", "limit": 1},
        {"do": "history_show"},
        {"do": "history_list", "limit": 2}
    ]);
    let bailed = envelope(&call(&client, "run", json!({"batch": steps, "bail": true})).await);
    assert_eq!(bailed["not_run"], json!([3]));
    assert!(
        bailed["error"]
            .as_str()
            .is_some_and(|e| e.starts_with("step 2 of 3 failed")),
        "{bailed}"
    );
    assert_eq!(bailed["code"], "missing_parameter");
    client.cancel().await.expect("close");
}

/// Routing answers to weak-model calls from the 2.4.1 smoke test, with Burp down.
#[tokio::test]
async fn weak_model_calls_while_burp_is_down() {
    let fixture = common::target("");
    let client = connect(&fixture).await;

    // Burp down: a name nobody has is unknown_tool at once; a known one starts Burp in `retry`.
    let typo = envelope(
        &call(
            &client,
            "run",
            json!({"do": "scope.chek", "url": "https://a.b"}),
        )
        .await,
    );
    assert_eq!(typo["code"], "unknown_tool", "{typo}");
    assert_eq!(typo["did_you_mean"][0], "scope.check", "{typo}");
    let nope = envelope(&call(&client, "run", json!({"do": "nope_tool"})).await);
    assert_eq!(nope["code"], "unknown_tool", "{nope}");
    let hash = envelope(
        &call(
            &client,
            "run",
            json!({"do": "util.hash", "data": "x", "algorithm": "MD5"}),
        )
        .await,
    );
    assert_eq!(hash["code"], "burp_not_running", "{hash}");
    assert_eq!(
        hash["retry"],
        json!({"batch": [{"do": "burp_up"}, {"do": "util.hash", "data": "x", "algorithm": "MD5"}], "bail": true})
    );
    let shutdown = envelope(&call(&client, "run", json!({"do": "burp.shutdown"})).await);
    assert!(shutdown.get("retry").is_none(), "destructive: {shutdown}");

    // `input` holding a value is a parameter, not a wrapper.
    let input = envelope(
        &call(
            &client,
            "run",
            json!({"do": "util.hash", "input": "x", "algorithm": "MD5"}),
        )
        .await,
    );
    assert_eq!(input["code"], "burp_not_running", "{input}");

    // do=guide / do=run.
    let guide = envelope(&call(&client, "run", json!({"do": "guide", "topic": "util"})).await);
    assert!(
        guide["error"]
            .as_str()
            .is_some_and(|e| e.contains("guide is its own tool")),
        "{guide}"
    );
    assert_eq!(guide["see"], json!({"guide": {"topic": "util"}}));
    assert_eq!(
        envelope(&call(&client, "run", json!({"do": 5})).await)["code"],
        "invalid_type"
    );

    client.cancel().await.expect("close");
}

/// Batch shapes, parameter synonyms and history errors from the 2.4.1 smoke test.
#[tokio::test]
async fn weak_model_batches_synonyms_and_history_errors() {
    let fixture = common::target("");
    let client = connect(&fixture).await;

    // bail as a string still stops the batch.
    let steps = json!([{"do": "history_show"}, {"do": "burp_status"}]);
    let bailed = envelope(&call(&client, "run", json!({"batch": steps, "bail": "true"})).await);
    assert_eq!(bailed["not_run"], json!([2]), "{bailed}");
    assert_eq!(
        notes(&call(&client, "run", json!({"batch": steps, "bail": "true"})).await),
        ["coerced 'bail' from string \"true\" to boolean"]
    );
    let maybe = envelope(&call(&client, "run", json!({"batch": steps, "bail": "maybe"})).await);
    assert_eq!(maybe["code"], "invalid_type", "{maybe}");

    // Steps as names, and `steps` for `batch`.
    let named = call(
        &client,
        "run",
        json!({"steps": ["burp_status", "history_list"]}),
    )
    .await;
    let out = json_of(&named);
    assert_eq!(out["steps"][0]["ok"], true, "{out}");
    assert_eq!(out["steps"][1]["ok"], true, "{out}");
    assert_eq!(notes(&named), ["read 'steps' as 'batch'"]);

    // Synonyms: count for limit, query for pattern, read as the declared name.
    let count = call(&client, "run", json!({"do": "history_list", "count": 1})).await;
    assert_eq!(rows(&count), 1);
    assert_eq!(notes(&count), ["read 'count' as 'limit'"]);
    let query = call(
        &client,
        "run",
        json!({"do": "history_search", "query": "x"}),
    )
    .await;
    assert_ne!(query.is_error, Some(true), "{}", text(&query));
    assert_eq!(notes(&query), ["read 'query' as 'pattern'"]);

    // History errors the caller fixes.
    let bad_ref =
        envelope(&call(&client, "run", json!({"do": "history_show", "ref": "nope"})).await);
    assert_eq!(bad_ref["code"], "invalid_arguments", "{bad_ref}");
    assert_eq!(bad_ref["retryable"], true);
    let missing = envelope(
        &call(
            &client,
            "run",
            json!({"do": "history_show", "ref": "p1:999999"}),
        )
        .await,
    );
    assert_eq!(missing["code"], "not_found", "{missing}");
    let project = envelope(
        &call(
            &client,
            "run",
            json!({"do": "history_list", "project": "nope"}),
        )
        .await,
    );
    assert_eq!(project["code"], "invalid_enum", "{project}");
    assert_eq!(project["param"], "project");
    let ref_project = envelope(
        &call(
            &client,
            "run",
            json!({"do": "history_show", "ref": "nope:1"}),
        )
        .await,
    );
    assert_eq!(ref_project["code"], "not_found", "{ref_project}");
    assert_eq!(ref_project["param"], "ref", "{ref_project}");
    assert!(
        project["allowed"].as_array().is_some_and(|a| !a.is_empty()),
        "{project}"
    );

    client.cancel().await.expect("close");
}

/// `guide` answers from the 2.4.1 smoke test.
#[tokio::test]
async fn weak_model_guide_topics() {
    let fixture = common::target("");
    let client = connect(&fixture).await;

    // guide: one action, hash names, run/guide, resource paths and `name`.
    let hash_topic = json_of(&call(&client, "guide", json!({"topic": "util.hash"})).await);
    assert_eq!(hash_topic["action"], "hash");
    assert_eq!(
        hash_topic["inputSchema"]["properties"]
            .as_object()
            .map(serde_json::Map::len),
        Some(2),
        "{hash_topic}"
    );
    assert!(
        hash_topic["usage"]
            .as_str()
            .is_some_and(|u| u.starts_with("util.hash(data*: string")),
        "{hash_topic}"
    );
    assert_eq!(hash_topic["example"]["do"], "util.hash");
    assert_eq!(
        json_of(&call(&client, "guide", json!({"topic": "sha256"})).await)["action"],
        "hash"
    );
    assert_eq!(
        json_of(&call(&client, "guide", json!({"name": "history_list"})).await)["do"],
        "history_list"
    );
    let send = json_of(&call(&client, "guide", json!({"topic": "http_send_request"})).await);
    assert_eq!(
        send["example"],
        json!({"do": "http_send_request", "url": "https://example.com/"})
    );
    for topic in ["run", "skill://overview/SKILL.md", "/overview"] {
        let r = call(&client, "guide", json!({"topic": topic})).await;
        assert_ne!(r.is_error, Some(true), "{topic}: {}", text(&r));
    }

    let unknown_skill = client
        .read_resource(ReadResourceRequestParams::new("skill://nope/SKILL.md"))
        .await
        .expect_err("unknown resource");
    assert!(
        format!("{unknown_skill:?}").contains("-32002"),
        "{unknown_skill:?}"
    );
    client.cancel().await.expect("close");
}

#[tokio::test]
async fn modern_client_uses_server_discover() {
    let fixture = common::target("");
    let client = ()
        .serve_with_lifecycle(
            TokioChildProcess::new(command(&fixture, &["mcp"])).expect("spawn"),
            ClientLifecycleMode::Discover {
                preferred_versions: vec![ProtocolVersion::V_2026_07_28],
            },
        )
        .await
        .expect("server/discover");
    let tools: Vec<String> = client
        .list_all_tools()
        .await
        .expect("tools/list")
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(tools, ["guide", "run"]);
    assert_eq!(
        rows(&call(&client, "run", json!({"do": "history_list", "limit": 1})).await),
        1
    );
    client.cancel().await.expect("close");
}
