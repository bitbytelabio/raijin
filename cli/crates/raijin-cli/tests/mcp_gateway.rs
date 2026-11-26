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
    assert!(text(&bad).contains("closest: "), "{}", text(&bad));
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

    let unknown = call(&client, "run", json!({"do": "proxy_histroy"})).await;
    assert_eq!(unknown.is_error, Some(true));
    assert!(
        text(&unknown).contains("closest: proxy_history"),
        "{}",
        text(&unknown)
    );

    let wrong_param = call(
        &client,
        "run",
        json!({"do": "history_list", "hostname": "x"}),
    )
    .await;
    assert!(
        text(&wrong_param).contains("unknown parameter(s) hostname"),
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
    assert!(
        text(&typo).contains("did you mean limit"),
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
