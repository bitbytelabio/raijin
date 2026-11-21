mod common;

use rmcp::model::{CallToolRequestParams, CallToolResult, JsonObject};
use rmcp::service::RunningService;
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use rmcp::{RoleClient, ServiceExt};
use serde_json::{Value, json};
use tokio::process::Command;

async fn connect(fixture: &common::Fixture) -> RunningService<RoleClient, ()> {
    let command = Command::new(env!("CARGO_BIN_EXE_raijin")).configure(|c| {
        c.arg("mcp")
            .current_dir(fixture.root())
            .env("HOME", fixture.root())
            .env("RAIJIN_JAR", &fixture.jar);
    });
    ().serve(TokioChildProcess::new(command).expect("spawn raijin mcp"))
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

#[tokio::test]
async fn lean_surface_lists_gateway_tools_and_domains() {
    let fixture = common::target("");
    let client = connect(&fixture).await;

    let tools: Vec<String> = client
        .list_all_tools()
        .await
        .expect("tools/list")
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    assert_eq!(tools, ["discover", "execute", "skill"]);
    let info = client.peer_info().expect("server info");
    assert!(
        info.instructions
            .as_deref()
            .is_some_and(|i| i.contains("skill('raijin-gateway')"))
    );

    let overview = json_of(&call(&client, "discover", json!({})).await);
    let domains: Vec<&str> = overview["domains"]
        .as_array()
        .expect("domains")
        .iter()
        .map(|d| d["name"].as_str().expect("name"))
        .collect();
    assert_eq!(domains.len(), 12, "{domains:?}");
    assert_eq!(&domains[10..], ["lifecycle", "history"]);
    assert_eq!(
        overview["instances"],
        json!([{"project": "p1", "state": "stopped", "mode": null, "mcp_url": null}, {"project": "p2", "state": "stopped", "mode": null, "mcp_url": null}])
    );

    let http = json_of(&call(&client, "discover", json!({"domain": "http"})).await);
    assert!(http["tools"].as_array().expect("tools").iter().any(|t| t["name"] == "http_send_request" && t["inputSchema"]["properties"].is_object()));
    let bad = call(&client, "discover", json!({"domain": "nope"})).await;
    assert_eq!(bad.is_error, Some(true));
    assert!(text(&bad).contains("valid: http, proxy"), "{}", text(&bad));
    client.cancel().await.expect("close");
}

#[tokio::test]
async fn execute_runs_local_tools_and_reports_routing_errors() {
    let fixture = common::target("");
    let client = connect(&fixture).await;

    let listed = json_of(
        &call(
            &client,
            "execute",
            json!({"tool": "history_list", "arguments": {"limit": 2}}),
        )
        .await,
    );
    assert_eq!(listed["total"], 6);
    assert_eq!(listed["rows"].as_array().map(Vec::len), Some(2));
    let scoped = json_of(
        &call(
            &client,
            "execute",
            json!({"tool": "history_list", "project": "p2"}),
        )
        .await,
    );
    assert_eq!(
        scoped["total"], 2,
        "execute's project selects the history project"
    );
    let down = json_of(
        &call(
            &client,
            "execute",
            json!({"tool": "burp_down", "arguments": {}, "project": "p2"}),
        )
        .await,
    );
    assert_eq!(
        down["stopped"][0]["project"], "p2",
        "execute's project reaches burp_down instead of default_project: {down}"
    );

    let proxy = call(
        &client,
        "execute",
        json!({"tool": "proxy_history", "arguments": {}}),
    )
    .await;
    assert_eq!(proxy.is_error, Some(true));
    assert!(
        text(&proxy).contains("no Burp running for this target"),
        "{}",
        text(&proxy)
    );

    let unknown = call(&client, "execute", json!({"tool": "proxy_histroy"})).await;
    assert_eq!(unknown.is_error, Some(true));
    assert!(
        text(&unknown).contains("closest: proxy_history"),
        "{}",
        text(&unknown)
    );

    let wrong_param = call(
        &client,
        "execute",
        json!({"tool": "history_list", "arguments": {"hostname": "x"}}),
    )
    .await;
    assert!(
        text(&wrong_param).contains("unknown parameter(s) hostname"),
        "{}",
        text(&wrong_param)
    );

    let skills = json_of(&call(&client, "skill", json!({})).await);
    let names: Vec<&str> = skills
        .as_array()
        .expect("skills")
        .iter()
        .map(|s| s["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["overview", "raijin-gateway", "offline-history"]);
    assert!(
        text(&call(&client, "skill", json!({"name": "offline-history"})).await)
            .contains("# Offline history review")
    );

    let prompts = client.list_all_prompts().await.expect("prompts/list");
    assert_eq!(prompts.len(), 3);
    client.cancel().await.expect("close");
}

#[tokio::test]
async fn large_results_are_saved_to_a_file() {
    let fixture = common::target("[mcp]\ninline_limit_kb = 1\n");
    let client = connect(&fixture).await;
    let result = call(&client, "execute", json!({"tool": "history_list"})).await;
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
    let command = Command::new(env!("CARGO_BIN_EXE_raijin")).configure(|c| {
        c.args(["mcp", "--surface", "full"])
            .current_dir(fixture.root())
            .env("HOME", fixture.root())
            .env("RAIJIN_JAR", &fixture.jar);
    });
    let client =
        ().serve(TokioChildProcess::new(command).expect("spawn"))
            .await
            .expect("initialize");
    let tools = client.list_all_tools().await.expect("tools/list");
    assert_eq!(tools.len(), 3 + 45);
    let direct = call(&client, "proxy_history", json!({})).await;
    assert!(
        text(&direct).contains("no Burp running for this target"),
        "{}",
        text(&direct)
    );
    client.cancel().await.expect("close");
}
