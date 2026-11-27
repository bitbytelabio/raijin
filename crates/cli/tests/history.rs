mod common;

use std::process::Command;

use serde_json::Value;

fn history(fixture: &common::Fixture, args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_raijin"))
        .arg("history")
        .args(args)
        .args(["-F", "json"])
        .current_dir(fixture.root())
        .env("HOME", fixture.root())
        .output()
        .expect("raijin runs");
    assert!(
        output.status.success(),
        "raijin history {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("json output")
}

fn refs(value: &Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .expect("array")
        .iter()
        .map(|r| r["ref"].as_str().expect("ref").to_owned())
        .collect()
}

#[test]
fn list_merges_projects_and_the_archive_by_time() {
    let fixture = common::target("");
    let out = history(&fixture, &["list"]);
    assert_eq!(out["total"], 6);
    assert_eq!(
        refs(&out, "rows"),
        ["p1:1", "p2:1", "p1:2", "p2:2", "p1:3", "p1:a1"]
    );
    let archived = &out["rows"][5];
    assert_eq!(archived["source"], "archive");
    assert_eq!(archived["tool"], "http_send_request");
    assert_eq!(archived["status"], 403);
    assert_eq!(out["rows"][0]["host"], "t.test");
    assert_eq!(out["warnings"], serde_json::json!([]));
}

#[test]
fn list_filters_projects_sources_and_status() {
    let fixture = common::target("");
    assert_eq!(
        refs(&history(&fixture, &["list", "-p", "p2"]), "rows"),
        ["p2:1", "p2:2"]
    );
    assert_eq!(
        refs(&history(&fixture, &["list", "--source", "archive"]), "rows"),
        ["p1:a1"]
    );
    assert_eq!(
        refs(
            &history(&fixture, &["list", "-s", "404", "-s", "403"]),
            "rows"
        ),
        ["p2:2", "p1:a1"]
    );
    assert_eq!(
        refs(&history(&fixture, &["list", "-c", "x"]), "rows"),
        Vec::<String>::new(),
        "a comment filter excludes archive rows"
    );
    assert_eq!(
        refs(&history(&fixture, &["list", "--source", "issues"]), "rows"),
        ["p1:i1"]
    );
    let paged = history(&fixture, &["list", "-n", "2", "--offset", "1"]);
    assert_eq!(
        (paged["total"].as_u64(), refs(&paged, "rows")),
        (Some(6), vec!["p2:1".to_owned(), "p1:2".to_owned()])
    );
}

#[test]
fn endpoints_merge_the_same_path_across_projects() {
    let fixture = common::target("");
    let out = history(&fixture, &["endpoints"]);
    let endpoints = out["endpoints"].as_array().expect("endpoints");
    let users_get = endpoints
        .iter()
        .find(|e| e["path"] == "/api/users" && e["method"] == "GET")
        .expect("GET /api/users");
    assert_eq!(users_get["count"], 2);
    assert_eq!(users_get["query_params"], serde_json::json!(["id"]));
    assert_eq!(users_get["projects"], serde_json::json!(["p1", "p2"]));
    let users_post = endpoints
        .iter()
        .find(|e| e["path"] == "/api/users" && e["method"] == "POST")
        .expect("POST /api/users");
    assert_eq!(users_post["body_params"], serde_json::json!(["name"]));
    assert!(
        endpoints.iter().any(|e| e["path"] == "/api/admin"),
        "archive exchanges are mapped too"
    );
}

#[test]
fn search_finds_the_post_body() {
    let fixture = common::target("");
    let out = history(&fixture, &["search", "\"name\":\"x\"", "--in", "req"]);
    let hits = out["hits"].as_array().expect("hits");
    assert_eq!(hits.len(), 1, "{out}");
    assert_eq!(hits[0]["ref"], "p1:2");
    assert_eq!(hits[0]["where"], "request");
    assert!(
        hits[0]["snippet"]
            .as_str()
            .expect("snippet")
            .contains("{\"name\":\"x\"}")
    );
}

#[test]
fn diff_and_show_read_single_exchanges() {
    let fixture = common::target("");
    let diff = history(&fixture, &["diff", "p1:1", "p2:1"]);
    let text = diff["diff"].as_str().expect("diff text");
    assert!(
        text.contains("--- p1:1") && text.contains("+++ p2:1"),
        "{text}"
    );
    assert!(
        text.contains("-[{\"id\":1,\"name\":\"alice\"}]")
            && text.contains("+[{\"id\":1,\"name\":\"bob\"}]"),
        "{text}"
    );

    let shown = history(&fixture, &["show", "p1:2", "--max-body", "4"]);
    assert_eq!(shown["method"], "POST");
    assert!(
        shown["request"]
            .as_str()
            .expect("request")
            .ends_with("\r\n\r\n{\"na")
    );
    assert_eq!(shown["request_truncated"], true);

    let issue = history(&fixture, &["show", "p1:i1"]);
    assert_eq!(issue["name"], "SQL injection");
    assert_eq!(issue["evidence"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        issue["background"],
        Value::Null,
        "lines written before background existed still parse"
    );

    let missing = Command::new(env!("CARGO_BIN_EXE_raijin"))
        .args(["history", "show", "p1:999"])
        .current_dir(fixture.root())
        .env("HOME", fixture.root())
        .output()
        .expect("raijin runs");
    assert!(!missing.status.success());
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(
        stderr.contains("no proxy entry p1:999") && !stderr.contains("malformed"),
        "{stderr}"
    );
}

#[test]
fn limit_zero_returns_only_the_total() {
    let fixture = common::target("");
    let out = history(&fixture, &["list", "-n", "0"]);
    assert_eq!(out["total"], 6);
    assert_eq!(out["rows"], serde_json::json!([]));
    assert!(out.get("limit_clamped_to").is_none(), "{out}");
}

#[test]
fn export_writes_amber_json_and_the_archive() {
    let fixture = common::target("");
    let out = history(&fixture, &["export", "-o", "out"]);
    assert_eq!(out["projects"][0]["entries"], 3);
    assert!(fixture.root().join("out/p1/history.json").is_file());
    assert!(
        fixture
            .root()
            .join("out/p1/archive/exchanges.jsonl")
            .is_file()
    );
    assert!(fixture.root().join("out/p2/history.json").is_file());
}
