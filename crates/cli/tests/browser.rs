//! The `browser` tool of `raijin mcp` against a fake `ShardBrowser` launcher.

mod common;

use std::sync::{Arc, Mutex};

use rmcp::model::{CallToolRequestParams, CallToolResult, JsonObject};
use rmcp::service::RunningService;
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use rmcp::{RoleClient, ServiceExt};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;

/// One request the fake launcher saw.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    authorization: Option<String>,
    body: String,
}

type Log = Arc<Mutex<Vec<Seen>>>;

fn reply(method: &str, path: &str) -> (u16, Value) {
    match (method, path) {
        ("GET", "/fingerprint/new/Windows") => (200, json!({"fingerprint": {"k": "v"}})),
        ("POST", "/profiles") => (200, json!({"id": "p1", "name": "x"})),
        ("GET", "/profiles") => (200, json!([{"id": "p1", "name": "Shop Test"}])),
        ("POST", "/profiles/p1/stop") => (200, json!({"stopped": true})),
        ("GET", "/running") => (200, json!([])),
        _ => (404, json!({"error": "no such thing"})),
    }
}

async fn serve_one(mut stream: TcpStream, log: Log) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let Ok(n) = stream.read(&mut chunk).await else {
            return;
        };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_owned();
    let path = first.next().unwrap_or_default().to_owned();
    let mut length = 0;
    let mut authorization = None;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            match k.trim().to_ascii_lowercase().as_str() {
                "content-length" => length = v.trim().parse().unwrap_or(0),
                "authorization" => authorization = Some(v.trim().to_owned()),
                _ => {}
            }
        }
    }
    while buf.len() < head_end + length {
        let Ok(n) = stream.read(&mut chunk).await else {
            return;
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..]).into_owned();
    let (status, value) = reply(&method, &path);
    log.lock().expect("log").push(Seen {
        method,
        path,
        authorization,
        body,
    });
    let text = value.to_string();
    let reason = if status == 200 { "OK" } else { "Not Found" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// A fake launcher on a free port: its port and what it saw.
async fn launcher() -> (u16, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve_one(stream, Arc::clone(&seen)));
        }
    });
    (port, log)
}

fn command(fixture: &common::Fixture, port: u16) -> Command {
    Command::new(env!("CARGO_BIN_EXE_raijin")).configure(|c| {
        c.args(["mcp"])
            .current_dir(fixture.root())
            .env("HOME", fixture.root())
            .env("RAIJIN_JAR", &fixture.jar)
            .env("SHARDX_API", format!("http://127.0.0.1:{port}"))
            .env("SHARDX_TOKEN", "t");
    })
}

async fn connect(fixture: &common::Fixture, port: u16) -> RunningService<RoleClient, ()> {
    ().serve(TokioChildProcess::new(command(fixture, port)).expect("spawn raijin mcp"))
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
async fn browser_actions_reach_the_launcher() {
    let fixture = common::target("");
    let (port, log) = launcher().await;
    let client = connect(&fixture, port).await;

    let created = call(
        &client,
        "browser",
        json!({"do": "create_profile", "name": "x", "platform": "Windows"}),
    )
    .await;
    assert_ne!(created.is_error, Some(true), "{}", text(&created));
    assert!(text(&created).contains("\"p1\""), "{}", text(&created));
    {
        let seen = log.lock().expect("log").clone();
        let calls: Vec<(&str, &str)> = seen
            .iter()
            .map(|s| (s.method.as_str(), s.path.as_str()))
            .collect();
        assert_eq!(
            calls,
            [("GET", "/fingerprint/new/Windows"), ("POST", "/profiles")]
        );
        assert!(
            seen.iter()
                .all(|s| s.authorization.as_deref() == Some("Bearer t")),
            "{seen:?}"
        );
        let body: Value = serde_json::from_str(&seen[1].body).expect("json body");
        assert_eq!(body["fingerprint"], json!({"k": "v"}));
        assert_eq!(body["name"], "x");
        assert!(body.get("platform").is_none(), "{body}");
    }

    let found = call(
        &client,
        "run",
        json!({"do": "browser.find_profile_by_name", "name": "shop"}),
    )
    .await;
    assert_ne!(found.is_error, Some(true), "{}", text(&found));
    assert_eq!(json_of(&found)["found"], 1);

    let batch = call(
        &client,
        "browser",
        json!({"batch": [{"do": "list_profiles"}, {"do": "find_profile_by_name", "name": "shop"}]}),
    )
    .await;
    assert_ne!(batch.is_error, Some(true), "{}", text(&batch));
    assert_eq!(json_of(&batch)["steps"].as_array().map(Vec::len), Some(2));
    for form in [
        json!({"batch": ["list_profiles"]}),
        json!({"steps": ["list_profiles"]}),
        json!({"batch": "[{\"do\":\"list_profiles\"}]"}),
        json!({"batch": {"do": "list_profiles"}}),
    ] {
        let result = call(&client, "browser", form.clone()).await;
        assert_ne!(result.is_error, Some(true), "{form}: {}", text(&result));
    }

    let missing = call(&client, "browser", json!({"do": "get_profile", "id": "zz"})).await;
    assert_eq!(missing.is_error, Some(true));
    let missing = json_of(&missing);
    assert_eq!(missing["code"], "not_found");
    assert!(
        missing["error"]
            .as_str()
            .is_some_and(|e| e.contains("GET /profiles/zz → no such thing")),
        "{missing}"
    );

    let stopped = call(
        &client,
        "browser",
        json!({"do": "stop_profile", "id": "p1"}),
    )
    .await;
    assert_ne!(stopped.is_error, Some(true), "{}", text(&stopped));
    {
        let seen = log.lock().expect("log").clone();
        let last: Vec<(&str, &str)> = seen[seen.len() - 2..]
            .iter()
            .map(|s| (s.method.as_str(), s.path.as_str()))
            .collect();
        assert_eq!(
            last,
            [("POST", "/profiles/p1/stop"), ("GET", "/running")],
            "stop_profile waits on the running list"
        );
    }
    client.cancel().await.expect("close");
}

#[tokio::test]
async fn browser_refuses_what_it_cannot_run() {
    let fixture = common::target("");
    let (port, log) = launcher().await;
    let client = connect(&fixture, port).await;

    let typo = call(&client, "browser", json!({"do": "crate_profile"})).await;
    assert_eq!(typo.is_error, Some(true));
    let typo = json_of(&typo);
    assert_eq!(typo["code"], "unknown_tool");
    assert!(
        typo["did_you_mean"]
            .as_array()
            .is_some_and(|d| d.contains(&json!("browser.create_profile"))),
        "{typo}"
    );

    let legacy = call(
        &client,
        "browser",
        json!({"do": "browser_click", "profile_id": "p1"}),
    )
    .await;
    assert_eq!(legacy.is_error, Some(true));
    assert!(
        json_of(&legacy)["error"]
            .as_str()
            .is_some_and(|e| e.contains("click <sel>")),
        "{}",
        text(&legacy)
    );

    let burp = call(
        &client,
        "browser",
        json!({"do": "create_temporary_profile", "via_burp": true}),
    )
    .await;
    assert_eq!(burp.is_error, Some(true));
    assert_eq!(
        json_of(&burp)["code"],
        "burp_not_running",
        "{}",
        text(&burp)
    );

    let close = call(
        &client,
        "browser",
        json!({"do": "page", "profile_id": "p1", "cmd": "close"}),
    )
    .await;
    assert_eq!(close.is_error, Some(true), "{}", text(&close));
    let typo = call(
        &client,
        "browser",
        json!({"do": "page", "profile_id": "p1", "cmds": ["get url", "nonsense-cmd"]}),
    )
    .await;
    assert_eq!(typo.is_error, Some(true), "{}", text(&typo));
    assert_eq!(json_of(&typo)["step"], 2, "{}", text(&typo));
    let seen = log.lock().expect("log").clone();
    assert!(
        seen.iter()
            .all(|s| s.path != "/running" && !s.path.ends_with("/start")),
        "a line that does not parse must not start the profile: {seen:?}"
    );
    client.cancel().await.expect("close");
}
