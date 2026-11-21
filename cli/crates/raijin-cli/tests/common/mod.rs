//! A target folder with two `.burp` projects (built with vendored amber), a Raijin archive for
//! project p1, and a small Raijin jar holding the tool catalog.

#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::json;

pub const T0: u64 = 1_700_000_000_000;

fn b64(s: &str) -> String {
    STANDARD.encode(s.as_bytes())
}

fn entry(url: &str, request: &str, response: &str, time: u64) -> serde_json::Value {
    json!({"url": url, "request": {"base64": b64(request)}, "response": {"base64": b64(response)}, "time_epoch_ms": time})
}

fn write_project(dir: &Path, name: &str, entries: &[serde_json::Value]) {
    let input = dir.join(format!("{name}.input.json"));
    fs::write(
        &input,
        serde_json::to_vec(&json!({"schema_version": 1, "entries": entries})).expect("json"),
    )
    .expect("input");
    let loaded = amber::load(&input).expect("amber input loads");
    amber::create(
        &dir.join("burp").join(format!("{name}.burp")),
        &loaded,
        &amber::WriteOptions {
            force: true,
            name: None,
        },
    )
    .expect("amber creates the project");
    fs::remove_file(input).expect("cleanup");
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub jar: PathBuf,
}

impl Fixture {
    pub fn root(&self) -> &Path {
        self.dir.path()
    }
}

/// `raijin_toml` is written as the target's raijin.toml.
pub fn target(raijin_toml: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("temp dir");
    let root = dir.path();
    fs::create_dir_all(root.join("burp")).expect("burp dir");
    fs::write(root.join("raijin.toml"), raijin_toml).expect("raijin.toml");

    let ok = |body: &str, ct: &str| {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    write_project(
        root,
        "p1",
        &[
            entry(
                "https://t.test/api/users?id=1",
                "GET /api/users?id=1 HTTP/1.1\r\nHost: t.test\r\n\r\n",
                &ok("[{\"id\":1,\"name\":\"alice\"}]", "application/json"),
                T0 + 1000,
            ),
            entry(
                "https://t.test/api/users",
                "POST /api/users HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"name\":\"x\"}",
                "HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n",
                T0 + 3000,
            ),
            entry(
                "https://t.test/index.html",
                "GET /index.html HTTP/1.1\r\nHost: t.test\r\n\r\n",
                &ok("<h1>hi</h1>", "text/html"),
                T0 + 5000,
            ),
        ],
    );
    write_project(
        root,
        "p2",
        &[
            entry(
                "https://t.test/api/users?id=1",
                "GET /api/users?id=1 HTTP/1.1\r\nHost: t.test\r\n\r\n",
                &ok("[{\"id\":1,\"name\":\"bob\"}]", "application/json"),
                T0 + 2000,
            ),
            entry(
                "https://t.test/api/orders",
                "GET /api/orders HTTP/1.1\r\nHost: t.test\r\n\r\n",
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
                T0 + 4000,
            ),
        ],
    );

    let archive = root.join(".raijin/archive/p1");
    fs::create_dir_all(&archive).expect("archive dir");
    let exchange = json!({
        "seq": 1, "time_epoch_ms": T0 + 6000, "tool": "http_send_request", "method": "GET",
        "url": "https://t.test/api/admin", "status": 403,
        "request_b64": b64("GET /api/admin HTTP/1.1\r\nHost: t.test\r\n\r\n"),
        "response_b64": b64("HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nno"),
        "request_truncated": false, "response_truncated": false, "response_reconstructed": false,
    });
    fs::write(archive.join("exchanges.jsonl"), format!("{exchange}\n")).expect("exchanges");
    let issue = json!({
        "seq": 1, "time_epoch_ms": T0 + 7000, "name": "SQL injection", "severity": "HIGH", "confidence": "FIRM",
        "base_url": "https://t.test/api/users", "detail": "d", "remediation": null,
        "evidence": [{"request_b64": b64("GET /api/users?id=1' HTTP/1.1\r\n\r\n"), "response_b64": null}],
    });
    fs::write(archive.join("issues.jsonl"), format!("{issue}\n")).expect("issues");

    let jar = root.join("raijin-test.jar");
    let mut zip = zip::ZipWriter::new(fs::File::create(&jar).expect("jar"));
    let options = zip::write::SimpleFileOptions::default();
    zip.start_file("catalog/tools.json", options)
        .expect("entry");
    zip.write_all(include_bytes!(
        "../../../../../src/main/resources/catalog/tools.json"
    ))
    .expect("catalog");
    zip.start_file("skills/overview.md", options)
        .expect("entry");
    zip.write_all(b"---\nname: overview\ndescription: Start here.\n---\n# Overview\n")
        .expect("skill");
    zip.finish().expect("zip");
    Fixture { dir, jar }
}
