//! Client of Raijin's JSON tool API (`/api/v1` on the MCP listeners, `transport/ToolApi.kt` in the
//! extension): list the tools and call one with plain HTTP, no MCP session.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use reqwest::{RequestBuilder, StatusCode};
use rmcp::model::{CallToolResult, JsonObject, ReadResourceResult, Resource, Tool};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::util::truncate_utf8;

/// Where to send a forwarded call: Raijin's MCP URL (`http://127.0.0.1:9876/mcp`, `[remote] url`);
/// the API lives at `/api/v1` on the same host and port.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub url: String,
    pub token: Option<String>,
}

#[derive(Deserialize)]
struct ToolList {
    tools: Vec<Tool>,
}

#[derive(Deserialize)]
struct Info {
    version: Option<String>,
}

#[derive(Deserialize)]
struct ResourceList {
    resources: Vec<Resource>,
}

/// Why a tool call did not return a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// No connection to Raijin (Burp down or a wrong URL).
    Unreachable(String),
    /// Raijin answered, but not with a result.
    Other(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable(msg) | Self::Other(msg) => f.write_str(msg),
        }
    }
}

/// Bytes of an error body quoted in a message.
const ERROR_BODY_BYTES: usize = 500;

/// The tool API base for the MCP URL `mcp_url`: its trailing `/mcp` segment becomes `/api/v1`, so a
/// reverse-proxy prefix survives (`https://h/raijin/mcp` → `https://h/raijin/api/v1`); a URL without
/// it gets `/api/v1` at the root.
fn api_base(mcp_url: &str) -> Result<String, String> {
    let mut url = url::Url::parse(mcp_url).map_err(|e| format!("bad Raijin URL {mcp_url}: {e}"))?;
    if url.cannot_be_a_base() {
        return Err(format!("bad Raijin URL {mcp_url}: not an http(s) URL"));
    }
    let prefix = url
        .path()
        .trim_end_matches('/')
        .strip_suffix("/mcp")
        .unwrap_or_default()
        .to_owned();
    url.set_path(&format!("{prefix}/api/v1"));
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

pub struct ToolApi {
    client: reqwest::Client,
    /// Tool list per API base; dropped when a request to that base cannot connect.
    tools: Mutex<HashMap<String, Vec<Tool>>>,
}

impl Default for ToolApi {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolApi {
    pub fn new() -> Self {
        // No total timeout: a tool call (a fuzz run, a crawl wait) may take minutes.
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self {
            client,
            tools: Mutex::new(HashMap::new()),
        }
    }

    /// Sends `request` (with the endpoint's bearer token) and reads the whole answer.
    async fn send(
        &self,
        endpoint: &Endpoint,
        base: &str,
        request: RequestBuilder,
    ) -> Result<(StatusCode, Vec<u8>), ApiError> {
        let request = match &endpoint.token {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        let answer = async {
            let response = request.send().await?;
            let status = response.status();
            Ok::<_, reqwest::Error>((status, response.bytes().await?.to_vec()))
        }
        .await;
        match answer {
            Ok(answer) => Ok(answer),
            Err(e) => {
                self.tools.lock().await.remove(base);
                Err(ApiError::Unreachable(format!(
                    "cannot reach Raijin at {base}: {e}"
                )))
            }
        }
    }

    /// The live tool list, cached per API base.
    pub async fn tools(&self, endpoint: &Endpoint) -> Result<Vec<Tool>, String> {
        let base = api_base(&endpoint.url)?;
        if let Some(tools) = self.tools.lock().await.get(&base) {
            return Ok(tools.clone());
        }
        let request = self.client.get(format!("{base}/tools"));
        let (status, body) = self
            .send(endpoint, &base, request)
            .await
            .map_err(|e| e.to_string())?;
        let list: ToolList = decode(&base, "the tool list", status, &body)?;
        self.tools.lock().await.insert(base, list.tools.clone());
        Ok(list.tools)
    }

    /// Runs tool `name` with `arguments` (`{}` when none); the extension resolves the name.
    pub async fn call(
        &self,
        endpoint: &Endpoint,
        name: &str,
        arguments: Option<JsonObject>,
    ) -> Result<CallToolResult, ApiError> {
        let base = api_base(&endpoint.url).map_err(ApiError::Other)?;
        let mut url = url::Url::parse(&base).map_err(|e| ApiError::Other(e.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| ApiError::Other(format!("bad Raijin URL {base}")))?
            .extend(["tools", name]);
        let request = self.client.post(url).json(&arguments.unwrap_or_default());
        let (status, body) = self.send(endpoint, &base, request).await?;
        // An older extension answers an unknown name with a 404 instead of an `unknown_tool` result.
        if status == StatusCode::NOT_FOUND && unknown_tool(&body) {
            return Err(ApiError::Other(format!("Raijin has no tool {name}")));
        }
        decode(&base, name, status, &body).map_err(ApiError::Other)
    }

    /// The running Raijin's MCP resources (`burp://...`), from `GET /api/v1/resources`.
    pub async fn resources(&self, endpoint: &Endpoint) -> Result<Vec<Resource>, String> {
        let base = api_base(&endpoint.url)?;
        let request = self.client.get(format!("{base}/resources"));
        let (status, body) = self
            .send(endpoint, &base, request)
            .await
            .map_err(|e| e.to_string())?;
        let list: ResourceList = decode(&base, "the resource list", status, &body)?;
        Ok(list.resources)
    }

    /// One resource of the running Raijin, from `GET /api/v1/resources/read?uri=<uri>`.
    pub async fn read_resource(
        &self,
        endpoint: &Endpoint,
        uri: &str,
    ) -> Result<ReadResourceResult, String> {
        let base = api_base(&endpoint.url)?;
        let mut url =
            url::Url::parse(&format!("{base}/resources/read")).map_err(|e| e.to_string())?;
        url.query_pairs_mut().append_pair("uri", uri);
        let (status, body) = self
            .send(endpoint, &base, self.client.get(url))
            .await
            .map_err(|e| e.to_string())?;
        if status == StatusCode::NOT_FOUND
            && let Ok(Value::Object(answer)) = serde_json::from_slice::<Value>(&body)
            && let Some(Value::String(error)) = answer.get("error")
        {
            return Err(error.clone());
        }
        decode(&base, uri, status, &body)
    }

    /// The extension's version, from `GET /api/v1/info`.
    pub async fn server_version(&self, endpoint: &Endpoint) -> Result<Option<String>, String> {
        let base = api_base(&endpoint.url)?;
        let request = self.client.get(format!("{base}/info"));
        let (status, body) = self
            .send(endpoint, &base, request)
            .await
            .map_err(|e| e.to_string())?;
        let info: Info = decode(&base, "info", status, &body)?;
        Ok(info.version)
    }
}

/// Whether a 404 body is the tool API's own `{"error":"unknown tool <name>"}`, not a missing route.
fn unknown_tool(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body).is_ok_and(|v| {
        v.get("error")
            .and_then(Value::as_str)
            .is_some_and(|e| e.starts_with("unknown tool "))
    })
}

/// A 2xx `body` decoded as `T`. A 404 from something other than the tool API means the extension
/// at `base` predates it; other statuses become `Raijin rejected <what>: HTTP <status>: <body>`.
fn decode<T: DeserializeOwned>(
    base: &str,
    what: &str,
    status: StatusCode,
    body: &[u8],
) -> Result<T, String> {
    if status == StatusCode::NOT_FOUND && !unknown_tool(body) {
        return Err(format!(
            "Raijin at {base} has no tool API (HTTP 404); update the extension to this CLI's release"
        ));
    }
    if !status.is_success() {
        let text = String::from_utf8_lossy(body);
        return Err(format!(
            "Raijin rejected {what}: HTTP {status}: {}",
            truncate_utf8(&text, ERROR_BODY_BYTES)
        ));
    }
    serde_json::from_slice(body)
        .map_err(|e| format!("Raijin answered {what} with an unreadable result: {e}"))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn the_api_sits_beside_the_mcp_path() {
        assert_eq!(
            api_base("http://127.0.0.1:9876/mcp").as_deref(),
            Ok("http://127.0.0.1:9876/api/v1")
        );
        assert_eq!(
            api_base("https://burp.lan:8443/mcp/?x=1#f").as_deref(),
            Ok("https://burp.lan:8443/api/v1")
        );
        assert_eq!(
            api_base("https://burp.lan/raijin/mcp").as_deref(),
            Ok("https://burp.lan/raijin/api/v1")
        );
        assert!(api_base("not a url").is_err());
    }

    /// Reads one HTTP/1.1 request (headers plus a Content-Length body) and returns its request line.
    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await.expect("read");
            data.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&data);
            if let Some(end) = text.find("\r\n\r\n") {
                let length = text[..end]
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if data.len() >= end + 4 + length || n == 0 {
                    return text.lines().next().unwrap_or_default().to_owned();
                }
            }
            if n == 0 {
                return String::new();
            }
        }
    }

    #[tokio::test]
    async fn api_client_talks_to_a_stub_raijin() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let line = read_request(&mut stream).await;
                let (status, body) = match line.split(' ').take(2).collect::<Vec<_>>()[..] {
                    ["GET", "/api/v1/tools"] => (
                        "200 OK",
                        r#"{"tools":[{"name":"t","inputSchema":{"type":"object"}}]}"#,
                    ),
                    ["POST", "/api/v1/tools/t"] => {
                        ("200 OK", r#"{"content":[{"type":"text","text":"ok"}]}"#)
                    }
                    ["POST", path] if path.starts_with("/api/v1/tools/") => {
                        ("404 Not Found", r#"{"error":"unknown tool nope"}"#)
                    }
                    ["GET", "/api/v1/resources"] => (
                        "200 OK",
                        r#"{"resources":[{"uri":"burp://scope","name":"scope","mimeType":"application/json"}]}"#,
                    ),
                    ["GET", "/api/v1/resources/read?uri=burp%3A%2F%2Fscope"] => (
                        "200 OK",
                        r#"{"contents":[{"uri":"burp://scope","mimeType":"application/json","text":"{}"}]}"#,
                    ),
                    // A route Ktor does not have: an extension without the tool API.
                    _ => ("404 Not Found", "Not Found"),
                };
                log.lock().await.push(line);
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        let api = ToolApi::new();
        let endpoint = Endpoint {
            url: format!("http://127.0.0.1:{port}/mcp"),
            token: None,
        };
        let tools = api.tools(&endpoint).await.expect("tools");
        assert_eq!(
            tools.iter().map(|t| t.name.to_string()).collect::<Vec<_>>(),
            ["t"]
        );
        assert!(seen.lock().await[0].starts_with("GET /api/v1/tools "));

        let result = api.call(&endpoint, "t", None).await.expect("call");
        let text = result.content[0].as_text().expect("text").text.clone();
        assert_eq!(text, "ok");

        let missing = api.call(&endpoint, "nope", None).await.expect_err("404");
        assert!(
            missing.to_string().contains("has no tool nope"),
            "{missing}"
        );

        let resources = api.resources(&endpoint).await.expect("resources");
        assert_eq!(resources[0].uri, "burp://scope");
        let read = api
            .read_resource(&endpoint, "burp://scope")
            .await
            .expect("read");
        assert_eq!(read.contents.len(), 1, "{read:?}");

        let down = Endpoint {
            url: "http://127.0.0.1:9/mcp".to_owned(),
            token: None,
        };
        let unreachable = api.call(&down, "t", None).await.expect_err("no listener");
        assert!(
            matches!(unreachable, ApiError::Unreachable(_)),
            "{unreachable:?}"
        );

        let old = Endpoint {
            url: format!("http://127.0.0.1:{port}/old/mcp"),
            token: None,
        };
        let no_api = api.tools(&old).await.expect_err("no /old/api/v1");
        assert!(no_api.contains("has no tool API"), "{no_api}");
    }

    #[test]
    fn a_kotlin_tool_and_result_decode() {
        // As McpJson (explicitNulls = false, encodeDefaults = true) writes them.
        let tool: ToolList = serde_json::from_str(
            r#"{"tools":[{"name":"scope","title":"Scope","description":"d","inputSchema":{"type":"object","properties":{"action":{"type":"string","enum":["check"]}},"required":["action"]},"annotations":{"readOnlyHint":false,"destructiveHint":true,"openWorldHint":false}}]}"#,
        )
        .expect("tool list");
        assert_eq!(tool.tools[0].name, "scope");
        let result: CallToolResult = serde_json::from_str(
            r#"{"content":[{"type":"text","text":"{\"ok\":true}"}],"isError":true}"#,
        )
        .expect("result");
        assert_eq!(result.is_error, Some(true));
    }
}
