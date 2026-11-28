//! The `ShardBrowser` launcher's automation HTTP API (`SHARDX_API`, `SHARDX_TOKEN`).

use std::time::Duration;

use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use url::Url;

use crate::mcp::error::{Code, ToolError};

const DEFAULT_API: &str = "http://127.0.0.1:40325";

pub struct Launcher {
    /// `SHARDX_API` without a trailing `/`, or why it is not a URL.
    base: Result<Url, String>,
    /// `SHARDX_API` as given (trailing `/` trimmed), for messages.
    shown: String,
    token: Option<String>,
    http: Client,
}

/// A running profile's CDP endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cdp {
    pub ws_url: String,
    pub http_url: String,
}

impl Launcher {
    pub fn from_env() -> Self {
        let raw = std::env::var("SHARDX_API")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_API.to_owned());
        let shown = raw.trim().trim_end_matches('/').to_owned();
        let base =
            Url::parse(&shown).map_err(|e| format!("SHARDX_API is not a URL ({e}): {shown}"));
        let token = std::env::var("SHARDX_TOKEN")
            .ok()
            .filter(|t| !t.trim().is_empty());
        // Never through HTTP_PROXY (often Burp itself): the token, proxy passwords and cookies
        // would land in its history, and the launcher is a local API anyway.
        let http = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("reqwest client with static settings builds");
        Self {
            base,
            shown,
            token,
            http,
        }
    }

    fn url(&self, segments: &[&str], query: &[(&str, &str)]) -> Result<Url, ToolError> {
        let mut url = self
            .base
            .clone()
            .map_err(|e| ToolError::new(Code::ConfigError, e))?;
        url.path_segments_mut()
            .map_err(|()| {
                ToolError::new(
                    Code::ConfigError,
                    format!("SHARDX_API cannot take a path: {}", self.shown),
                )
            })?
            .pop_if_empty()
            .extend(segments);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        Ok(url)
    }

    /// One launcher call: `segments` are percent-encoded one by one, `body` goes as JSON. An empty
    /// response is `null`, one that is not JSON a string.
    pub async fn api(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<Value, ToolError> {
        let url = self.url(segments, query)?;
        let mut shown = format!("{method} /{}", segments.join("/"));
        if !query.is_empty() {
            let pairs: Vec<String> = query.iter().map(|(k, v)| format!("{k}={v}")).collect();
            shown.push('?');
            shown.push_str(&pairs.join("&"));
        }
        let mut request = self.http.request(method, url);
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = &body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(|e| {
            if e.is_connect() {
                ToolError::new(
                    Code::ConfigError,
                    format!(
                        "nothing answered at {}: is the ShardBrowser launcher running, and is SHARDX_API right?",
                        self.shown
                    ),
                )
            } else {
                ToolError::new(Code::ToolFailed, format!("{shown} → {e}"))
            }
        })?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| ToolError::new(Code::ToolFailed, format!("{shown} → {e}")))?;
        let data = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).unwrap_or(Value::String(text))
        };
        if status.is_success() {
            return Ok(data);
        }
        let err = data
            .get("error")
            .and_then(Value::as_str)
            .map_or_else(|| format!("HTTP {}", status.as_u16()), str::to_owned);
        let message = format!("{shown} → {err}");
        Err(match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => ToolError::new(
                Code::ConfigError,
                format!(
                    "{message}: set SHARDX_TOKEN to the token from ShardBrowser Settings → Automation API"
                ),
            ),
            StatusCode::NOT_FOUND => ToolError::new(Code::NotFound, message),
            StatusCode::BAD_REQUEST | StatusCode::CONFLICT | StatusCode::UNPROCESSABLE_ENTITY => {
                ToolError::new(Code::InvalidArguments, message)
            }
            _ => ToolError::new(Code::ToolFailed, message),
        })
    }

    pub async fn get(&self, segments: &[&str]) -> Result<Value, ToolError> {
        self.api(Method::GET, segments, &[], None).await
    }

    /// Whether the API answers and takes the token; what it found, never an error. `/health` is
    /// open, so a refusal after it answered means a wrong token rather than nothing listening.
    pub async fn health(&self) -> Value {
        let api = &self.shown;
        let health = match self.url(&["health"], &[]) {
            Ok(url) => self.http.get(url).send().await,
            Err(e) => return json!({"ok": false, "api": api, "reason": e.error}),
        };
        match health {
            Ok(r) if !r.status().is_success() => {
                return json!({
                    "ok": false,
                    "api": api,
                    "reason": format!("the API answered HTTP {}", r.status().as_u16()),
                });
            }
            Ok(_) => {}
            Err(e) => {
                return json!({
                    "ok": false,
                    "api": api,
                    "reason": "nothing answered — is the launcher running, and is SHARDX_API right?",
                    "detail": e.to_string(),
                });
            }
        }
        match self.get(&["profiles"]).await {
            Ok(profiles) => json!({
                "ok": true,
                "api": api,
                "tokenAccepted": true,
                "profiles": profiles.as_array().map_or(0, Vec::len),
            }),
            Err(e) => json!({
                "ok": false,
                "api": api,
                "tokenAccepted": false,
                "reason": "the API is up but refused this token — check SHARDX_TOKEN",
                "detail": e.error,
            }),
        }
    }

    /// The profile's CDP endpoints, starting it (`headless`) when it is not running.
    pub async fn cdp(&self, profile_id: &str, headless: bool) -> Result<Cdp, ToolError> {
        let running = self.get(&["running"]).await?;
        let mut cdp = running
            .as_array()
            .and_then(|all| {
                all.iter()
                    .find(|r| r.get("profile_id").and_then(Value::as_str) == Some(profile_id))
            })
            .and_then(|entry| cdp_of(&entry["cdp"]));
        let mut cdp_error = None;
        if cdp.is_none() {
            let started = self
                .api(
                    Method::POST,
                    &["profiles", profile_id, "start"],
                    &[],
                    Some(json!({"headless": headless})),
                )
                .await?;
            cdp = cdp_of(&started["cdp"]);
            cdp_error = started
                .get("cdp_error")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        cdp.ok_or_else(|| {
            ToolError::new(
                Code::ToolFailed,
                format!(
                    "profile {profile_id} started without a CDP endpoint: {}",
                    cdp_error.as_deref().unwrap_or("the launcher gave none")
                ),
            )
        })
    }
}

fn cdp_of(cdp: &Value) -> Option<Cdp> {
    let ws_url = cdp.get("web_socket_debugger_url")?.as_str()?.to_owned();
    let http_url = cdp.get("http_url")?.as_str()?.to_owned();
    Some(Cdp { ws_url, http_url })
}
