//! The `ShardBrowser` launcher's automation HTTP API. The API is `SHARDX_API`, else `[browser]
//! api` in raijin.toml, else the local launcher's port from its settings, else port 40325. The
//! token is the `[browser] token_env` variable (`SHARDX_TOKEN`), else, for a launcher on this
//! machine, a short-lived one signed with the secret in the launcher's settings.

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::{Client, Method, StatusCode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::config;
use crate::mcp::error::{Code, ToolError};

const DEFAULT_PORT: u64 = 40325;
const DEFAULT_TOKEN_ENV: &str = "SHARDX_TOKEN";
/// How long a token made from the launcher's secret is valid.
const MINTED_TTL_SECS: u64 = 300;

pub struct Launcher {
    /// The API base without a trailing `/`, or why it is not a URL.
    base: Result<Url, String>,
    /// The API base as given (trailing `/` trimmed), for messages.
    shown: String,
    token: Token,
    http: Client,
}

/// Where the bearer token comes from.
enum Token {
    /// The token variable's value.
    Given(String),
    /// Signed per request with the local launcher's `api_secret`, read anew each time so a
    /// regenerated secret is picked up.
    Local,
    /// Neither: the API is not on this machine and no token is set.
    Missing,
}

/// The local launcher's `settings.json` (in the OS config directory, `shardx-launcher/`).
fn launcher_settings() -> Option<Value> {
    let dir = if cfg!(target_os = "macos") {
        config::home_dir().ok()?.join("Library/Application Support")
    } else if cfg!(windows) {
        PathBuf::from(std::env::var_os("APPDATA")?)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| Some(config::home_dir().ok()?.join(".config")))?
    };
    let text = std::fs::read_to_string(dir.join("shardx-launcher/settings.json")).ok()?;
    serde_json::from_str(&text).ok()
}

/// HMAC-SHA256 (RFC 2104).
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// An HS256 JWT the launcher accepts (`sub` `shardx-api`), valid for `ttl` seconds from `now`.
fn mint(secret: &str, now: u64, ttl: u64) -> String {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = json!({"sub": "shardx-api", "iat": now, "exp": now + ttl});
    let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
    let signed = format!("{header}.{claims}");
    let signature = URL_SAFE_NO_PAD.encode(hmac_sha256(secret.as_bytes(), signed.as_bytes()));
    format!("{signed}.{signature}")
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// A running profile's CDP endpoints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cdp {
    pub ws_url: String,
    pub http_url: String,
}

impl Launcher {
    /// The launcher `settings` (`[browser]` of raijin.toml) and the environment point at.
    pub fn new(settings: &config::Browser) -> Self {
        let env = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let raw = env("SHARDX_API")
            .or_else(|| settings.api.clone().filter(|v| !v.trim().is_empty()))
            .unwrap_or_else(|| {
                let port = launcher_settings()
                    .and_then(|s| s.get("api_port").and_then(Value::as_u64))
                    .unwrap_or(DEFAULT_PORT);
                format!("http://127.0.0.1:{port}")
            });
        let shown = raw.trim().trim_end_matches('/').to_owned();
        let base =
            Url::parse(&shown).map_err(|e| format!("the launcher API is not a URL ({e}): {shown}"));
        let token_env = settings.token_env.as_deref().unwrap_or(DEFAULT_TOKEN_ENV);
        let token = match env(token_env) {
            Some(token) => Token::Given(token.trim().to_owned()),
            None if base.as_ref().is_ok_and(is_loopback) => Token::Local,
            None => Token::Missing,
        };
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

    /// The bearer token for one request; None when there is none to send.
    fn bearer(&self) -> Option<String> {
        match &self.token {
            Token::Given(token) => Some(token.clone()),
            Token::Local => {
                let settings = launcher_settings()?;
                let secret = settings.get("api_secret")?.as_str()?;
                (!secret.is_empty())
                    .then(|| mint(secret, crate::util::now_ms() / 1000, MINTED_TTL_SECS))
            }
            Token::Missing => None,
        }
    }

    /// Where the token comes from, for `health_check`.
    fn token_source(&self) -> &'static str {
        match self.token {
            Token::Given(_) => "env",
            Token::Local => "launcher settings",
            Token::Missing => "none",
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
        if let Some(token) = self.bearer() {
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
                    "{message}: set SHARDX_TOKEN to the token from ShardBrowser Settings → Automation API, or unset it to use the local launcher's own"
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

    /// Whether `profile_id` left the launcher's running list within `within` (polled every
    /// 250 ms); `false` when the list cannot be read.
    pub async fn wait_stopped(&self, profile_id: &str, within: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + within;
        loop {
            let Ok(running) = self.get(&["running"]).await else {
                return false;
            };
            let listed = running.as_array().is_some_and(|all| {
                all.iter()
                    .any(|r| r.get("profile_id").and_then(Value::as_str) == Some(profile_id))
            });
            if !listed {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
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
                "token": self.token_source(),
                "profiles": profiles.as_array().map_or(0, Vec::len),
            }),
            Err(e) => json!({
                "ok": false,
                "api": api,
                "tokenAccepted": false,
                "token": self.token_source(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc_4231() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            crate::util::hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let long_key = [0xaa_u8; 131];
        let mac = hmac_sha256(
            &long_key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            crate::util::hex(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn minted_tokens_carry_the_launcher_claims() {
        let token = mint("s3cret", 1000, 300);
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "{token}");
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).expect("base64"))
                .expect("json");
        assert_eq!(
            claims,
            json!({"sub": "shardx-api", "iat": 1000, "exp": 1300})
        );
        let signed = format!("{}.{}", parts[0], parts[1]);
        assert_eq!(
            parts[2],
            URL_SAFE_NO_PAD.encode(hmac_sha256(b"s3cret", signed.as_bytes()))
        );
    }
}
