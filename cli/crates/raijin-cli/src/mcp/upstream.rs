//! MCP client sessions to Raijin (streamable HTTP), one per URL, reconnected once on transport errors.

use std::collections::HashMap;

use rmcp::model::{CallToolRequestParams, CallToolResult, JsonObject, Tool};
use rmcp::service::{Peer, RunningService, ServiceError};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::{RoleClient, ServiceExt};
use tokio::sync::Mutex;

/// Where to send a forwarded call.
#[derive(Debug, Clone)]
pub struct Endpoint {
    pub url: String,
    pub token: Option<String>,
}

struct Session {
    service: RunningService<RoleClient, ()>,
    tools: Option<Vec<Tool>>,
}

#[derive(Default)]
pub struct Pool {
    sessions: Mutex<HashMap<String, Session>>,
}

impl Pool {
    async fn peer(&self, endpoint: &Endpoint) -> Result<Peer<RoleClient>, String> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get(&endpoint.url)
            && !session.service.is_closed()
        {
            return Ok(session.service.peer().clone());
        }
        let mut config = StreamableHttpClientTransportConfig::with_uri(endpoint.url.as_str());
        if let Some(token) = &endpoint.token {
            config = config.auth_header(token.clone());
        }
        let transport = StreamableHttpClientTransport::from_config(config);
        let service = ()
            .serve(transport)
            .await
            .map_err(|e| format!("cannot reach Raijin at {}: {e}", endpoint.url))?;
        let peer = service.peer().clone();
        sessions.insert(
            endpoint.url.clone(),
            Session {
                service,
                tools: None,
            },
        );
        Ok(peer)
    }

    async fn drop_session(&self, url: &str) {
        if let Some(session) = self.sessions.lock().await.remove(url) {
            let _ = session.service.cancel().await;
        }
    }

    /// Forwards one `tools/call`; a transport failure drops the session and retries once.
    pub async fn call(
        &self,
        endpoint: &Endpoint,
        name: &str,
        arguments: Option<JsonObject>,
    ) -> Result<CallToolResult, String> {
        let mut retried = false;
        loop {
            let peer = self.peer(endpoint).await?;
            let mut params = CallToolRequestParams::new(name.to_owned());
            params.arguments.clone_from(&arguments);
            match peer.call_tool(params).await {
                Ok(result) => return Ok(result),
                Err(ServiceError::McpError(e)) => {
                    return Err(format!("Raijin rejected {name}: {}", e.message));
                }
                Err(e) if !retried => {
                    retried = true;
                    tracing_note(&format!("{name}: {e}; reconnecting"));
                    self.drop_session(&endpoint.url).await;
                }
                Err(e) => return Err(format!("{name} failed: {e}")),
            }
        }
    }

    /// The live tool list (cached for the session).
    pub async fn tools(&self, endpoint: &Endpoint) -> Result<Vec<Tool>, String> {
        if let Some(session) = self.sessions.lock().await.get(&endpoint.url)
            && !session.service.is_closed()
            && let Some(tools) = &session.tools
        {
            return Ok(tools.clone());
        }
        let peer = self.peer(endpoint).await?;
        let tools = if let Ok(tools) = peer.list_all_tools().await {
            tools
        } else {
            self.drop_session(&endpoint.url).await;
            let peer = self.peer(endpoint).await?;
            peer.list_all_tools()
                .await
                .map_err(|e| format!("tools/list at {}: {e}", endpoint.url))?
        };
        if let Some(session) = self.sessions.lock().await.get_mut(&endpoint.url) {
            session.tools = Some(tools.clone());
        }
        Ok(tools)
    }

    /// The server's version from `initialize`.
    pub async fn server_version(&self, endpoint: &Endpoint) -> Result<Option<String>, String> {
        let peer = self.peer(endpoint).await?;
        Ok(peer
            .peer_info()
            .and_then(|info| info.server_info.as_ref().map(|s| s.version.clone())))
    }
}

/// Diagnostics go to stderr: stdout carries JSON-RPC.
fn tracing_note(message: &str) {
    eprintln!("raijin mcp: {message}");
}
