//! `history show` / `history_show`.

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use super::source::{self, Source};
use super::{Ref, RefKind, split_message};
use crate::config::Target;

pub const DEFAULT_MAX_BODY: usize = 4096;

#[derive(Debug, Clone, Default, clap::Args, serde::Deserialize, schemars::JsonSchema)]
pub struct ShowParams {
    /// `<project>:<id>` (Proxy), `<project>:a<seq>` (archive) or `<project>:i<seq>` (issue).
    #[arg(value_name = "REF")]
    #[serde(rename = "ref")]
    pub reference: String,
    /// Body bytes to show per message (default 4096); headers are always whole.
    #[arg(long)]
    pub max_body: Option<usize>,
    /// Show whole bodies.
    #[arg(long)]
    #[serde(default)]
    pub full: bool,
}

/// One message as text: headers whole, body lossy UTF-8 cut at `max_body` bytes.
pub fn render(raw: &[u8], max_body: Option<usize>) -> (String, bool) {
    let (head, body) = split_message(raw);
    let (body, truncated) = match max_body {
        Some(max) if body.len() > max => (&body[..max], true),
        _ => (body, false),
    };
    let mut text = String::from_utf8_lossy(head).into_owned();
    text.push_str(&String::from_utf8_lossy(body));
    (text, truncated)
}

pub fn run(target: &Target, params: &ShowParams) -> Result<Value> {
    let reference = Ref::parse(&params.reference)?;
    let source = source::find(target, &reference.project)?;
    let max_body = if params.full {
        None
    } else {
        Some(params.max_body.unwrap_or(DEFAULT_MAX_BODY))
    };
    match reference.kind {
        RefKind::Proxy(id) => {
            let (row, request, response) = source::proxy_entry(&source, id)?;
            Ok(exchange_json(
                serde_json::to_value(&row)?,
                &request,
                response.as_deref(),
                max_body,
                json!({}),
            ))
        }
        RefKind::Archive(seq) => {
            let line = source::archive_line(&source, seq)?;
            let request = STANDARD.decode(&line.request_b64)?;
            let response = line
                .response_b64
                .as_deref()
                .map(|b| STANDARD.decode(b))
                .transpose()?;
            let row = source::archive_row(&source, &line, &request, response.as_deref());
            let extra = json!({
                "archive_request_truncated": line.request_truncated,
                "archive_response_truncated": line.response_truncated,
                "response_reconstructed": line.response_reconstructed,
            });
            Ok(exchange_json(
                serde_json::to_value(&row)?,
                &request,
                response.as_deref(),
                max_body,
                extra,
            ))
        }
        RefKind::Issue(seq) => issue(&source, seq, max_body),
    }
}

fn exchange_json(
    row: Value,
    request: &[u8],
    response: Option<&[u8]>,
    max_body: Option<usize>,
    extra: Value,
) -> Value {
    let (request_text, request_truncated) = render(request, max_body);
    let (response_text, response_truncated) = response.map_or((None, false), |r| {
        let (t, cut) = render(r, max_body);
        (Some(t), cut)
    });
    let mut out = row;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("request".to_owned(), json!(request_text));
        obj.insert("response".to_owned(), json!(response_text));
        obj.insert("request_truncated".to_owned(), json!(request_truncated));
        obj.insert("response_truncated".to_owned(), json!(response_truncated));
        if let Value::Object(extra) = extra {
            obj.extend(extra);
        }
    }
    out
}

fn issue(source: &Source, seq: u64, max_body: Option<usize>) -> Result<Value> {
    let line = source::issue_line(source, seq)?;
    let mut evidence = Vec::new();
    for item in &line.evidence {
        let request = STANDARD.decode(&item.request_b64)?;
        let response = item
            .response_b64
            .as_deref()
            .map(|b| STANDARD.decode(b))
            .transpose()?;
        let (request_text, request_truncated) = render(&request, max_body);
        let response = response.map(|r| render(&r, max_body));
        evidence.push(json!({
            "request": request_text,
            "request_truncated": request_truncated,
            "response": response.as_ref().map(|r| &r.0),
            "response_truncated": response.as_ref().is_some_and(|r| r.1),
        }));
    }
    let mut out = serde_json::to_value(line.row(&source.project))?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("detail".to_owned(), json!(line.detail));
        obj.insert("remediation".to_owned(), json!(line.remediation));
        obj.insert("background".to_owned(), json!(line.background));
        obj.insert(
            "remediation_background".to_owned(),
            json!(line.remediation_background),
        );
        obj.insert("evidence".to_owned(), Value::Array(evidence));
    }
    Ok(out)
}
