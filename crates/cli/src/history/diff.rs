//! `history diff` / `history_diff`: unified diff of two exchanges.

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use similar::TextDiff;

use super::source;
use super::{Ref, RefKind};
use crate::config::Target;

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    clap::ValueEnum,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum DiffPart {
    #[default]
    Response,
    Request,
}

#[derive(Debug, Clone, Default, clap::Args, serde::Deserialize, schemars::JsonSchema)]
pub struct DiffParams {
    /// First ref (`<project>:<id>` or `<project>:a<seq>`).
    pub a: String,
    /// Second ref.
    pub b: String,
    /// response (default) or request.
    #[arg(long, value_enum)]
    #[serde(default)]
    pub part: Option<DiffPart>,
}

fn message(target: &Target, text: &str, part: DiffPart) -> Result<String> {
    let reference = Ref::parse(text)?;
    let source = source::find(target, &reference.project)?;
    let (request, response) = match reference.kind {
        RefKind::Proxy(id) => {
            let (_, request, response) = source::proxy_entry(&source, id)?;
            (request, response)
        }
        RefKind::Archive(seq) => {
            let line = source::archive_line(&source, seq)?;
            (
                STANDARD.decode(&line.request_b64)?,
                line.response_b64
                    .as_deref()
                    .map(|b| STANDARD.decode(b))
                    .transpose()?,
            )
        }
        RefKind::Issue(_) => anyhow::bail!("{text} is an issue; diff compares exchanges"),
    };
    let bytes = match part {
        DiffPart::Request => request,
        DiffPart::Response => response.with_context(|| format!("{text} has no response"))?,
    };
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub fn run(target: &Target, params: &DiffParams) -> Result<Value> {
    let part = params.part.unwrap_or_default();
    let a = message(target, &params.a, part)?;
    let b = message(target, &params.b, part)?;
    let diff = TextDiff::from_lines(&a, &b);
    let unified = diff
        .unified_diff()
        .context_radius(3)
        .header(&params.a, &params.b)
        .to_string();
    Ok(json!({
        "a": params.a,
        "b": params.b,
        "part": match part { DiffPart::Request => "request", DiffPart::Response => "response" },
        "identical": a == b,
        "diff": unified,
    }))
}
