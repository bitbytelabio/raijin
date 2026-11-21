//! `history list` / `history_list`.

use std::collections::HashSet;

use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::source::{self, Kinds, Load};
use super::{Filters, Selection, split_message};
use crate::config::Target;
use crate::util::hex;

pub const DEFAULT_LIMIT: u64 = 100;
pub const MAX_LIMIT: u64 = 1000;

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
pub enum Which {
    Proxy,
    Archive,
    Issues,
    /// Proxy and archive rows.
    #[default]
    All,
}

#[derive(Debug, Clone, Default, clap::Args, serde::Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct ListParams {
    #[command(flatten)]
    #[serde(flatten)]
    pub selection: Selection,
    #[command(flatten)]
    #[serde(flatten)]
    pub filters: Filters,
    /// proxy, archive (Raijin tool traffic), issues (scanner issues), or all (proxy + archive).
    #[arg(long, value_enum)]
    pub source: Option<Which>,
    /// Keep one row per method + URL + request body.
    #[arg(long)]
    pub dedupe: bool,
    /// Rows to return (default 100, max 1000; 0 returns only `total`).
    #[arg(short = 'n', long)]
    pub limit: Option<u64>,
    /// Rows to skip.
    #[arg(long)]
    pub offset: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ListResult {
    pub total: usize,
    pub rows: Vec<Value>,
    pub warnings: Vec<super::Warning>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_clamped_to: Option<u64>,
}

pub fn run(target: &Target, params: &ListParams) -> Result<ListResult> {
    let sources = source::discover(target, &params.selection)?;
    let which = params.source.unwrap_or_default();
    let requested = params.limit.unwrap_or(DEFAULT_LIMIT);
    let limit = requested.min(MAX_LIMIT);
    let offset = usize::try_from(params.offset.unwrap_or(0)).unwrap_or(usize::MAX);
    let take = usize::try_from(limit).unwrap_or(usize::MAX);

    let (rows, warnings): (Vec<(u64, String, Value)>, _) = if which == Which::Issues {
        let (per, warnings) = source::par_map(&sources, |s, _notes| {
            let mut out = Vec::new();
            source::for_each_issue(s, |issue| {
                let row = issue.row(&s.project);
                if params.filters.accepts_issue(&row) {
                    out.push((
                        row.time_epoch_ms,
                        row.reference.clone(),
                        serde_json::to_value(&row)?,
                    ));
                }
                Ok(())
            })?;
            Ok(out)
        });
        (per.into_iter().flatten().collect(), warnings)
    } else {
        let kinds = Kinds {
            proxy: which != Which::Archive,
            archive: which != Which::Proxy,
        };
        let load = Load {
            request: params.dedupe,
            response: false,
        };
        let (per, warnings) = source::par_map(&sources, |s, notes| {
            let mut out = Vec::new();
            source::for_each_exchange(s, &params.filters, kinds, load, notes, |ex| {
                let key = if params.dedupe {
                    dedupe_key(&ex.row, ex.request.as_deref())
                } else {
                    String::new()
                };
                out.push((ex.row.time_epoch_ms, key, serde_json::to_value(&ex.row)?));
                Ok(())
            })?;
            Ok(out)
        });
        let mut rows: Vec<_> = per.into_iter().flatten().collect();
        if params.dedupe {
            rows.sort_by_key(|r| r.0);
            let mut seen = HashSet::new();
            rows.retain(|(_, key, _)| seen.insert(key.clone()));
        }
        (rows, warnings)
    };

    let mut rows = rows;
    rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| ref_of(&a.2).cmp(ref_of(&b.2))));
    let total = rows.len();
    let page = rows
        .into_iter()
        .skip(offset)
        .take(take)
        .map(|(_, _, v)| v)
        .collect();
    Ok(ListResult {
        total,
        rows: page,
        warnings,
        limit_clamped_to: (requested != limit).then_some(limit),
    })
}

fn ref_of(v: &Value) -> &str {
    v["ref"].as_str().unwrap_or_default()
}

fn dedupe_key(row: &super::Row, request: Option<&[u8]>) -> String {
    let body = request.map(|r| split_message(r).1).unwrap_or_default();
    json!([row.method, row.url, hex(&Sha256::digest(body))]).to_string()
}
