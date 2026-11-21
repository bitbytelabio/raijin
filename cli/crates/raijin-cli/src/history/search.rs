//! `history search` / `history_search`: a byte regex over raw requests and responses.

use anyhow::{Context, Result};
use regex::bytes::{Regex, RegexBuilder};
use serde::Serialize;

use super::source::{self, Kinds, Load};
use super::{Filters, Selection, Warning};
use crate::config::Target;

const DEFAULT_CONTEXT: usize = 80;
const MAX_CONTEXT: usize = 2000;
const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 1000;
const HITS_PER_ENTRY: usize = 3;
const MAX_MATCH_BYTES: usize = 1024;
/// Bounds compiled regex size, like Raijin's `SafeRegex`: a hostile pattern fails instead of exhausting memory.
const REGEX_SIZE_LIMIT: usize = 10 * 1024 * 1024;

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
pub enum Part {
    Req,
    Resp,
    #[default]
    Both,
}

#[derive(Debug, Clone, Default, clap::Args, serde::Deserialize, schemars::JsonSchema)]
pub struct SearchParams {
    /// Regex (Rust syntax), matched against raw message bytes; `(?i)` for case-insensitive.
    pub pattern: String,
    /// Where to search: req, resp or both (default).
    #[arg(long = "in", value_enum)]
    #[serde(rename = "in", default)]
    pub part: Option<Part>,
    /// Bytes of context on each side of a hit (default 80).
    #[arg(long)]
    pub context_bytes: Option<usize>,
    /// Hits to return (default 50).
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,
    #[command(flatten)]
    #[serde(flatten)]
    pub selection: Selection,
    #[command(flatten)]
    #[serde(flatten)]
    pub filters: Filters,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hit {
    #[serde(rename = "ref")]
    pub reference: String,
    #[serde(rename = "where")]
    pub location: &'static str,
    pub offset: usize,
    pub snippet: String,
    #[serde(skip)]
    time: u64,
}

#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub total_hits: usize,
    pub hits: Vec<Hit>,
    pub warnings: Vec<Warning>,
}

pub fn run(target: &Target, params: &SearchParams) -> Result<SearchResult> {
    let regex: Regex = RegexBuilder::new(&params.pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .with_context(|| format!("bad pattern {:?}", params.pattern))?;
    let part = params.part.unwrap_or_default();
    let context = params
        .context_bytes
        .unwrap_or(DEFAULT_CONTEXT)
        .min(MAX_CONTEXT);
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let load = Load {
        request: part != Part::Resp,
        response: part != Part::Req,
    };
    let sources = source::discover(target, &params.selection)?;

    // Each project keeps only its first `limit` hits (rows arrive in entry order) and counts the
    // rest; a snippet shows at most MAX_MATCH_BYTES of the match itself.
    let (per, warnings) = source::par_map(&sources, |s, notes| {
        let mut hits = Vec::new();
        let mut total = 0usize;
        source::for_each_exchange(s, &params.filters, Kinds::ALL, load, notes, |ex| {
            let mut found = 0;
            let messages = [
                ("request", ex.request.as_deref()),
                ("response", ex.response.as_deref()),
            ];
            for (location, message) in messages {
                let Some(bytes) = message else { continue };
                for m in regex.find_iter(bytes) {
                    if found == HITS_PER_ENTRY {
                        break;
                    }
                    found += 1;
                    total += 1;
                    if hits.len() == limit {
                        continue;
                    }
                    let start = m.start().saturating_sub(context);
                    let match_end = m.end().min(m.start() + MAX_MATCH_BYTES);
                    let end = (match_end + context).min(bytes.len());
                    hits.push(Hit {
                        reference: ex.row.reference.clone(),
                        location,
                        offset: m.start(),
                        snippet: String::from_utf8_lossy(&bytes[start..end]).into_owned(),
                        time: ex.row.time_epoch_ms,
                    });
                }
            }
            Ok(())
        })?;
        Ok((hits, total))
    });
    let total_hits: usize = per.iter().map(|(_, total)| total).sum();
    let mut hits: Vec<Hit> = per.into_iter().flat_map(|(hits, _)| hits).collect();
    hits.sort_by(|a, b| {
        a.time
            .cmp(&b.time)
            .then_with(|| a.reference.cmp(&b.reference))
    });
    hits.truncate(limit);
    Ok(SearchResult {
        total_hits,
        hits,
        warnings,
    })
}
