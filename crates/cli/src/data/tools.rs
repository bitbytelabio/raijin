//! Arguments and results of the `data_*` tools, shared by `raijin mcp` and `raijin data`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use super::store::{UPSTREAM, manifest};
use super::{Entry, Filters, Kind, Library, Source, matches};
use crate::mcp::error::{Code, ToolError};
use crate::util::{suggest, truncate_utf8};

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    /// Only this source: xss, url, bchecks, bambdas or custom.
    pub source: Option<Source>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct SearchArgs {
    #[serde(flatten)]
    pub filters: Filters,
    /// Rows to return (default 20, max 200).
    pub limit: Option<usize>,
    /// Rows to skip (default 0); the result's `next_offset` continues.
    pub offset: Option<usize>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetArgs {
    /// Entry id from `data_search` (`xss:events/onload/svg`, `bchecks:<path>`, `custom:<category>/<hash>`).
    pub id: String,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
pub struct PayloadsArgs {
    #[serde(flatten)]
    pub filters: Filters,
    /// Host put in place of <attacker> (URL cheat sheet): one you control.
    pub attacker: Option<String>,
    /// Host put in place of <allowed> (URL cheat sheet): the one the target trusts.
    pub allowed: Option<String>,
    /// Payloads to return (default 100, max 2000).
    pub limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddArgs {
    /// payload (default), bcheck or bambda.
    pub kind: Option<Kind>,
    /// Payload file (data/payloads/<category>.json), or a subfolder for a script; letters, digits, '_' and '-'.
    pub category: Option<String>,
    /// The payload string (kind payload).
    pub payload: Option<String>,
    /// Where and why it worked (kind payload).
    pub description: Option<String>,
    /// Tags (kind payload).
    pub tags: Option<Vec<String>>,
    /// The context it fits, e.g. "attribute, double quotes" (kind payload).
    pub context: Option<String>,
    /// File name without extension (kind bcheck or bambda); letters, digits, '_' and '-'.
    pub name: Option<String>,
    /// The whole `BCheck` (starting with `metadata:`) or Bambda (kind bcheck or bambda).
    pub script: Option<String>,
    /// Replace an existing script file of that name.
    pub overwrite: Option<bool>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportArgs {
    /// Id of a `BCheck` or Bambda (`data_search` with kind bcheck or bambda).
    pub id: String,
    /// Burp project to import into (default: the running one).
    pub project: Option<String>,
}

#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateArgs {
    /// Only this source: xss, url, bchecks or bambdas (default: all four).
    pub source: Option<Source>,
}

const SEARCH_LIMIT: usize = 20;
const SEARCH_MAX: usize = 200;
const PAYLOAD_LIMIT: usize = 100;
const PAYLOAD_MAX: usize = 2000;
/// Bytes of a payload shown in a search row.
const ROW_PAYLOAD_BYTES: usize = 300;
const DAY_MS: u64 = 24 * 3600 * 1000;

/// `requested` (else `default`) capped at `max`, and the cap when it applied.
fn clamp(requested: Option<usize>, default: usize, max: usize) -> (usize, Option<usize>) {
    let wanted = requested.unwrap_or(default);
    if wanted > max {
        (max, Some(max))
    } else {
        (wanted, None)
    }
}

fn categories<'a>(entries: impl Iterator<Item = &'a Entry>) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for e in entries {
        *out.entry(e.category.clone()).or_insert(0) += 1;
    }
    out
}

/// `upstream`'s sources with their cache state, and `custom`'s counts.
pub fn list(
    root: &Path,
    custom_dir: Option<&Path>,
    upstream: &Library,
    custom: &Library,
    now: u64,
    only: Option<Source>,
) -> Value {
    let sources: Vec<Value> = UPSTREAM
        .iter()
        .filter(|up| only.is_none_or(|s| s == up.source))
        .map(|up| match manifest(root, up.source) {
            Some(m) => {
                let mine: Vec<&Entry> = upstream
                    .entries
                    .iter()
                    .filter(|e| e.source == up.source)
                    .collect();
                json!({
                    "source": up.source,
                    "repo": up.repo,
                    "branch": up.branch,
                    "license": up.license,
                    "commit": m.commit,
                    "fetched_at_ms": m.fetched_at_ms,
                    "age_days": now.saturating_sub(m.fetched_at_ms) / DAY_MS,
                    "entries": mine.len(),
                    "categories": categories(mine.into_iter()),
                })
            }
            None => json!({"source": up.source, "repo": up.repo, "missing": true}),
        })
        .collect();
    let mut value = json!({
        "cache_dir": root.display().to_string(),
        "custom_dir": custom_dir.map(|d| d.display().to_string()),
        "sources": sources,
    });
    if only.is_none_or(|s| s == Source::Custom) {
        value["custom"] = json!({
            "entries": custom.entries.len(),
            "categories": categories(custom.entries.iter()),
        });
    }
    let warnings: Vec<&super::Warning> = upstream.warnings.iter().chain(&custom.warnings).collect();
    value["warnings"] = json!(warnings);
    value
}

/// One search row: what tells entries apart, the vector of a payload (cut), never a whole script.
fn row(e: &Entry) -> Value {
    let mut r = json!({
        "id": e.id,
        "source": e.source,
        "kind": e.kind,
        "category": e.category,
        "title": e.title,
    });
    if let Some(d) = &e.description
        && *d != e.title
    {
        r["description"] = json!(d);
    }
    if !e.tags.is_empty() {
        r["tags"] = json!(e.tags);
    }
    if !e.browsers.is_empty() {
        r["browsers"] = json!(e.browsers);
    }
    if let Some(i) = e.interaction {
        r["interaction"] = json!(i);
    }
    if let Some(c) = &e.context {
        r["context"] = json!(c);
    }
    if e.kind == Kind::Payload {
        let cut = truncate_utf8(&e.payload, ROW_PAYLOAD_BYTES);
        r["payload"] = json!(cut);
        if cut.len() < e.payload.len() {
            r["truncated"] = json!(true);
        }
    }
    r
}

pub fn search(entries: &[&Entry], args: &SearchArgs) -> Value {
    let (limit, clamped) = clamp(args.limit, SEARCH_LIMIT, SEARCH_MAX);
    let offset = args.offset.unwrap_or(0);
    let hits: Vec<&&Entry> = entries
        .iter()
        .filter(|e| matches(e, &args.filters))
        .collect();
    let rows: Vec<Value> = hits
        .iter()
        .skip(offset)
        .take(limit)
        .map(|e| row(e))
        .collect();
    let mut value = json!({"total": hits.len(), "offset": offset});
    if offset + rows.len() < hits.len() {
        value["next_offset"] = json!(offset + rows.len());
    }
    value["rows"] = json!(rows);
    if let Some(max) = clamped {
        value["limit_clamped_to"] = json!(max);
    }
    value
}

/// The entry `id` names.
pub fn find<'a>(entries: &[&'a Entry], id: &str) -> Result<&'a Entry, ToolError> {
    // An id copied from a file name, with spaces, reads as its slug.
    let slug = super::parse::id_slug(id);
    if let Some(e) = entries.iter().find(|e| e.id == id || e.id == slug) {
        return Ok(e);
    }
    let near: Vec<String> = suggest(id, entries.iter().map(|e| e.id.as_str()), 3)
        .into_iter()
        .map(str::to_owned)
        .collect();
    let words = id.rsplit(['/', ':']).next().unwrap_or(id);
    Err(
        ToolError::new(Code::NotFound, format!("no data entry {id:?}"))
            .param("id")
            .got(json!(id))
            .did_you_mean(near)
            .see(json!({"do": "data_search", "query": words})),
    )
}

pub fn get(entries: &[&Entry], id: &str) -> Result<Value, ToolError> {
    let e = find(entries, id)?;
    serde_json::to_value(e).map_err(|e| ToolError::new(Code::Internal, e.to_string()))
}

/// The payload strings of the matching payload entries, placeholders filled, without duplicates.
pub fn payloads(
    entries: &[&Entry],
    args: &PayloadsArgs,
) -> Result<(Value, Vec<String>), ToolError> {
    if let Some(kind) = args.filters.kind.filter(|k| *k != Kind::Payload) {
        return Err(ToolError::new(
            Code::InvalidEnum,
            "data_payloads returns payload strings only; search scripts with data_search",
        )
        .param("kind")
        .got(json!(kind))
        .allowed(vec![json!("payload")]));
    }
    let (limit, clamped) = clamp(args.limit, PAYLOAD_LIMIT, PAYLOAD_MAX);
    let mut seen = BTreeSet::new();
    let mut all = Vec::new();
    for e in entries
        .iter()
        .filter(|e| e.kind == Kind::Payload && matches(e, &args.filters))
    {
        let mut p = e.payload.clone();
        if let Some(a) = &args.attacker {
            p = p.replace("<attacker>", a);
        }
        if let Some(a) = &args.allowed {
            p = p.replace("<allowed>", a);
        }
        if !p.is_empty() && seen.insert(p.clone()) {
            all.push(p);
        }
    }
    let total = all.len();
    all.truncate(limit);
    let mut notes = Vec::new();
    if all
        .iter()
        .any(|p| p.contains("<attacker>") || p.contains("<allowed>"))
    {
        notes.push(
            "payloads contain <attacker>/<allowed>; pass \"attacker\":\"<host>\" and \"allowed\":\"<host>\""
                .to_owned(),
        );
    }
    let mut value = json!({"total": total, "count": all.len(), "payloads": all});
    if let Some(max) = clamped {
        value["limit_clamped_to"] = json!(max);
    }
    Ok((value, notes))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn payload(id: &str, p: &str) -> Entry {
        Entry::new(
            id.into(),
            Source::Url,
            Kind::Payload,
            "loopback".into(),
            "t".into(),
            p.into(),
            PathBuf::new(),
        )
    }

    #[test]
    fn placeholders_are_filled_or_noted() {
        let a = payload("url:a", "http://<attacker>/?<allowed>");
        let b = payload("url:b", "http://<attacker>/?<allowed>");
        let entries = [&a, &b];
        let args: PayloadsArgs =
            serde_json::from_value(json!({"attacker": "evil.example", "allowed": "good.example"}))
                .expect("args");
        let (value, notes) = payloads(&entries, &args).expect("payloads");
        assert_eq!(
            value["payloads"],
            json!(["http://evil.example/?good.example"])
        );
        assert_eq!(notes, Vec::<String>::new());
        let (_, notes) = payloads(&entries, &PayloadsArgs::default()).expect("raw");
        assert_eq!(notes.len(), 1);
        let bad = PayloadsArgs {
            filters: Filters {
                kind: Some(Kind::Bcheck),
                ..Filters::default()
            },
            ..PayloadsArgs::default()
        };
        assert_eq!(
            payloads(&entries, &bad).expect_err("kind").code,
            Code::InvalidEnum
        );
    }

    #[test]
    fn search_pages_and_clamps() {
        let all: Vec<Entry> = (0..5).map(|i| payload(&format!("url:{i}"), "x")).collect();
        let refs: Vec<&Entry> = all.iter().collect();
        let args: SearchArgs =
            serde_json::from_value(json!({"limit": 2, "offset": 2})).expect("args");
        let v = search(&refs, &args);
        assert_eq!(v["total"], 5);
        assert_eq!(v["next_offset"], 4);
        let big: SearchArgs = serde_json::from_value(json!({"limit": 1000})).expect("args");
        assert_eq!(search(&refs, &big)["limit_clamped_to"], 200);
        let missing = get(&refs, "url:9").expect_err("missing");
        assert_eq!(missing.code, Code::NotFound);
    }
}
