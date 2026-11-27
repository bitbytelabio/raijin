//! Arguments and results of the `data_*` tools, shared by `raijin mcp` and `raijin data`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

use super::store::{UPSTREAM, manifest};
use super::{
    Entry, Filters, Kind, Library, Source, browser_name, category_matches, haystack, matches,
    query_words,
};
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
    pub source: Option<UpdateSource>,
}

/// A source `data_update` downloads: every [`Source`] but `custom`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum UpdateSource {
    Xss,
    Url,
    Bchecks,
    Bambdas,
}

impl From<UpdateSource> for Source {
    fn from(s: UpdateSource) -> Self {
        match s {
            UpdateSource::Xss => Self::Xss,
            UpdateSource::Url => Self::Url,
            UpdateSource::Bchecks => Self::Bchecks,
            UpdateSource::Bambdas => Self::Bambdas,
        }
    }
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

/// Most categories or browsers an `invalid_enum` of a filter lists.
const MAX_ALLOWED: usize = 20;

/// `values` for `allowed`: the ones nearest `got` first, then the rest, at most [`MAX_ALLOWED`];
/// and the nearest ones for `did_you_mean`.
fn allowed_and_near(got: &str, values: &BTreeSet<String>) -> (Vec<Value>, Vec<String>) {
    let near: Vec<String> = suggest(got, values.iter().map(String::as_str), 3)
        .into_iter()
        .map(str::to_owned)
        .collect();
    let mut allowed: Vec<String> = near.clone();
    allowed.extend(values.iter().filter(|v| !near.contains(v)).cloned());
    allowed.truncate(MAX_ALLOWED);
    (allowed.into_iter().map(Value::String).collect(), near)
}

/// `f` checked against the entries its `source` and `kind` select, for `tool`: a category in
/// another form (`Restricted Characters`) is read as the one entries use, an id pasted as category
/// (`events/onload`) as category + tag, a browser alias (`chromium`) as its name; a category or
/// browser no entry has is `invalid_enum`. Each reading is noted. Without entries (a source not
/// downloaded) nothing is checked.
fn checked_filters(
    tool: &str,
    entries: &[&Entry],
    filters: &Filters,
) -> Result<(Filters, Vec<String>), ToolError> {
    let mut f = filters.clone();
    let mut notes = Vec::new();
    let pool: Vec<&Entry> = entries
        .iter()
        .copied()
        .filter(|e| f.source.is_none_or(|s| s == e.source) && f.kind.is_none_or(|k| k == e.kind))
        .collect();
    if pool.is_empty() {
        return Ok((f, notes));
    }
    let source = f.source;
    let see = || match source {
        Some(s) => json!({"do": "data_list", "source": s}),
        None => json!({"do": "data_list"}),
    };
    if let Some(c) = f.category.clone().filter(|c| !c.trim().is_empty()) {
        if let Some(e) = pool.iter().find(|e| category_matches(&e.category, &c)) {
            let depth = c.split('/').count();
            let actual = e
                .category
                .split('/')
                .take(depth)
                .collect::<Vec<_>>()
                .join("/");
            if !actual.eq_ignore_ascii_case(c.trim()) {
                notes.push(format!("matched 'category' \"{c}\" to \"{actual}\""));
            }
            f.category = Some(actual);
        } else if let Some((head, _)) = c.split_once('/')
            && let Some(e) = pool.iter().find(|e| category_matches(&e.category, head))
        {
            let category = e.category.split('/').next().unwrap_or_default().to_owned();
            let tag = c.rsplit('/').next().unwrap_or_default().trim().to_owned();
            notes.push(format!(
                "read 'category' \"{c}\" as category \"{category}\" + tag \"{tag}\""
            ));
            f.category = Some(category);
            if f.tag.as_deref().is_none_or(str::is_empty) && !tag.is_empty() {
                f.tag = Some(tag);
            }
        } else {
            let cats: BTreeSet<String> = pool.iter().map(|e| e.category.clone()).collect();
            let (allowed, near) = allowed_and_near(&c, &cats);
            return Err(ToolError::new(
                Code::InvalidEnum,
                format!(
                    "{tool}: no entry has category \"{c}\"; 'allowed' lists categories of the selected data."
                ),
            )
            .param("category")
            .got(json!(c))
            .allowed(allowed)
            .did_you_mean(near)
            .see(see()));
        }
    }
    if let Some(b) = f.browser.clone().filter(|b| !b.trim().is_empty()) {
        let name = browser_name(&b);
        let browsers: BTreeSet<String> = pool
            .iter()
            .flat_map(|e| e.browsers.iter().map(|x| x.to_lowercase()))
            .collect();
        if !browsers.contains(&name) {
            let (allowed, near) = allowed_and_near(&name, &browsers);
            let listed = if browsers.is_empty() {
                "the selected entries name no browser"
            } else {
                "'allowed' lists the browsers entries name"
            };
            return Err(ToolError::new(
                Code::InvalidEnum,
                format!("{tool}: no entry has browser \"{b}\"; {listed}."),
            )
            .param("browser")
            .got(json!(b))
            .allowed(allowed)
            .did_you_mean(near)
            .see(see()));
        }
        if name != b.trim().to_lowercase() {
            notes.push(format!("matched 'browser' \"{b}\" to \"{name}\""));
        }
        f.browser = Some(name);
    }
    Ok((f, notes))
}

/// Why `f` matched nothing, as notes: a tag no entry of the selected source and kind has (with the
/// closest ones), and each query word no entry contains (with how many the other words match).
fn zero_notes(entries: &[&Entry], f: &Filters) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(t) = f.tag.as_deref().filter(|t| !t.is_empty()) {
        let tags: BTreeSet<&str> = entries
            .iter()
            .filter(|e| {
                f.source.is_none_or(|s| s == e.source) && f.kind.is_none_or(|k| k == e.kind)
            })
            .flat_map(|e| e.tags.iter().map(String::as_str))
            .collect();
        if !tags.iter().any(|x| x.eq_ignore_ascii_case(t)) {
            let near = suggest(t, tags.iter().copied(), 3);
            notes.push(if near.is_empty() {
                format!("no entry has tag \"{t}\"")
            } else {
                format!("no entry has tag \"{t}\"; closest: {}", near.join(", "))
            });
        }
    }
    if let Some(q) = f.query.as_deref() {
        let unqueried = Filters {
            query: None,
            ..f.clone()
        };
        let hays: Vec<String> = entries
            .iter()
            .filter(|e| matches(e, &unqueried))
            .map(|e| haystack(e))
            .collect();
        let holds =
            |text: &str, token: &str| query_words(token).iter().all(|w| text.contains(w.as_str()));
        let (present, missing): (Vec<&str>, Vec<&str>) = q
            .split_whitespace()
            .partition(|token| hays.iter().any(|h| holds(h, token)));
        let alone = if present.is_empty() {
            String::new()
        } else {
            let n = hays
                .iter()
                .filter(|h| present.iter().all(|token| holds(h, token)))
                .count();
            format!("; \"{}\" alone matches {n}", present.join(" "))
        };
        notes.extend(
            missing
                .iter()
                .map(|m| format!("no entry contains \"{m}\"{alone}")),
        );
    }
    notes
}

/// Search rows for `args`, rows whose title holds every query word first; notes say how filters
/// were read and, without hits, why.
pub fn search(entries: &[&Entry], args: &SearchArgs) -> Result<(Value, Vec<String>), ToolError> {
    let (filters, mut notes) = checked_filters("data_search", entries, &args.filters)?;
    let (limit, clamped) = clamp(args.limit, SEARCH_LIMIT, SEARCH_MAX);
    let offset = args.offset.unwrap_or(0);
    let mut hits: Vec<&&Entry> = entries.iter().filter(|e| matches(e, &filters)).collect();
    let words = filters.query.as_deref().map_or_default(query_words);
    if !words.is_empty() {
        hits.sort_by_key(|e| {
            let title = e.title.to_lowercase().replace(['-', '_'], " ");
            !words.iter().all(|w| title.contains(w.as_str()))
        });
    }
    let rows: Vec<Value> = hits
        .iter()
        .skip(offset)
        .take(limit)
        .map(|e| row(e))
        .collect();
    let mut value = json!({"total": hits.len(), "offset": offset});
    if !rows.is_empty() && offset + rows.len() < hits.len() {
        value["next_offset"] = json!(offset + rows.len());
    }
    value["rows"] = json!(rows);
    if let Some(max) = clamped {
        value["limit_clamped_to"] = json!(max);
    }
    if hits.is_empty() {
        notes.extend(zero_notes(entries, &filters));
    }
    Ok((value, notes))
}

/// The entry `id` names, and a note when it was read leniently: in another case, or without its
/// `<source>:` prefix, when that names one entry. `tool` is the call made; only `data_get` gets a
/// `retry` with the one near id.
pub fn find<'a>(
    entries: &[&'a Entry],
    id: &str,
    tool: &str,
) -> Result<(&'a Entry, Option<String>), ToolError> {
    // An id copied from a file name, with spaces, reads as its slug.
    let slug = super::parse::id_slug(id);
    if let Some(e) = entries.iter().find(|e| e.id == id || e.id == slug) {
        return Ok((e, None));
    }
    let t = id.trim();
    if t.len() >= 2 && t.starts_with('<') && t.ends_with('>') {
        return Err(ToolError::new(
            Code::PlaceholderValue,
            format!("{tool}: 'id' is the placeholder {t:?}; take a real id from data_search"),
        )
        .param("id")
        .got(json!(id))
        .see(json!({"do": "data_search"})));
    }
    let only = |hits: Vec<&'a Entry>| match hits[..] {
        [one] => Some(one),
        _ => None,
    };
    let same = |e: &Entry, want: &str| e.id.eq_ignore_ascii_case(want);
    if let Some(e) = only(
        entries
            .iter()
            .copied()
            .filter(|e| same(e, t) || same(e, &slug))
            .collect(),
    ) {
        return Ok((
            e,
            Some(format!("matched id case-insensitively to \"{}\"", e.id)),
        ));
    }
    if let Some(e) = only(
        entries
            .iter()
            .copied()
            .filter(|e| {
                let prefix = e.source.as_str();
                same(e, &format!("{prefix}:{t}")) || same(e, &format!("{prefix}:{slug}"))
            })
            .collect(),
    ) {
        return Ok((e, Some(format!("read id as \"{}\"", e.id))));
    }
    let near: Vec<String> = suggest(id, entries.iter().map(|e| e.id.as_str()), 3)
        .into_iter()
        .map(str::to_owned)
        .collect();
    let words = id.rsplit(['/', ':']).next().unwrap_or(id);
    let mut error = ToolError::new(Code::NotFound, format!("no data entry {id:?}"))
        .param("id")
        .got(json!(id))
        .see(json!({"do": "data_search", "query": words}));
    // Reading is safe to retry; an import of another script is not.
    if let [one] = near.as_slice()
        && tool == "data_get"
    {
        error = error.retry(json!({"do": tool, "id": one}));
    }
    Err(error.did_you_mean(near))
}

pub fn get(entries: &[&Entry], id: &str) -> Result<(Value, Option<String>), ToolError> {
    let (e, note) = find(entries, id, "data_get")?;
    serde_json::to_value(e)
        .map(|v| (v, note))
        .map_err(|e| ToolError::new(Code::Internal, e.to_string()))
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
    if let Some(source) = args
        .filters
        .source
        .filter(|s| matches!(s, Source::Bchecks | Source::Bambdas))
    {
        return Err(ToolError::new(
            Code::InvalidEnum,
            format!(
                "data_payloads returns payload strings only; {} holds scripts: search them with data_search",
                source.as_str()
            ),
        )
        .param("source")
        .got(json!(source))
        .allowed(vec![json!("xss"), json!("url"), json!("custom")])
        .see(json!({"do": "data_search", "source": source})));
    }
    let (filters, mut notes) = checked_filters("data_payloads", entries, &args.filters)?;
    // A strict-mode client sends "" for a host it has none for: filling it in would cut payloads.
    let host = |name: &str, value: Option<&str>, notes: &mut Vec<String>| {
        let value = value.map(str::trim).filter(|v| !v.is_empty())?;
        if value.contains('/') {
            notes.push(format!("'{name}' should be a host (got {value:?})"));
        }
        Some(value.to_owned())
    };
    let attacker = host("attacker", args.attacker.as_deref(), &mut notes);
    let allowed = host("allowed", args.allowed.as_deref(), &mut notes);
    let (limit, clamped) = clamp(args.limit, PAYLOAD_LIMIT, PAYLOAD_MAX);
    let mut seen = BTreeSet::new();
    let mut all = Vec::new();
    for e in entries
        .iter()
        .filter(|e| e.kind == Kind::Payload && matches(e, &filters))
    {
        let mut p = e.payload.clone();
        if let Some(a) = &attacker {
            p = p.replace("<attacker>", a);
        }
        if let Some(a) = &allowed {
            p = p.replace("<allowed>", a);
        }
        if !p.is_empty() && seen.insert(p.clone()) {
            all.push(p);
        }
    }
    let total = all.len();
    if total == 0 {
        notes.extend(zero_notes(entries, &filters));
    }
    all.truncate(limit);
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
        let empty: PayloadsArgs =
            serde_json::from_value(json!({"attacker": "", "allowed": " "})).expect("args");
        let (value, notes) = payloads(&entries, &empty).expect("empty hosts");
        assert_eq!(value["payloads"], json!(["http://<attacker>/?<allowed>"]));
        assert_eq!(notes.len(), 1, "{notes:?}");
        let url: PayloadsArgs =
            serde_json::from_value(json!({"attacker": "https://evil.example/"})).expect("args");
        let (_, notes) = payloads(&entries, &url).expect("url host");
        assert!(
            notes
                .iter()
                .any(|n| n.starts_with("'attacker' should be a host")),
            "{notes:?}"
        );
        let scripts: PayloadsArgs =
            serde_json::from_value(json!({"source": "bchecks"})).expect("args");
        let e = payloads(&entries, &scripts).expect_err("scripts");
        assert_eq!(
            (e.code, e.param.as_deref()),
            (Code::InvalidEnum, Some("source"))
        );
    }

    fn search_of(entries: &[&Entry], args: Value) -> Result<(Value, Vec<String>), ToolError> {
        search(entries, &serde_json::from_value(args).expect("args"))
    }

    #[test]
    fn search_pages_and_clamps() {
        let all: Vec<Entry> = (0..5).map(|i| payload(&format!("url:{i}"), "x")).collect();
        let refs: Vec<&Entry> = all.iter().collect();
        let (v, _) = search_of(&refs, json!({"limit": 2, "offset": 2})).expect("search");
        assert_eq!(v["total"], 5);
        assert_eq!(v["next_offset"], 4);
        let (big, _) = search_of(&refs, json!({"limit": 1000})).expect("search");
        assert_eq!(big["limit_clamped_to"], 200);
        let (none, _) = search_of(&refs, json!({"limit": 0})).expect("limit 0");
        assert_eq!(none["total"], 5);
        assert!(none.get("next_offset").is_none(), "{none}");
        let missing = get(&refs, "url:9").expect_err("missing");
        assert_eq!(missing.code, Code::NotFound);
    }

    fn xss(id: &str, category: &str, title: &str, tags: &[&str]) -> Entry {
        let mut e = Entry::new(
            id.into(),
            Source::Xss,
            Kind::Payload,
            category.into(),
            title.into(),
            "<x>".into(),
            PathBuf::new(),
        );
        e.tags = tags.iter().map(|t| (*t).to_owned()).collect();
        e.browsers = vec!["chrome".into()];
        e
    }

    #[test]
    fn filters_in_another_form_are_read_or_refused_with_the_values() {
        let a = xss(
            "xss:restricted_characters/a",
            "restricted_characters",
            "no parens",
            &["a"],
        );
        let b = xss(
            "xss:events/onload/svg",
            "events",
            "onload on svg",
            &["onload", "svg"],
        );
        let refs = [&a, &b];
        let (v, notes) =
            search_of(&refs, json!({"category": "Restricted Characters"})).expect("category");
        assert_eq!(v["total"], 1);
        assert_eq!(
            notes,
            ["matched 'category' \"Restricted Characters\" to \"restricted_characters\""]
        );
        let nope = search_of(&refs, json!({"category": "nope"})).expect_err("unknown");
        assert_eq!(nope.code, Code::InvalidEnum);
        assert_eq!(
            nope.allowed,
            [json!("events"), json!("restricted_characters")]
        );
        let (v, notes) = search_of(&refs, json!({"category": "events/onload"})).expect("id");
        assert_eq!(v["total"], 1, "{notes:?}");
        let (v, notes) = search_of(&refs, json!({"browser": "chromium"})).expect("browser");
        assert_eq!(v["total"], 2);
        assert_eq!(notes, ["matched 'browser' \"chromium\" to \"chrome\""]);
        let safari = search_of(&refs, json!({"browser": "safari"})).expect_err("safari");
        assert_eq!(safari.allowed, [json!("chrome")]);
        let (v, notes) = search_of(&refs, json!({"tag": "on-load"})).expect("tag");
        assert_eq!(v["total"], 0);
        assert_eq!(notes, ["no entry has tag \"on-load\"; closest: onload"]);
        let (_, notes) = search_of(&refs, json!({"query": "svg nowhere"})).expect("query");
        assert_eq!(
            notes,
            ["no entry contains \"nowhere\"; \"svg\" alone matches 1"]
        );
    }

    #[test]
    fn title_hits_come_first() {
        let a = xss("xss:a", "c", "autoconfig actuator", &["beans"]);
        let b = xss("xss:b", "c", "beans actuator", &[]);
        let (v, _) = search_of(&[&a, &b], json!({"query": "beans actuator"})).expect("search");
        assert_eq!(v["rows"][0]["id"], "xss:b");
        assert_eq!(v["rows"][1]["id"], "xss:a");
    }

    #[test]
    fn an_id_in_another_case_or_without_its_source_is_found() {
        let a = xss("xss:events/onload/svg", "events", "t", &[]);
        let refs = [&a];
        let (_, note) = find(&refs, "xss:events/onload/SVG", "data_get").expect("case");
        assert!(note.is_some());
        let (e, note) = find(&refs, "events/onload/svg", "data_get").expect("prefix");
        assert_eq!(e.id, "xss:events/onload/svg");
        assert_eq!(
            note.as_deref(),
            Some("read id as \"xss:events/onload/svg\"")
        );
        let placeholder = find(&refs, "<id>", "data_get").expect_err("placeholder");
        assert_eq!(placeholder.code, Code::PlaceholderValue);
        let near = find(&refs, "xss:events/onload/sv", "data_get").expect_err("near");
        assert_eq!(
            near.retry,
            Some(json!({"do": "data_get", "id": "xss:events/onload/svg"}))
        );
        let import = find(&refs, "xss:events/onload/sv", "data_import").expect_err("near");
        assert_eq!(
            import.retry, None,
            "an import of another script is never retried"
        );
    }
}
