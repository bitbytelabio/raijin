//! `PortSwigger`'s public data (XSS and URL-validation cheat sheets, `BChecks`, Bambdas) cached once per
//! machine in `~/.raijin/data/`, plus this target's own payloads and scripts (`[data] dir`).
//! Never bundled: the cheat sheets carry no license, so they are only downloaded on the user's machine.

pub mod custom;
pub mod parse;
pub mod store;
pub mod tools;

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Where an entry comes from: one of `PortSwigger`'s repos, or this target's own data.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Xss,
    Url,
    Bchecks,
    Bambdas,
    Custom,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Xss => "xss",
            Self::Url => "url",
            Self::Bchecks => "bchecks",
            Self::Bambdas => "bambdas",
            Self::Custom => "custom",
        }
    }
}

/// What an entry holds: a payload string, or a `BCheck` or Bambda script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Payload,
    Bcheck,
    Bambda,
}

/// One vector, `BCheck` or Bambda.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    pub id: String,
    pub source: Source,
    pub kind: Kind,
    pub category: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The vector for payloads; the whole file text for scripts.
    pub payload: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub browsers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interaction: Option<bool>,
    /// Every other upstream field (`url`, `hash`, `prefix`, `author`, `given`, `bambda_id`, ...).
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub extra: Map<String, Value>,
    pub file: PathBuf,
}

impl Entry {
    /// An entry with only its identity, payload and file set.
    pub fn new(
        id: String,
        source: Source,
        kind: Kind,
        category: String,
        title: String,
        payload: String,
        file: PathBuf,
    ) -> Self {
        Self {
            id,
            source,
            kind,
            category,
            title,
            description: None,
            payload,
            tags: Vec::new(),
            browsers: Vec::new(),
            context: None,
            interaction: None,
            extra: Map::new(),
            file,
        }
    }
}

/// A file that could not be read or parsed; the rest of the load goes on.
#[derive(Debug, Clone, Serialize)]
pub struct Warning {
    pub file: String,
    pub error: String,
}

#[derive(Debug, Clone, Default)]
pub struct Library {
    pub entries: Vec<Entry>,
    pub warnings: Vec<Warning>,
}

impl Library {
    /// Appends `-2`, `-3`, ... to ids already taken, in order.
    pub fn dedupe_ids(&mut self) {
        let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for e in &mut self.entries {
            let n = seen.entry(e.id.clone()).or_insert(0);
            *n += 1;
            if *n > 1 {
                e.id = format!("{}-{n}", e.id);
            }
        }
    }
}

/// Filters shared by `data_search` and `data_payloads`; every one given must match.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
pub struct Filters {
    /// Words (space-separated), all of which must appear, in any case, in the title, description, payload, category or tags.
    pub query: Option<String>,
    /// xss, url, bchecks, bambdas (from `PortSwigger`) or custom (this target's data/).
    pub source: Option<Source>,
    /// payload, bcheck or bambda.
    pub kind: Option<Kind>,
    /// Category (file or folder) in any case; also matches its subfolders (`Filter` matches `Filter/Proxy/HTTP`).
    pub category: Option<String>,
    /// One tag, exact in any case (xss: event or element; url: URL, HOST, CORS; bchecks: passive, active, ...).
    pub tag: Option<String>,
    /// Only vectors known to work in this browser (chrome, firefox, safari).
    pub browser: Option<String>,
    /// Text in the vector's context (xss cheat sheet), any case.
    pub context: Option<String>,
    /// true: leave out vectors that need a user action.
    pub no_interaction: Option<bool>,
}

/// A category segment or word in one form: lowercase, `-`, ` ` and `_` as `_`, one trailing `s`
/// dropped (`Restricted Characters` and `restricted_character` -> `restricted_character`).
pub fn norm_term(s: &str) -> String {
    let mut t: String = s
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if matches!(c, '-' | ' ' | '_') { '_' } else { c })
        .collect();
    if t.len() > 1 && t.ends_with('s') {
        t.pop();
    }
    t
}

/// A category path with each `/` segment in [`norm_term`] form.
pub fn norm_category(s: &str) -> String {
    s.split('/').map(norm_term).collect::<Vec<_>>().join("/")
}

/// Whether category `cat` is `wanted` or one of its subfolders, both in [`norm_category`] form.
pub fn category_matches(cat: &str, wanted: &str) -> bool {
    let cat = norm_category(cat);
    let wanted = norm_category(wanted);
    cat == wanted || cat.starts_with(&format!("{wanted}/"))
}

/// The browser name entries use for `b`: `chromium` and `edge` are `chrome`, `ff` is `firefox`.
pub fn browser_name(b: &str) -> String {
    let b = b.trim().to_lowercase();
    match b.as_str() {
        "chromium" | "edge" => "chrome".to_owned(),
        "ff" => "firefox".to_owned(),
        _ => b,
    }
}

/// The words of a query: lowercase, split on spaces, `-` and `_`.
pub fn query_words(q: &str) -> Vec<String> {
    q.to_lowercase()
        .split([' ', '\t', '\n', '-', '_'])
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The text a query searches in `e`: title, description, payload, category and tags, lowercase,
/// with `-` and `_` as spaces.
pub fn haystack(e: &Entry) -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}",
        e.title,
        e.description.as_deref().unwrap_or_default(),
        e.payload,
        e.category,
        e.tags.join(" ")
    )
    .to_lowercase()
    .replace(['-', '_'], " ")
}

/// Whether `e` passes every filter of `f`.
pub fn matches(e: &Entry, f: &Filters) -> bool {
    if f.source.is_some_and(|s| s != e.source) || f.kind.is_some_and(|k| k != e.kind) {
        return false;
    }
    if let Some(c) = f.category.as_deref().filter(|c| !c.is_empty())
        && !category_matches(&e.category, c)
    {
        return false;
    }
    if let Some(t) = f.tag.as_deref().filter(|t| !t.is_empty())
        && !e.tags.iter().any(|x| x.eq_ignore_ascii_case(t))
    {
        return false;
    }
    if let Some(b) = f.browser.as_deref().filter(|b| !b.is_empty()) {
        let b = browser_name(b);
        if !e.browsers.iter().any(|x| x.eq_ignore_ascii_case(&b)) {
            return false;
        }
    }
    if let Some(c) = f.context.as_deref().filter(|c| !c.is_empty())
        && !e
            .context
            .as_deref()
            .is_some_and(|x| x.to_lowercase().contains(&c.to_lowercase()))
    {
        return false;
    }
    if f.no_interaction == Some(true) && e.interaction == Some(true) {
        return false;
    }
    if let Some(q) = f.query.as_deref() {
        let words = query_words(q);
        if !words.is_empty() {
            let hay = haystack(e);
            if !words.iter().all(|w| hay.contains(w.as_str())) {
                return false;
            }
        }
    }
    true
}

/// The first 8 hex characters of `sha256(text)`: a stable id for an entry without one.
pub fn id_hash(text: &str) -> String {
    crate::util::hex(&Sha256::digest(text.as_bytes())[..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        let mut e = Entry::new(
            "xss:events/onload/svg".into(),
            Source::Xss,
            Kind::Payload,
            "events".into(),
            "onload on svg".into(),
            "<svg onload=alert(1)>".into(),
            PathBuf::new(),
        );
        e.tags = vec!["onload".into(), "svg".into()];
        e.browsers = vec!["chrome".into()];
        e.interaction = Some(false);
        e
    }

    #[test]
    fn filters_combine() {
        let e = entry();
        let f = |v: Value| -> Filters { serde_json::from_value(v).expect("filters") };
        assert!(matches(&e, &f(serde_json::json!({"query": "SVG Onload"}))));
        assert!(!matches(&e, &f(serde_json::json!({"query": "svg img"}))));
        assert!(matches(
            &e,
            &f(serde_json::json!({"category": "EVENTS", "tag": "SVG"}))
        ));
        assert!(matches(&e, &f(serde_json::json!({"category": "Event"}))));
        assert!(!matches(&e, &f(serde_json::json!({"category": "even"}))));
        assert!(matches(&e, &f(serde_json::json!({"browser": "Chromium"}))));
        assert!(matches(
            &e,
            &f(serde_json::json!({"query": "onload-on_svg"}))
        ));
        assert!(!matches(&e, &f(serde_json::json!({"browser": "safari"}))));
        assert!(!matches(&e, &f(serde_json::json!({"source": "url"}))));
        assert!(matches(&e, &f(serde_json::json!({"no_interaction": true}))));
    }

    #[test]
    fn category_matches_subfolders() {
        let mut e = entry();
        e.category = "Filter/Proxy/HTTP".into();
        let f = Filters {
            category: Some("filter".into()),
            ..Filters::default()
        };
        assert!(matches(&e, &f));
    }
}
