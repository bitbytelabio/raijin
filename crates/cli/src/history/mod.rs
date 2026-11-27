//! Offline review of a target's `.burp` projects (vendored bproj) and the Raijin exchange archive.
//!
//! Every operation is a CLI subcommand (`raijin history …`) and an MCP tool (`history_…`) with the
//! same parameters: the parameter structs derive both `clap::Args` and `Deserialize`/`JsonSchema`.

pub mod diff;
pub mod endpoints;
pub mod export;
pub mod list;
pub mod search;
pub mod show;
pub mod source;

use anyhow::{Result, bail};
use bproj::HistoryFilter;
use serde::{Deserialize, Deserializer, Serialize};

/// A history failure the caller fixes by changing the call; `raijin mcp` gives each its own error
/// code. Raised through `anyhow` and found again with [`Problem::of`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// A ref that does not parse.
    BadRef(String),
    /// A ref with nothing behind it.
    NotFound(String),
    /// A project the target does not have.
    UnknownProject { wanted: String, known: Vec<String> },
    /// A search pattern that is not a regex, with why on one line.
    BadPattern { pattern: String, reason: String },
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadRef(message) | Self::NotFound(message) => f.write_str(message),
            Self::BadPattern { reason, .. } => {
                write!(f, "'pattern' is not a valid regex ({reason})")
            }
            Self::UnknownProject { wanted, known } => {
                write!(f, "no project {wanted:?}; known: {}", known.join(", "))
            }
        }
    }
}

impl std::error::Error for Problem {}

impl Problem {
    /// The [`Problem`] in `error`'s chain, if any.
    pub fn of(error: &anyhow::Error) -> Option<&Self> {
        error.chain().find_map(|e| e.downcast_ref::<Self>())
    }
}

/// Which files to read: `project` names (default: every project) or `file` globs (replace discovery).
#[derive(Debug, Clone, Default, clap::Args, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct Selection {
    /// Project name(s) to read; default all projects of the target.
    #[arg(short = 'p', long = "project")]
    #[serde(deserialize_with = "one_or_many")]
    #[schemars(with = "OneOrMany")]
    pub project: Vec<String>,
    /// .burp file glob(s), relative to the target root; replaces project discovery.
    #[arg(long = "file")]
    #[serde(deserialize_with = "one_or_many")]
    #[schemars(with = "OneOrMany")]
    pub file: Vec<String>,
}

/// A string or a list of strings.
#[derive(schemars::JsonSchema)]
#[serde(untagged)]
#[allow(dead_code)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

fn one_or_many<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        One(String),
        Many(Vec<String>),
    }
    Ok(match Option::<Raw>::deserialize(d)? {
        None => Vec::new(),
        Some(Raw::One(s)) => vec![s],
        Some(Raw::Many(v)) => v,
    })
}

/// bproj's history filters. On archive rows the same predicates run in Rust; a comment or
/// highlight filter excludes archive rows (they have neither).
#[derive(Debug, Clone, Default, clap::Args, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct Filters {
    /// Exact host, case-insensitive.
    #[arg(short = 'H', long)]
    pub host: Option<String>,
    /// Case-insensitive substring of the absolute URL.
    #[arg(short = 'u', long)]
    pub url: Option<String>,
    /// Exact request method, case-insensitive.
    #[arg(short = 'X', long)]
    pub method: Option<String>,
    /// Status codes to keep (any of).
    #[arg(short = 's', long, value_name = "CODE")]
    pub status: Vec<u64>,
    /// Lower bound on the request time, epoch milliseconds.
    #[arg(short = 'S', long, value_name = "EPOCH_MS")]
    pub since: Option<u64>,
    /// Upper bound on the request time, epoch milliseconds.
    #[arg(short = 'U', long, value_name = "EPOCH_MS")]
    pub until: Option<u64>,
    /// Case-insensitive substring of the response Content-Type.
    #[arg(short = 'm', long)]
    pub mime: Option<String>,
    /// Exact tool (Proxy rows: Burp's tool source; archive rows: the Raijin tool name).
    #[arg(short = 't', long)]
    pub tool: Option<String>,
    /// Case-insensitive substring of the Proxy comment.
    #[arg(short = 'c', long)]
    pub comment: Option<String>,
    /// Proxy highlight colour, or `none`.
    #[arg(short = 'l', long)]
    pub highlight: Option<String>,
}

impl Filters {
    pub fn bproj(&self) -> Result<HistoryFilter> {
        let filter = HistoryFilter {
            host: self.host.clone(),
            url_contains: self.url.clone(),
            method: self.method.clone(),
            status: self.status.clone(),
            since_epoch_ms: self.since,
            until_epoch_ms: self.until,
            mime_contains: self.mime.clone(),
            tool: self.tool.clone(),
            comment_contains: self.comment.clone(),
            highlight: self.highlight.clone(),
            entry_id: None,
        };
        filter.validate()?;
        Ok(filter)
    }

    /// The bproj predicates applied to an archive row.
    pub fn accepts_archive(&self, row: &Row) -> bool {
        if self.comment.is_some() || self.highlight.is_some() {
            return false;
        }
        let eq = |want: &Option<String>, have: Option<&str>| {
            want.as_ref()
                .is_none_or(|w| have.is_some_and(|h| h.eq_ignore_ascii_case(w)))
        };
        let contains = |want: &Option<String>, have: Option<&str>| {
            want.as_ref().is_none_or(|w| {
                have.is_some_and(|h| h.to_ascii_lowercase().contains(&w.to_ascii_lowercase()))
            })
        };
        eq(&self.host, row.host.as_deref())
            && contains(&self.url, row.url.as_deref())
            && eq(&self.method, row.method.as_deref())
            && (self.status.is_empty() || row.status.is_some_and(|s| self.status.contains(&s)))
            && self.since.is_none_or(|s| row.time_epoch_ms >= s)
            && self.until.is_none_or(|u| row.time_epoch_ms <= u)
            && contains(&self.mime, row.mime.as_deref())
            && eq(&self.tool, Some(row.tool.as_str()))
    }

    /// Issues carry a time and a base URL only; any other filter excludes them.
    pub fn accepts_issue(&self, issue: &IssueRow) -> bool {
        let host = url::Url::parse(&issue.base_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned));
        self.method.is_none()
            && self.status.is_empty()
            && self.mime.is_none()
            && self.tool.is_none()
            && self.comment.is_none()
            && self.highlight.is_none()
            && self
                .host
                .as_ref()
                .is_none_or(|h| host.as_deref().is_some_and(|x| x.eq_ignore_ascii_case(h)))
            && self.url.as_ref().is_none_or(|u| {
                issue
                    .base_url
                    .to_ascii_lowercase()
                    .contains(&u.to_ascii_lowercase())
            })
            && self.since.is_none_or(|s| issue.time_epoch_ms >= s)
            && self.until.is_none_or(|u| issue.time_epoch_ms <= u)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RowSource {
    Proxy,
    Archive,
}

/// One exchange, from Proxy history (bproj) or the Raijin archive.
#[derive(Debug, Clone, Serialize)]
pub struct Row {
    #[serde(rename = "ref")]
    pub reference: String,
    pub project: String,
    pub source: RowSource,
    pub tool: String,
    pub time_epoch_ms: u64,
    pub method: Option<String>,
    pub url: Option<String>,
    pub host: Option<String>,
    pub status: Option<u64>,
    pub mime: Option<String>,
    pub req_len: u64,
    pub resp_len: Option<u64>,
    pub comment: Option<String>,
    pub highlight: Option<String>,
    pub live: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct IssueRow {
    #[serde(rename = "ref")]
    pub reference: String,
    pub project: String,
    pub time_epoch_ms: u64,
    pub name: String,
    pub severity: Option<String>,
    pub confidence: Option<String>,
    pub base_url: String,
}

/// A per-file problem: reported, never fatal.
#[derive(Debug, Clone, Serialize)]
pub struct Warning {
    pub project: String,
    pub error: String,
}

/// `<project>:<entry_id>`, `<project>:a<seq>` (archive) or `<project>:i<seq>` (issue).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefKind {
    Proxy(u64),
    Archive(u64),
    Issue(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ref {
    pub project: String,
    pub kind: RefKind,
}

impl Ref {
    pub fn parse(text: &str) -> Result<Self> {
        let bad = || {
            Problem::BadRef(format!(
                "bad ref {text:?}: expected <project>:<id>, <project>:a<seq> or <project>:i<seq>, e.g. main:1"
            ))
        };
        let Some((project, id)) = text.rsplit_once(':') else {
            bail!(bad());
        };
        let number = |s: &str| s.parse::<u64>().map_err(|_| bad());
        let kind = if let Some(seq) = id.strip_prefix('a') {
            RefKind::Archive(number(seq)?)
        } else if let Some(seq) = id.strip_prefix('i') {
            RefKind::Issue(number(seq)?)
        } else {
            RefKind::Proxy(number(id)?)
        };
        Ok(Self {
            project: project.to_owned(),
            kind,
        })
    }
}

/// Header block and body of a raw HTTP message (split at the first blank line).
pub fn split_message(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return (&raw[..i + 4], &raw[i + 4..]);
    }
    if let Some(i) = raw.windows(2).position(|w| w == b"\n\n") {
        return (&raw[..i + 2], &raw[i + 2..]);
    }
    (raw, &[])
}

/// First value of header `name` (case-insensitive) in a raw message.
pub fn header_value(raw: &[u8], name: &str) -> Option<String> {
    let (head, _) = split_message(raw);
    String::from_utf8_lossy(head)
        .lines()
        .skip(1)
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refs_parse() {
        assert_eq!(
            Ref::parse("day1:12").expect("proxy").kind,
            RefKind::Proxy(12)
        );
        assert_eq!(
            Ref::parse("day1:a3").expect("archive").kind,
            RefKind::Archive(3)
        );
        assert_eq!(
            Ref::parse("day-1:i7").expect("issue"),
            Ref {
                project: "day-1".to_owned(),
                kind: RefKind::Issue(7)
            }
        );
        assert!(Ref::parse("day1").is_err());
        assert!(Ref::parse("day1:x").is_err());
    }

    #[test]
    fn headers_come_from_raw_bytes() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\nbody";
        assert_eq!(
            header_value(raw, "content-type").as_deref(),
            Some("text/html")
        );
        assert_eq!(split_message(raw).1, b"body");
    }
}
