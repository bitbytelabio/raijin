//! Which files a history call reads, and reading them: Proxy rows through bproj, archive rows and
//! issues from Raijin's JSONL files. Files are read in parallel, one thread per project.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::thread;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bproj::{HistoryEntry, Project};
use serde::Deserialize;

use super::{Filters, IssueRow, Problem, Row, RowSource, Selection, Warning, header_value};
use crate::burp::instance::{Instance, is_ours};
use crate::config::Target;

pub const EXCHANGES_FILE: &str = "exchanges.jsonl";
pub const ISSUES_FILE: &str = "issues.jsonl";

/// One project's files.
#[derive(Debug, Clone)]
pub struct Source {
    pub project: String,
    pub burp: Option<PathBuf>,
    pub archive: Option<PathBuf>,
    /// A CLI-managed Burp has this project open right now.
    pub live: bool,
}

/// The sources `selection` names: every `<projects_dir>/*.burp` and archive, plus
/// `history.include` globs; or only the `file` globs when given.
pub fn discover(target: &Target, selection: &Selection) -> Result<Vec<Source>> {
    let mut by_name: BTreeMap<String, Source> = BTreeMap::new();
    let add_files = |paths: Vec<PathBuf>, by_name: &mut BTreeMap<String, Source>| {
        for path in paths {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("burp")
                .to_owned();
            let mut name = stem.clone();
            let mut n = 2;
            while by_name.contains_key(&name) {
                name = format!("{stem}-{n}");
                n += 1;
            }
            by_name.insert(
                name.clone(),
                Source {
                    project: name,
                    burp: Some(path),
                    archive: None,
                    live: false,
                },
            );
        }
    };

    if selection.file.is_empty() {
        let projects_dir = target.projects_dir();
        let mut own: Vec<PathBuf> = std::fs::read_dir(&projects_dir).map_or_default(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e == "burp"))
                .collect()
        });
        own.sort();
        add_files(own, &mut by_name);
        if let Ok(rd) = std::fs::read_dir(target.state_dir().join("archive")) {
            for entry in rd.flatten() {
                if let Some(name) = entry.file_name().to_str()
                    && entry.path().is_dir()
                {
                    by_name.entry(name.to_owned()).or_insert_with(|| Source {
                        project: name.to_owned(),
                        burp: None,
                        archive: None,
                        live: false,
                    });
                }
            }
        }
        for source in by_name.values_mut() {
            let dir = target.archive_dir(&source.project);
            if dir.is_dir() {
                source.archive = Some(dir);
            }
        }
        add_files(
            glob_files(target, &target.config.history.include)?,
            &mut by_name,
        );
    } else {
        add_files(glob_files(target, &selection.file)?, &mut by_name);
    }

    if !selection.project.is_empty() {
        for wanted in &selection.project {
            if !by_name.contains_key(wanted) {
                bail!(Problem::UnknownProject {
                    wanted: wanted.clone(),
                    known: by_name.keys().cloned().collect(),
                });
            }
        }
        by_name.retain(|name, _| selection.project.contains(name));
    }
    for source in by_name.values_mut() {
        source.live = Instance::load(target, &source.project)
            .ok()
            .flatten()
            .is_some_and(|i| i.pid.is_some_and(|pid| is_ours(pid, &i)));
    }
    Ok(by_name.into_values().collect())
}

/// `.burp` files matching `patterns` (relative to the target root), sorted and deduplicated.
fn glob_files(target: &Target, patterns: &[String]) -> Result<Vec<PathBuf>> {
    let mut files = BTreeSet::new();
    for pattern in patterns {
        let full = target.resolve(Path::new(pattern));
        let full = full
            .to_str()
            .with_context(|| format!("non-UTF-8 glob {pattern}"))?;
        let matches = glob::glob(full).with_context(|| format!("bad glob {pattern}"))?;
        for path in matches.flatten() {
            if path.extension().is_some_and(|e| e == "burp") && path.is_file() {
                files.insert(path);
            }
        }
    }
    Ok(files.into_iter().collect())
}

/// The source named `project`.
pub fn find(target: &Target, project: &str) -> Result<Source> {
    discover(
        target,
        &Selection {
            project: vec![project.to_owned()],
            file: Vec::new(),
        },
    )?
    .into_iter()
    .next()
    .ok_or_else(|| {
        anyhow::Error::new(Problem::NotFound(format!(
            "no project {project:?}; history_list shows the refs"
        )))
    })
}

/// The end of the warning a live project's data gets.
pub const LIVE_INCOMPLETE: &str = "is running; data may be incomplete";

/// Runs `f` on every source in its own thread. A failure becomes a warning; a live project gets
/// a warning that its data may be incomplete.
pub fn par_map<T: Send>(
    sources: &[Source],
    f: impl Fn(&Source, &mut Vec<String>) -> Result<T> + Sync,
) -> (Vec<T>, Vec<Warning>) {
    // At most one reader per CPU at a time; a target can list many files.
    let width = thread::available_parallelism().map_or(4, NonZeroUsize::get);
    let mut results: Vec<(Result<T>, Vec<String>)> = Vec::with_capacity(sources.len());
    for chunk in sources.chunks(width) {
        thread::scope(|scope| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|s| {
                    scope.spawn(|| {
                        let mut notes = Vec::new();
                        let result = f(s, &mut notes);
                        (result, notes)
                    })
                })
                .collect();
            for handle in handles {
                results.push(handle.join().unwrap_or_else(|_| {
                    (Err(anyhow::anyhow!("reader thread panicked")), Vec::new())
                }));
            }
        });
    }
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    for (source, (result, notes)) in sources.iter().zip(results) {
        warnings.extend(notes.into_iter().map(|error| Warning {
            project: source.project.clone(),
            error,
        }));
        match result {
            Ok(value) => {
                if source.live {
                    warnings.push(Warning {
                        project: source.project.clone(),
                        error: format!("project {} {LIVE_INCOMPLETE}", source.project),
                    });
                }
                out.push(value);
            }
            Err(e) => warnings.push(Warning {
                project: source.project.clone(),
                error: if source.live {
                    format!(
                        "project {} is running and could not be read: {e:#}; use run {{\"do\":\"proxy_history\"}}",
                        source.project
                    )
                } else {
                    format!("{e:#}")
                },
            }),
        }
    }
    (out, warnings)
}

/// Which messages to load along with each row.
#[derive(Debug, Clone, Copy, Default)]
pub struct Load {
    pub request: bool,
    pub response: bool,
}

/// A row with the raw messages [`Load`] asked for.
#[derive(Debug, Clone)]
pub struct Exchange {
    pub row: Row,
    pub request: Option<Vec<u8>>,
    pub response: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kinds {
    pub proxy: bool,
    pub archive: bool,
}

impl Kinds {
    pub const ALL: Self = Self {
        proxy: true,
        archive: true,
    };
}

/// Every exchange of `source` that passes `filters`, Proxy rows first, then archive rows. Rows
/// bproj could not decode (a project damaged by a crash) are reported in `notes`.
pub fn for_each_exchange(
    source: &Source,
    filters: &Filters,
    kinds: Kinds,
    load: Load,
    notes: &mut Vec<String>,
    mut visit: impl FnMut(Exchange) -> Result<()>,
) -> Result<()> {
    if kinds.proxy
        && let Some(burp) = &source.burp
    {
        let project = Project::open(burp).with_context(|| format!("reading {}", burp.display()))?;
        let summary = project.for_each(&filters.bproj()?, |entry| {
            let request = if load.request {
                Some(message_bytes(&project, &entry.request)?)
            } else {
                None
            };
            let response = match (&entry.response, load.response) {
                (Some(m), true) => Some(message_bytes(&project, m)?),
                _ => None,
            };
            visit(Exchange {
                row: proxy_row(source, &entry),
                request,
                response,
            })
            .map_err(|e| bproj::Error::Malformed(format!("{e:#}")))
        })?;
        if !summary.complete {
            notes.push(format!(
                "some Proxy rows of {} could not be fully decoded ({} rows in the file); results may miss entries",
                burp.display(),
                summary.total
            ));
        }
    }
    if kinds.archive
        && let Some(dir) = &source.archive
    {
        for_each_archive_line(&dir.join(EXCHANGES_FILE), |line: ArchiveLine| {
            let request = STANDARD
                .decode(&line.request_b64)
                .context("archive request_b64")?;
            let response = line
                .response_b64
                .as_deref()
                .map(|b| STANDARD.decode(b))
                .transpose()
                .context("archive response_b64")?;
            let row = archive_row(source, &line, &request, response.as_deref());
            if !filters.accepts_archive(&row) {
                return Ok(());
            }
            visit(Exchange {
                row,
                request: load.request.then_some(request),
                response: if load.response { response } else { None },
            })
        })?;
    }
    Ok(())
}

pub fn message_bytes(
    project: &Project,
    message: &bproj::model::history::Message,
) -> bproj::Result<Vec<u8>> {
    project
        .source()
        .bytes(message.payload_offset, message.length)
}

fn proxy_row(source: &Source, entry: &HistoryEntry) -> Row {
    Row {
        reference: format!("{}:{}", source.project, entry.entry_id),
        project: source.project.clone(),
        source: RowSource::Proxy,
        tool: entry.tool_source.clone(),
        time_epoch_ms: entry.time_epoch_ms.unsigned,
        method: entry.request.method.clone(),
        url: entry.request.url.clone(),
        host: entry.service.as_ref().map(|s| s.host.text.value.clone()),
        status: entry.response.as_ref().map(|_| entry.status_code.unsigned),
        mime: entry
            .response
            .as_ref()
            .and_then(|m| m.content_type())
            .map(str::to_owned),
        req_len: entry.request.length,
        resp_len: entry.response.as_ref().map(|m| m.length),
        comment: Some(entry.comment.value.clone()).filter(|c| !c.is_empty()),
        highlight: entry.highlight.value.clone(),
        live: source.live,
    }
}

/// One line of `exchanges.jsonl` (written by Raijin's `ExchangeArchive`).
#[derive(Debug, Clone, Deserialize)]
pub struct ArchiveLine {
    pub seq: u64,
    pub time_epoch_ms: u64,
    pub tool: String,
    pub method: String,
    pub url: String,
    pub status: Option<u64>,
    pub request_b64: String,
    pub response_b64: Option<String>,
    #[serde(default)]
    pub request_truncated: bool,
    #[serde(default)]
    pub response_truncated: bool,
    #[serde(default)]
    pub response_reconstructed: bool,
}

pub fn archive_row(
    source: &Source,
    line: &ArchiveLine,
    request: &[u8],
    response: Option<&[u8]>,
) -> Row {
    Row {
        reference: format!("{}:a{}", source.project, line.seq),
        project: source.project.clone(),
        source: RowSource::Archive,
        tool: line.tool.clone(),
        time_epoch_ms: line.time_epoch_ms,
        method: Some(line.method.clone()),
        url: Some(line.url.clone()),
        host: url::Url::parse(&line.url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.trim_matches(['[', ']']).to_owned())),
        status: line.status,
        mime: response.and_then(|r| header_value(r, "content-type")),
        req_len: request.len() as u64,
        resp_len: response.map(|r| r.len() as u64),
        comment: None,
        highlight: None,
        live: source.live,
    }
}

/// One line of `issues.jsonl`.
#[derive(Debug, Clone, Deserialize)]
pub struct IssueLine {
    pub seq: u64,
    pub time_epoch_ms: u64,
    pub name: String,
    pub severity: Option<String>,
    pub confidence: Option<String>,
    pub base_url: String,
    pub detail: Option<String>,
    pub remediation: Option<String>,
    /// The issue type's description (Burp's issue definition), absent in lines older Raijin versions wrote.
    #[serde(default)]
    pub background: Option<String>,
    /// The issue type's generic remediation (Burp's issue definition).
    #[serde(default)]
    pub remediation_background: Option<String>,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Evidence {
    pub request_b64: String,
    pub response_b64: Option<String>,
}

impl IssueLine {
    pub fn row(&self, project: &str) -> IssueRow {
        IssueRow {
            reference: format!("{project}:i{}", self.seq),
            project: project.to_owned(),
            time_epoch_ms: self.time_epoch_ms,
            name: self.name.clone(),
            severity: self.severity.clone(),
            confidence: self.confidence.clone(),
            base_url: self.base_url.clone(),
        }
    }
}

pub fn for_each_issue(
    source: &Source,
    mut visit: impl FnMut(IssueLine) -> Result<()>,
) -> Result<()> {
    if let Some(dir) = &source.archive {
        for_each_archive_line(&dir.join(ISSUES_FILE), &mut visit)?;
    }
    Ok(())
}

/// Parses each non-blank line of a JSONL file; a missing file has no lines. A malformed line
/// (a crash mid-write) is skipped.
fn for_each_archive_line<T: for<'de> Deserialize<'de>>(
    path: &Path,
    mut visit: impl FnMut(T) -> Result<()>,
) -> Result<()> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<T>(&line) {
            visit(value)?;
        }
    }
    Ok(())
}

/// The archive line with `seq`.
pub fn archive_line(source: &Source, seq: u64) -> Result<ArchiveLine> {
    let dir = source.archive.as_ref().ok_or_else(|| {
        Problem::NotFound(format!(
            "project {} has no archive, so no {}:a{seq}",
            source.project, source.project
        ))
    })?;
    let mut found = None;
    for_each_archive_line(&dir.join(EXCHANGES_FILE), |line: ArchiveLine| {
        if line.seq == seq {
            found = Some(line);
        }
        Ok(())
    })?;
    Ok(found.ok_or_else(|| {
        Problem::NotFound(format!(
            "no archive entry {}:a{seq}; history_list shows the refs",
            source.project
        ))
    })?)
}

pub fn issue_line(source: &Source, seq: u64) -> Result<IssueLine> {
    let mut found = None;
    for_each_issue(source, |line| {
        if line.seq == seq {
            found = Some(line);
        }
        Ok(())
    })?;
    Ok(found.ok_or_else(|| {
        Problem::NotFound(format!(
            "no issue {}:i{seq}; history_list with source issues shows the refs",
            source.project
        ))
    })?)
}

/// The Proxy entry `entry_id` with its raw messages.
pub fn proxy_entry(source: &Source, entry_id: u64) -> Result<(Row, Vec<u8>, Option<Vec<u8>>)> {
    let burp = source
        .burp
        .as_ref()
        .with_context(|| format!("project {} has no .burp file", source.project))?;
    let project = Project::open(burp).with_context(|| format!("reading {}", burp.display()))?;
    // Project::entry reports a missing id as a malformed project; look it up here instead.
    let filter = bproj::HistoryFilter {
        entry_id: Some(entry_id),
        ..bproj::HistoryFilter::default()
    };
    let mut found = None;
    project.for_each(&filter, |entry| {
        found = Some(entry);
        Ok(())
    })?;
    let entry = found.ok_or_else(|| {
        Problem::NotFound(format!(
            "no proxy entry {}:{entry_id} in {}; history_list shows the refs",
            source.project,
            burp.display()
        ))
    })?;
    let request = message_bytes(&project, &entry.request)?;
    let response = entry
        .response
        .as_ref()
        .map(|m| message_bytes(&project, m))
        .transpose()?;
    Ok((proxy_row(source, &entry), request, response))
}
