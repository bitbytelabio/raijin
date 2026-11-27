//! `~/.raijin/data/<source>/`: the files Raijin reads from `PortSwigger`'s repos, with a
//! `manifest.json` (commit, fetch time). The repos are shallow bare clones in
//! `~/.raijin/data/.repos/`, fetched with gix. Downloaded only on the user's machine.

use std::fs;
use std::num::NonZeroU32;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result, bail};
use gix::remote::fetch::Shallow;
use serde::{Deserialize, Serialize};

use super::parse::{parse_bambda, parse_bcheck, parse_url, parse_xss};
use super::{Library, Source, Warning};
use crate::util::{now_ms, private_dir};

/// One `PortSwigger` repo and the files of it Raijin keeps.
pub struct Upstream {
    pub source: Source,
    pub repo: &'static str,
    pub branch: &'static str,
    pub license: &'static str,
    /// Whether to keep a file, by its path inside the repo (`/` separators).
    keep: fn(&str) -> bool,
}

const NO_LICENSE: &str = "© PortSwigger, no license: local use only, never republish";

fn is_license(rel: &str) -> bool {
    !rel.contains('/') && rel.starts_with("LICENSE")
}

/// `<dir>/<name>.<ext>` directly in `dir`.
fn top_level(rel: &str, dir: &str, ext: &str) -> bool {
    rel.strip_prefix(dir)
        .and_then(|r| r.strip_prefix('/'))
        .is_some_and(|name| !name.contains('/') && name.ends_with(ext))
}

pub static UPSTREAM: [Upstream; 4] = [
    Upstream {
        source: Source::Xss,
        repo: "PortSwigger/xss-cheatsheet-data",
        branch: "master",
        license: NO_LICENSE,
        keep: |rel| top_level(rel, "json", ".json") || is_license(rel),
    },
    Upstream {
        source: Source::Url,
        repo: "PortSwigger/url-cheatsheet-data",
        branch: "main",
        license: NO_LICENSE,
        keep: |rel| top_level(rel, "src", ".json") || is_license(rel),
    },
    Upstream {
        source: Source::Bchecks,
        repo: "PortSwigger/BChecks",
        branch: "main",
        license: "LGPL-3.0",
        keep: |rel| {
            (rel.ends_with(".bcheck")
                && !rel.split('/').any(|c| c.eq_ignore_ascii_case("archived")))
                || is_license(rel)
        },
    },
    Upstream {
        source: Source::Bambdas,
        repo: "PortSwigger/bambdas",
        branch: "main",
        license: "LGPL-3.0",
        keep: |rel| rel.ends_with(".bambda") || is_license(rel),
    },
];

/// The upstream repo of `source`; None for `custom`.
pub fn upstream(source: Source) -> Option<&'static Upstream> {
    UPSTREAM.iter().find(|u| u.source == source)
}

const MANIFEST: &str = "manifest.json";
/// `root/.repos/<source>.git`: bare, shallow (depth 1) clones that later updates fetch into.
const REPOS: &str = ".repos";
/// Kept files bigger than this are skipped.
const MAX_FILE: usize = 4 << 20;
/// Kept files of one source, and their total size, beyond which it is refused.
const MAX_FILES: usize = 20_000;
const MAX_TOTAL: usize = 256 << 20;
/// gix network settings: give up on a connection after 15 s, and on a transfer slower than
/// 1 KiB/s for 30 s.
const GIT_CONFIG: [&str; 3] = [
    "gitoxide.http.connectTimeout=15000",
    "http.lowSpeedLimit=1024",
    "http.lowSpeedTime=30",
];
/// Sources older than this refresh on the first data call of a session.
pub const STALE_MS: u64 = 7 * 24 * 3600 * 1000;
/// Set (non-empty) to turn the automatic download and refresh off; `data_update` still works.
pub const AUTO_UPDATE_ENV: &str = "RAIJIN_NO_DATA_UPDATE";

/// Whether the gateway may download and refresh sources on its own.
pub fn auto_update() -> bool {
    std::env::var_os(AUTO_UPDATE_ENV).is_none_or(|v| v.is_empty())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub source: Source,
    pub repo: String,
    pub branch: String,
    pub commit: Option<String>,
    pub fetched_at_ms: u64,
    pub files: usize,
}

/// The first 12 characters of a commit SHA, or `unknown commit`.
pub fn short_commit(commit: Option<&str>) -> &str {
    commit.map_or("unknown commit", |c| crate::util::truncate_utf8(c, 12))
}

pub fn manifest(root: &Path, source: Source) -> Option<Manifest> {
    let text = fs::read_to_string(root.join(source.as_str()).join(MANIFEST)).ok()?;
    serde_json::from_str(&text).ok()
}

/// Removes a folder on every exit path (it is gone already once renamed into place).
struct Staging(PathBuf);

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Whether a repo path is relative and made of plain names only (no `..`, no root).
fn plain_path(rel: &str) -> bool {
    !rel.is_empty()
        && Path::new(rel)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

/// One file to install: its path inside the repo (`/` separators) and its contents.
pub struct RepoFile {
    pub path: String,
    pub data: Vec<u8>,
}

/// Writes the `files` that `up` keeps into `root/<source>/` with a manifest, replacing what was
/// there. Paths that are not [`plain_path`]s and files over [`MAX_FILE`] are skipped.
pub fn install_files(
    root: &Path,
    up: &Upstream,
    commit: Option<String>,
    files: impl IntoIterator<Item = RepoFile>,
    now: u64,
) -> Result<Manifest> {
    private_dir(root)?;
    let name = up.source.as_str();
    let pid = std::process::id();
    let tmp_path = root.join(format!(".{name}.tmp-{pid}-{now}"));
    fs::create_dir(&tmp_path).with_context(|| format!("creating {}", tmp_path.display()))?;
    // Only a folder this call created is removed on failure.
    let tmp = Staging(tmp_path);
    let mut count = 0;
    let mut total = 0;
    for file in files {
        if file.data.len() > MAX_FILE || !plain_path(&file.path) || !(up.keep)(&file.path) {
            continue;
        }
        total += file.data.len();
        if count >= MAX_FILES || total > MAX_TOTAL {
            bail!(
                "{name} holds over {MAX_FILES} files or {} MiB to keep",
                MAX_TOTAL >> 20
            );
        }
        let dest = tmp.0.join(&file.path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&dest, &file.data).with_context(|| format!("writing {}", dest.display()))?;
        count += 1;
    }
    let manifest = Manifest {
        source: up.source,
        repo: up.repo.to_owned(),
        branch: up.branch.to_owned(),
        commit,
        fetched_at_ms: now,
        files: count,
    };
    fs::write(tmp.0.join(MANIFEST), serde_json::to_vec_pretty(&manifest)?)?;

    let dest = root.join(name);
    let old = Staging(root.join(format!(".{name}.old-{pid}-{now}")));
    match fs::rename(&dest, &old.0) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("moving {} aside", dest.display())),
    }
    if fs::rename(&tmp.0, &dest).is_err() {
        let _ = fs::rename(&old.0, &dest);
        bail!("another update of {name} is running; retry");
    }
    Ok(manifest)
}

/// The shallow fetch every clone and update makes: the branch tip only.
fn tip_only() -> Shallow {
    Shallow::DepthAtRemote(NonZeroU32::MIN)
}

/// `up`'s bare clone under `root/.repos/`, brought to the remote branch tip: fetched into when it
/// exists, cloned (again) otherwise. Pure Rust (gix); no `git` binary or user git config is used.
fn sync_repo(root: &Path, up: &Upstream) -> Result<gix::Repository> {
    let dir = root.join(REPOS).join(format!("{}.git", up.source.as_str()));
    let url = format!("https://github.com/{}.git", up.repo);
    let interrupt = AtomicBool::new(false);
    if dir.is_dir()
        && let Ok(repo) = fetch_into(&dir, &url, up.branch, &interrupt)
    {
        return Ok(repo);
    }
    // No clone yet, or one that cannot fetch: clone beside it and swap only once that worked, so
    // an offline update keeps the clone it had.
    private_dir(&root.join(REPOS))?;
    let fresh = Staging(dir.with_extension(format!("git.tmp-{}", std::process::id())));
    let _ = fs::remove_dir_all(&fresh.0);
    let open = gix::open::Options::isolated().config_overrides(GIT_CONFIG);
    gix::clone::PrepareFetch::new(
        url.as_str(),
        &fresh.0,
        gix::create::Kind::Bare,
        gix::create::Options::default(),
        open,
    )
    .with_context(|| format!("cloning {url}"))?
    .with_shallow(tip_only())
    .fetch_only(gix::progress::Discard, &interrupt)
    .with_context(|| format!("cloning {url}"))?;
    if dir.exists() {
        fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    fs::rename(&fresh.0, &dir).with_context(|| format!("moving the clone to {}", dir.display()))?;
    Ok(gix::open_opts(
        &dir,
        gix::open::Options::isolated().config_overrides(GIT_CONFIG),
    )?)
}

/// Fetches `branch` of `url` into the bare clone at `dir`, depth 1.
fn fetch_into(
    dir: &Path,
    url: &str,
    branch: &str,
    interrupt: &AtomicBool,
) -> Result<gix::Repository> {
    let repo = gix::open_opts(
        dir,
        gix::open::Options::isolated().config_overrides(GIT_CONFIG),
    )?;
    let spec = format!("+refs/heads/{branch}:refs/heads/{branch}");
    repo.remote_at(url)?
        .with_refspecs([spec.as_str()], gix::remote::Direction::Fetch)?
        .connect(gix::remote::Direction::Fetch)
        .with_context(|| format!("fetching {url}"))?
        .prepare_fetch(
            gix::progress::Discard,
            gix::remote::ref_map::Options::default(),
        )?
        .with_shallow(tip_only())
        .receive(gix::progress::Discard, interrupt)
        .with_context(|| format!("fetching {url}"))?;
    Ok(repo)
}

/// The commit `branch` points at in `repo`, and the blobs of its tree that `up` keeps.
fn tip_files(repo: &gix::Repository, up: &Upstream) -> Result<(String, Vec<RepoFile>)> {
    let name = format!("refs/heads/{}", up.branch);
    let commit = repo
        .find_reference(name.as_str())
        .with_context(|| format!("{} has no branch {}", up.repo, up.branch))?
        .peel_to_commit()?;
    let mut files = Vec::new();
    for entry in commit.tree()?.traverse().breadthfirst.files()? {
        if !entry.mode.is_blob() {
            continue;
        }
        let Ok(path) = std::str::from_utf8(&entry.filepath) else {
            continue;
        };
        if !plain_path(path) || !(up.keep)(path) {
            continue;
        }
        let data = repo.find_object(entry.oid)?.detach().data;
        files.push(RepoFile {
            path: path.to_owned(),
            data,
        });
    }
    Ok((commit.id.to_string(), files))
}

/// Brings `up`'s clone to the branch tip and installs the files it keeps.
pub async fn fetch(root: &Path, up: &'static Upstream) -> Result<Manifest> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let repo = sync_repo(&root, up)?;
        let (commit, files) = tip_files(&repo, up)?;
        install_files(&root, up, Some(commit), files, now_ms())
    })
    .await
    .context("update task panicked")?
}

/// Sources never downloaded or older than [`STALE_MS`], with their manifest when there is one.
pub fn due(root: &Path, now: u64) -> Vec<(&'static Upstream, Option<Manifest>)> {
    UPSTREAM
        .iter()
        .filter_map(|up| {
            let m = manifest(root, up.source);
            let fresh = m
                .as_ref()
                .is_some_and(|m| now.saturating_sub(m.fetched_at_ms) < STALE_MS);
            (!fresh).then_some((up, m))
        })
        .collect()
}

/// Each downloaded source's fetch time: the upstream library is reloaded when this changes.
pub fn stamp(root: &Path) -> Vec<(Source, u64)> {
    UPSTREAM
        .iter()
        .filter_map(|up| manifest(root, up.source).map(|m| (up.source, m.fetched_at_ms)))
        .collect()
}

/// Files under `dir` (recursively) ending in `ext`, as (path relative to `dir`, absolute path),
/// sorted by relative path. A missing folder gives none.
pub fn files(dir: &Path, ext: &str) -> Vec<(String, PathBuf)> {
    fn walk(dir: &Path, base: &Path, ext: &str, out: &mut Vec<(String, PathBuf)>) {
        let Ok(read) = fs::read_dir(dir) else {
            return;
        };
        for entry in read.flatten() {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                walk(&path, base, ext, out);
            } else if kind.is_file()
                && path.to_string_lossy().ends_with(ext)
                && let Some(rel) = path.strip_prefix(base).ok().and_then(Path::to_str)
            {
                out.push((rel.replace('\\', "/"), path.clone()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, ext, &mut out);
    out.sort();
    out
}

/// Every downloaded source, parsed: xss, url, bchecks, bambdas in that order.
pub fn load_upstream(root: &Path) -> Library {
    let mut lib = Library::default();
    for up in &UPSTREAM {
        if manifest(root, up.source).is_none() {
            continue;
        }
        let dir = root.join(up.source.as_str());
        let ext = match up.source {
            Source::Bchecks => ".bcheck",
            Source::Bambdas => ".bambda",
            _ => ".json",
        };
        for (rel, path) in files(&dir, ext) {
            if rel == MANIFEST {
                continue;
            }
            let shown = format!("{}/{rel}", up.source.as_str());
            let text = match fs::read_to_string(&path) {
                Ok(t) => t,
                Err(e) => {
                    lib.warnings.push(Warning {
                        file: shown,
                        error: e.to_string(),
                    });
                    continue;
                }
            };
            let parsed = match up.source {
                Source::Xss => parse_xss(&rel, &text),
                Source::Url => parse_url(&rel, &text),
                Source::Bchecks => Ok(vec![parse_bcheck(up.source, &rel, &text)]),
                _ => Ok(vec![parse_bambda(up.source, &rel, &text)]),
            };
            match parsed {
                Ok(entries) => lib.entries.extend(entries.into_iter().map(|mut e| {
                    e.file.clone_from(&path);
                    e
                })),
                Err(e) => lib.warnings.push(Warning {
                    file: shown,
                    error: format!("{e:#}"),
                }),
            }
        }
    }
    lib.dedupe_ids();
    lib
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> Vec<RepoFile> {
        [
            ("json/a.json", "[]"),
            ("README.md", "readme"),
            ("../evil.json", "[]"),
            ("json/../../evil2.json", "[]"),
            ("/abs.json", "[]"),
        ]
        .into_iter()
        .map(|(path, body)| RepoFile {
            path: path.to_owned(),
            data: body.as_bytes().to_vec(),
        })
        .collect()
    }

    #[test]
    fn install_keeps_only_wanted_files_and_replaces_the_folder() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("data");
        let sha = "0b1e337e0b1e337e0b1e337e0b1e337e0b1e337e";
        let up = upstream(Source::Xss).expect("xss");
        let m = install_files(&root, up, Some(sha.to_owned()), tree(), 1).expect("install");
        assert_eq!(m.commit.as_deref(), Some(sha));
        assert_eq!(m.files, 1);
        let mut found: Vec<String> = files(&root.join("xss"), "")
            .into_iter()
            .map(|(r, _)| r)
            .collect();
        found.sort();
        assert_eq!(found, ["json/a.json", "manifest.json"]);
        assert!(!dir.path().join("evil.json").exists());
        assert!(!root.join("evil.json").exists());

        fs::write(root.join("xss/json/stale.json"), "[]").expect("stale");
        let again = install_files(&root, up, None, tree(), 2).expect("again");
        assert_eq!(again.commit, None);
        assert!(!root.join("xss/json/stale.json").exists());
        assert_eq!(
            manifest(&root, Source::Xss)
                .expect("manifest")
                .fetched_at_ms,
            2
        );
        let leftovers: Vec<_> = fs::read_dir(&root)
            .expect("root")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(leftovers, ["xss"]);
    }

    #[test]
    fn due_lists_missing_and_stale_sources() {
        let dir = tempfile::tempdir().expect("temp dir");
        let up = upstream(Source::Xss).expect("xss");
        install_files(dir.path(), up, None, tree(), 1000).expect("install");
        let due_now: Vec<Source> = due(dir.path(), 2000)
            .iter()
            .map(|(u, _)| u.source)
            .collect();
        assert_eq!(due_now, [Source::Url, Source::Bchecks, Source::Bambdas]);
        assert_eq!(due(dir.path(), 1000 + STALE_MS).len(), 4);
    }
}
