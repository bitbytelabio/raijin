//! This target's own data (`[data] dir`, tracked by git): `payloads/<category>.json` arrays,
//! `bchecks/**/*.bcheck` and `bambdas/**/*.bambda`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::parse::{json, parse_bambda, parse_bcheck};
use super::store::files;
use super::tools::AddArgs;
use super::{Entry, Kind, Library, Source, Warning, id_hash};
use crate::mcp::error::{Code, ToolError};

/// One item of `payloads/<category>.json`; other keys are ignored.
#[derive(Debug, Deserialize)]
struct CustomPayload {
    payload: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    context: Option<String>,
}

fn payload_entry(category: &str, file: &Path, p: CustomPayload) -> Entry {
    let title = p
        .description
        .clone()
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| category.to_owned());
    let mut e = Entry::new(
        format!("custom:{category}/{}", id_hash(&p.payload)),
        Source::Custom,
        Kind::Payload,
        category.to_owned(),
        title,
        p.payload,
        file.to_path_buf(),
    );
    e.description = p.description;
    e.tags = p.tags;
    e.context = p.context;
    e
}

/// Everything under `dir`; a missing folder gives an empty library, a malformed file a warning.
pub fn load_custom(dir: &Path) -> Library {
    let mut lib = Library::default();
    let payloads = dir.join("payloads");
    for (rel, path) in files(&payloads, ".json") {
        if rel.contains('/') {
            continue;
        }
        let category = rel.trim_end_matches(".json").to_owned();
        let read = fs::read_to_string(&path)
            .map_err(anyhow::Error::from)
            .and_then(|t| json(&t))
            .and_then(|v| Ok(serde_json::from_value::<Vec<CustomPayload>>(v)?));
        match read {
            Ok(items) => lib.entries.extend(
                items
                    .into_iter()
                    .map(|p| payload_entry(&category, &path, p)),
            ),
            Err(e) => lib_warn(
                &mut lib.warnings,
                format!("payloads/{rel}"),
                format!("{e:#}"),
            ),
        }
    }
    for (sub, ext, kind) in [
        ("bchecks", ".bcheck", Kind::Bcheck),
        ("bambdas", ".bambda", Kind::Bambda),
    ] {
        for (rel, path) in files(&dir.join(sub), ext) {
            match fs::read_to_string(&path) {
                Ok(text) => {
                    let mut e = if kind == Kind::Bcheck {
                        parse_bcheck(Source::Custom, &rel, &text)
                    } else {
                        parse_bambda(Source::Custom, &rel, &text)
                    };
                    e.file = path;
                    lib.entries.push(e);
                }
                Err(e) => lib_warn(&mut lib.warnings, format!("{sub}/{rel}"), e.to_string()),
            }
        }
    }
    lib.dedupe_ids();
    lib
}

fn lib_warn(warnings: &mut Vec<Warning>, file: String, error: String) {
    warnings.push(Warning { file, error });
}

fn invalid(message: impl Into<String>) -> ToolError {
    ToolError::new(Code::InvalidArguments, message)
}

fn failed(e: impl std::fmt::Display) -> ToolError {
    ToolError::new(Code::ToolFailed, e.to_string())
}

/// A file or folder name: `^[A-Za-z0-9_-]+$`.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `value` as a file or folder name: lowercase, so the id names the file on a case-insensitive
/// filesystem too (noted when that changed it).
fn checked_name(
    param: &str,
    value: Option<&str>,
    notes: &mut Vec<String>,
) -> Result<Option<String>, ToolError> {
    match value {
        None => Ok(None),
        Some(v) if valid_name(v) => {
            let lower = v.to_ascii_lowercase();
            if lower != v {
                notes.push(format!("lowercased '{param}' \"{v}\" to \"{lower}\""));
            }
            Ok(Some(lower))
        }
        Some(v) => Err(invalid(format!(
            "invalid {param} {v:?}: use letters, digits, '_' and '-'"
        ))
        .param(param)
        .got(json!(v))),
    }
}

/// What [`write_atomic`] does when `path` exists.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Existing {
    Replace,
    Keep,
}

/// Writes `bytes` to `path` through a temp file of its own in the same folder, creating the folder.
/// With [`Existing::Keep`] the file is linked into place, which fails when `path` exists.
fn write_atomic(path: &Path, bytes: &[u8], existing: Existing) -> Result<(), ToolError> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let parent = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|e| failed(format!("creating {}: {e}", parent.display())))?;
    let name = path.file_name().map_or_default(|n| n.to_string_lossy());
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = parent.join(format!(".{name}.tmp-{}-{seq}", std::process::id()));
    let placed = fs::write(&tmp, bytes).and_then(|()| match existing {
        Existing::Replace => fs::rename(&tmp, path),
        Existing::Keep => fs::hard_link(&tmp, path).and_then(|()| fs::remove_file(&tmp)),
    });
    placed.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            exists_error(path)
        } else {
            failed(format!("writing {}: {e}", path.display()))
        }
    })
}

fn exists_error(path: &Path) -> ToolError {
    invalid(format!(
        "{} exists; pass \"overwrite\":true to replace it",
        shown(path)
    ))
    .param("overwrite")
}

fn shown(path: &Path) -> String {
    path.display().to_string()
}

/// Saves a payload, `BCheck` or Bambda under `dir` (see [`AddArgs`]). Calls run one at a time, so
/// two payloads saved at once to one category both land. Notes say how the arguments were read.
pub fn add(dir: &Path, args: &AddArgs) -> Result<(Value, Vec<String>), ToolError> {
    static LOCK: Mutex<()> = Mutex::new(());
    let _held = LOCK.lock().map_err(|_| {
        ToolError::new(
            Code::Internal,
            "an earlier data_add failed mid-write; restart raijin mcp",
        )
    })?;
    let mut notes = Vec::new();
    let given = |v: Option<&str>| v.is_some_and(|s| !s.trim().is_empty());
    let value = match args.kind.unwrap_or(Kind::Payload) {
        Kind::Payload => {
            if given(args.script.as_deref()) {
                notes.push("ignored 'script': a payload entry stores only 'payload'".to_owned());
            }
            add_payload(dir, args, &mut notes)
        }
        kind => {
            if given(args.payload.as_deref()) {
                notes.push(format!(
                    "ignored 'payload': a {} entry stores only 'script'",
                    if kind == Kind::Bcheck {
                        "bcheck"
                    } else {
                        "bambda"
                    }
                ));
            }
            add_script(dir, kind, args, &mut notes)
        }
    }?;
    Ok((value, notes))
}

/// `tags` with comma-separated items split into one tag each (noted), trimmed, empty ones dropped.
fn split_tags(tags: &[String], notes: &mut Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for t in tags {
        let parts: Vec<String> = t
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect();
        if t.contains(',') {
            notes.push(format!("split 'tags' {t:?} into {} tags", parts.len()));
        }
        out.extend(parts);
    }
    out
}

fn add_payload(dir: &Path, args: &AddArgs, notes: &mut Vec<String>) -> Result<Value, ToolError> {
    let payload = args
        .payload
        .as_deref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| invalid("data_add needs a non-empty 'payload'").param("payload"))?;
    let category = checked_name("category", args.category.as_deref(), notes)?
        .ok_or_else(|| invalid("data_add needs 'category' for a payload").param("category"))?;
    let file = dir.join("payloads").join(format!("{category}.json"));
    let id = format!("custom:{category}/{}", id_hash(payload));
    let mut items: Vec<Value> = match fs::read_to_string(&file) {
        Ok(text) => match json(&text) {
            Ok(Value::Array(items)) => items,
            Ok(_) => return Err(failed(format!("{} is not a JSON array", shown(&file)))),
            Err(e) => return Err(failed(format!("reading {}: {e:#}", shown(&file)))),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(failed(format!("reading {}: {e}", shown(&file)))),
    };
    if items
        .iter()
        .any(|i| i.get("payload").and_then(Value::as_str) == Some(payload))
    {
        return Ok(json!({
            "added": false,
            "id": id,
            "file": shown(&file),
            "reason": format!("already in {category}"),
        }));
    }
    let mut item = Map::new();
    item.insert("payload".to_owned(), json!(payload));
    if let Some(d) = args.description.as_deref().filter(|d| !d.is_empty()) {
        item.insert("description".to_owned(), json!(d));
    }
    let tags = split_tags(args.tags.as_deref().unwrap_or_default(), notes);
    if !tags.is_empty() {
        item.insert("tags".to_owned(), json!(tags));
    }
    if let Some(c) = args.context.as_deref().filter(|c| !c.is_empty()) {
        item.insert("context".to_owned(), json!(c));
    }
    items.push(Value::Object(item));
    let mut text = serde_json::to_string_pretty(&items).map_err(failed)?;
    text.push('\n');
    write_atomic(&file, text.as_bytes(), Existing::Replace)?;
    Ok(json!({"added": true, "id": id, "file": shown(&file)}))
}

fn add_script(
    dir: &Path,
    kind: Kind,
    args: &AddArgs,
    notes: &mut Vec<String>,
) -> Result<Value, ToolError> {
    let (sub, ext) = if kind == Kind::Bcheck {
        ("bchecks", "bcheck")
    } else {
        ("bambdas", "bambda")
    };
    let name = checked_name("name", args.name.as_deref(), notes)?
        .ok_or_else(|| invalid(format!("data_add needs 'name' for a {ext}")).param("name"))?;
    let category = checked_name("category", args.category.as_deref(), notes)?;
    let script = args
        .script
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            invalid(format!("data_add needs a non-empty 'script' for a {ext}")).param("script")
        })?;
    if kind == Kind::Bcheck && !script.lines().any(|l| l.trim() == "metadata:") {
        return Err(invalid("a BCheck starts with a metadata: block").param("script"));
    }
    let rel = match &category {
        Some(c) => format!("{c}/{name}"),
        None => name,
    };
    let file: PathBuf = dir.join(sub).join(format!("{rel}.{ext}"));
    let existing = if args.overwrite == Some(true) {
        Existing::Replace
    } else {
        Existing::Keep
    };
    write_atomic(&file, script.as_bytes(), existing)?;
    Ok(json!({"added": true, "id": format!("custom:{sub}/{rel}"), "file": shown(&file)}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: Value) -> AddArgs {
        serde_json::from_value(v).expect("args")
    }

    /// [`super::add`] without its notes.
    fn add(dir: &Path, args: &AddArgs) -> Result<Value, ToolError> {
        super::add(dir, args).map(|(value, _)| value)
    }

    #[test]
    fn names_are_lowercased_and_tags_split_so_the_id_finds_the_entry() {
        let dir = tempfile::tempdir().expect("temp dir");
        let (saved, notes) = super::add(
            dir.path(),
            &args(json!({
                "category": "WAF-Bypass",
                "payload": "<x>",
                "tags": ["svg,onload"],
                "script": "ignored"
            })),
        )
        .expect("add");
        assert_eq!(
            notes,
            [
                "ignored 'script': a payload entry stores only 'payload'",
                "lowercased 'category' \"WAF-Bypass\" to \"waf-bypass\"",
                "split 'tags' \"svg,onload\" into 2 tags",
            ]
        );
        let id = saved["id"].as_str().expect("id");
        assert!(id.starts_with("custom:waf-bypass/"), "{id}");
        let lib = load_custom(dir.path());
        let entries: Vec<&Entry> = lib.entries.iter().collect();
        let (found, note) = super::super::tools::find(&entries, id, "data_get").expect("found");
        assert_eq!(note, None);
        assert_eq!(found.tags, ["svg", "onload"]);
    }

    #[test]
    fn payloads_are_saved_once_and_loaded() {
        let dir = tempfile::tempdir().expect("temp dir");
        let first = add(
            dir.path(),
            &args(json!({"category": "waf", "payload": "<x>", "description": "d"})),
        )
        .expect("add");
        assert_eq!(first["added"], true);
        let again = add(
            dir.path(),
            &args(json!({"category": "waf", "payload": "<x>"})),
        )
        .expect("again");
        assert_eq!(again["added"], false);
        assert_eq!(again["id"], first["id"]);
        let lib = load_custom(dir.path());
        assert_eq!(lib.entries.len(), 1);
        assert_eq!(lib.entries[0].id, first["id"].as_str().expect("id"));
        assert_eq!(lib.entries[0].title, "d");

        let bad = add(
            dir.path(),
            &args(json!({"category": "../x", "payload": "<x>"})),
        )
        .expect_err("bad");
        assert_eq!(bad.code, Code::InvalidArguments);
    }

    #[test]
    fn scripts_need_their_shape_and_overwrite() {
        let dir = tempfile::tempdir().expect("temp dir");
        let no_meta = add(
            dir.path(),
            &args(json!({"kind": "bcheck", "name": "a", "script": "given response then\n"})),
        )
        .expect_err("no metadata");
        assert!(no_meta.error.contains("metadata:"), "{}", no_meta.error);
        let script = "metadata:\n    language: v2-beta\n    name: \"A\"\n\ngiven response then\n";
        let saved = add(
            dir.path(),
            &args(json!({"kind": "bcheck", "name": "a", "category": "mine", "script": script})),
        )
        .expect("saved");
        assert_eq!(saved["id"], "custom:bchecks/mine/a");
        let exists = add(
            dir.path(),
            &args(json!({"kind": "bcheck", "name": "a", "category": "mine", "script": script})),
        )
        .expect_err("exists");
        assert!(exists.error.contains("overwrite"), "{}", exists.error);
        add(
            dir.path(),
            &args(json!({"kind": "bcheck", "name": "a", "category": "mine", "script": script, "overwrite": true})),
        )
        .expect("overwritten");
        let lib = load_custom(dir.path());
        assert_eq!(lib.entries[0].id, "custom:bchecks/mine/a");
        assert_eq!(lib.entries[0].title, "A");
    }
}
