//! Normalizers from upstream and custom files to [`Entry`]s. Pure: text and a path relative to the
//! source root in, entries out; the loader turns `file` into an absolute path.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};

use super::{Entry, Kind, Source, id_hash};

/// `text` with every lone UTF-16 surrogate escape (`\ud83c` without its pair) replaced by `\ufffd`,
/// which `serde_json` would reject. Valid pairs and escaped backslashes (`\\ud83c`) stay as they are.
pub fn fix_lone_surrogates(text: &str) -> Cow<'_, str> {
    fn unit(b: &[u8], at: usize) -> Option<u16> {
        if b.get(at) != Some(&b'\\') || b.get(at + 1) != Some(&b'u') {
            return None;
        }
        let hex = std::str::from_utf8(b.get(at + 2..at + 6)?).ok()?;
        u16::from_str_radix(hex, 16).ok()
    }
    let b = text.as_bytes();
    let mut out: Option<String> = None;
    let mut copied = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            i += 1;
            continue;
        }
        let Some(u) = unit(b, i) else {
            // `\\`, `\"`, ...: the escaped character is never the start of another escape.
            i += 2;
            continue;
        };
        let lone = match u {
            0xD800..=0xDBFF => match unit(b, i + 6) {
                Some(0xDC00..=0xDFFF) => {
                    i += 12;
                    continue;
                }
                _ => true,
            },
            0xDC00..=0xDFFF => true,
            _ => false,
        };
        if lone {
            let s = out.get_or_insert_with(|| String::with_capacity(text.len()));
            s.push_str(&text[copied..i]);
            s.push_str("\\ufffd");
            copied = i + 6;
        }
        i += 6;
    }
    match out {
        None => Cow::Borrowed(text),
        Some(mut s) => {
            s.push_str(&text[copied..]);
            Cow::Owned(s)
        }
    }
}

/// JSON text after [`fix_lone_surrogates`].
pub fn json(text: &str) -> Result<Value> {
    Ok(serde_json::from_str(&fix_lone_surrogates(text))?)
}

/// The file name of `rel` without its extension.
fn stem(rel: &str) -> String {
    Path::new(rel)
        .file_stem()
        .map_or_default(|s| s.to_string_lossy().into_owned())
}

/// `rel` without its extension, with `/` separators.
fn without_ext(rel: &str) -> String {
    let p = Path::new(rel);
    let parent = p
        .parent()
        .map_or_default(|p| p.to_string_lossy().into_owned());
    if parent.is_empty() {
        stem(rel)
    } else {
        format!("{parent}/{}", stem(rel))
    }
}

/// The folder of `rel`, or `root` for a file at the top.
fn folder(rel: &str) -> String {
    match Path::new(rel).parent().map(|p| p.to_string_lossy()) {
        Some(p) if !p.is_empty() => p.into_owned(),
        _ => "root".to_owned(),
    }
}

fn first_str<'v>(o: &'v Map<String, Value>, keys: &[&str]) -> Option<&'v str> {
    keys.iter().find_map(|k| o.get(*k).and_then(Value::as_str))
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).map_or_default(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}

/// One XSS cheat sheet file (`json/<category>.json`): `events.json` is an object of events, each
/// with its vectors per element; every other file is an array of vectors.
pub fn parse_xss(rel: &str, text: &str) -> Result<Vec<Entry>> {
    let category = stem(rel);
    let file = PathBuf::from(rel);
    match json(text)? {
        Value::Object(events) => {
            let mut out = Vec::new();
            for (event, body) in &events {
                let description = body
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let Some(tags) = body.get("tags").and_then(Value::as_array) else {
                    continue;
                };
                for t in tags.iter().filter_map(Value::as_object) {
                    let tag = t.get("tag").and_then(Value::as_str).unwrap_or_default();
                    let code = t.get("code").and_then(Value::as_str).unwrap_or_default();
                    let mut e = Entry::new(
                        format!("xss:{category}/{event}/{tag}"),
                        Source::Xss,
                        Kind::Payload,
                        category.clone(),
                        format!("{event} on {tag}: {description}"),
                        code.to_owned(),
                        file.clone(),
                    );
                    if !description.is_empty() {
                        e.description = Some(description.to_owned());
                    }
                    e.tags = vec![event.clone(), tag.to_owned()];
                    e.browsers = strings(t.get("browsers"));
                    e.interaction = t.get("interaction").and_then(Value::as_bool);
                    for (k, v) in t {
                        if !matches!(k.as_str(), "tag" | "code" | "browsers" | "interaction") {
                            e.extra.insert(k.clone(), v.clone());
                        }
                    }
                    out.push(e);
                }
            }
            Ok(out)
        }
        Value::Array(items) => Ok(items
            .iter()
            .filter_map(Value::as_object)
            .map(|o| xss_item(&category, &file, o))
            .collect()),
        _ => bail!("neither an object of events nor an array of vectors"),
    }
}

const XSS_PAYLOAD_KEYS: [&str; 4] = ["code", "vector", "payload", "closestVector"];
const XSS_TITLE_KEYS: [&str; 3] = ["description", "title", "library"];

fn xss_item(category: &str, file: &Path, o: &Map<String, Value>) -> Entry {
    let payload = first_str(o, &XSS_PAYLOAD_KEYS).unwrap_or_default();
    let mut title =
        first_str(o, &XSS_TITLE_KEYS).map_or_else(|| category.to_owned(), |t| t.trim().to_owned());
    if let Some(v) = first_str(o, &["versionRange", "version"]) {
        title = format!("{title} ({v})");
    }
    let key = if payload.is_empty() { &title } else { payload };
    let mut e = Entry::new(
        format!("xss:{category}/{}", id_hash(key)),
        Source::Xss,
        Kind::Payload,
        category.to_owned(),
        title,
        payload.to_owned(),
        file.to_path_buf(),
    );
    e.context = o.get("context").and_then(Value::as_str).map(str::to_owned);
    e.browsers = strings(o.get("browsers"));
    e.interaction = o.get("interaction").and_then(Value::as_bool);
    if let Some(t) = o.get("type").and_then(Value::as_str) {
        e.tags.push(t.to_owned());
    }
    if o.get("csp").and_then(Value::as_bool) == Some(true) {
        e.tags.push("csp".to_owned());
    }
    let payload_key = XSS_PAYLOAD_KEYS
        .iter()
        .find(|k| o.get(**k).is_some_and(Value::is_string));
    let title_key = XSS_TITLE_KEYS
        .iter()
        .find(|k| o.get(**k).is_some_and(Value::is_string));
    for (k, v) in o {
        let used = Some(&k.as_str()) == payload_key
            || Some(&k.as_str()) == title_key
            || matches!(k.as_str(), "context" | "browsers" | "interaction" | "type");
        if !used {
            e.extra.insert(k.clone(), v.clone());
        }
    }
    e
}

/// One URL validation bypass file (`src/<category>.json`): `{name, payloads:[...]}`.
pub fn parse_url(rel: &str, text: &str) -> Result<Vec<Entry>> {
    let category = stem(rel);
    let root = json(text)?;
    let items = root
        .get("payloads")
        .and_then(Value::as_array)
        .context("no \"payloads\" array")?;
    Ok(items
        .iter()
        .filter_map(Value::as_object)
        .map(|o| {
            let part = |k: &str| o.get(k).and_then(Value::as_str).unwrap_or_default();
            let payload = format!("{}{}{}", part("prefix"), part("payload"), part("suffix"));
            let description = part("description").trim();
            let mut e = Entry::new(
                format!("url:{category}/{}", id_hash(&payload)),
                Source::Url,
                Kind::Payload,
                category.clone(),
                if description.is_empty() {
                    category.clone()
                } else {
                    description.to_owned()
                },
                payload,
                PathBuf::from(rel),
            );
            if !description.is_empty() {
                e.description = Some(description.to_owned());
            }
            e.tags = strings(o.get("tags"));
            for k in ["port", "prefix", "suffix", "id"] {
                if let Some(v) = o.get(k).filter(|v| !v.is_null()) {
                    e.extra.insert(k.to_owned(), v.clone());
                }
            }
            e
        })
        .collect())
}

/// The id of a script file: `<source>:<rel>` upstream, `custom:<dir>/<rel>` for this target's own.
fn script_id(source: Source, dir: &str, rel: &str) -> String {
    let path = id_slug(&without_ext(rel));
    match source {
        Source::Custom => format!("custom:{dir}/{path}"),
        s => format!("{}:{path}", s.as_str()),
    }
}

/// `id` with every run of whitespace as one `-`, so ids built from file names
/// (`Springboot beans actuator.bcheck`) need no quoting: `Springboot-beans-actuator`.
pub fn id_slug(id: &str) -> String {
    id.split_whitespace().collect::<Vec<_>>().join("-")
}

fn unquote(v: &str) -> &str {
    v.trim().trim_matches('"')
}

/// One `BCheck`: its `metadata:` block (name, description, author, tags) and `given <x> then`.
pub fn parse_bcheck(source: Source, rel: &str, text: &str) -> Entry {
    let mut meta: Vec<(&str, &str)> = Vec::new();
    let mut in_meta = false;
    for line in text.lines() {
        if line.trim() == "metadata:" {
            in_meta = true;
            continue;
        }
        if !in_meta {
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with([' ', '\t']) {
            break;
        }
        if let Some((k, v)) = line.trim().split_once(':') {
            meta.push((k.trim(), v.trim()));
        }
    }
    let get = |key: &str| {
        meta.iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| unquote(v))
    };
    let title = get("name")
        .filter(|n| !n.is_empty())
        .map_or_else(|| stem(rel), str::to_owned);
    let mut e = Entry::new(
        script_id(source, "bchecks", rel),
        source,
        Kind::Bcheck,
        folder(rel),
        title,
        text.to_owned(),
        PathBuf::from(rel),
    );
    e.description = get("description")
        .filter(|d| !d.is_empty())
        .map(str::to_owned);
    if let Some((_, tags)) = meta.iter().find(|(k, _)| *k == "tags") {
        e.tags = tags
            .split(',')
            .map(|t| t.trim().trim_matches('"').trim().to_owned())
            .filter(|t| !t.is_empty())
            .collect();
    }
    for key in ["author", "language"] {
        if let Some(v) = get(key).filter(|v| !v.is_empty()) {
            e.extra.insert(key.to_owned(), Value::String(v.to_owned()));
        }
    }
    let given = text.lines().map(str::trim).find_map(|l| {
        let rest = l.strip_prefix("given ")?;
        Some(rest.split_once(" then").map_or(rest, |(g, _)| g).trim())
    });
    if let Some(g) = given {
        e.extra
            .insert("given".to_owned(), Value::String(g.to_owned()));
    }
    e
}

/// One Bambda file: header lines (`id:`, `name:`, `function:`, `location:`) up to `source: |+`, then
/// the body indented 2 spaces, whose `/** ... **/` doc comment gives the description and author. A
/// file without that header (a bare lambda) is the body itself.
pub fn parse_bambda(source: Source, rel: &str, text: &str) -> Entry {
    let lines: Vec<&str> = text.lines().collect();
    let source_at = lines
        .iter()
        .position(|l| l.trim_start().starts_with("source:"));
    let (header, body): (&[&str], Vec<&str>) = match source_at {
        Some(at) => (
            &lines[..at],
            lines[at + 1..]
                .iter()
                .map(|l| {
                    let strip = l.len() - l.trim_start_matches(' ').len();
                    &l[strip.min(2)..]
                })
                .collect(),
        ),
        None => (&[], lines.clone()),
    };
    let get = |key: &str| {
        header.iter().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim() == key)
                .then(|| unquote(v))
                .filter(|v| !v.is_empty())
        })
    };
    let title = get("name").map_or_else(|| stem(rel), str::to_owned);
    let mut e = Entry::new(
        script_id(source, "bambdas", rel),
        source,
        Kind::Bambda,
        folder(rel),
        title,
        text.to_owned(),
        PathBuf::from(rel),
    );
    e.tags = ["function", "location"]
        .iter()
        .filter_map(|k| get(k).map(str::to_owned))
        .collect();
    if let Some(id) = get("id") {
        e.extra
            .insert("bambda_id".to_owned(), Value::String(id.to_owned()));
    }
    let (description, author) = doc_comment(&body);
    e.description = description;
    if let Some(a) = author {
        e.extra.insert("author".to_owned(), Value::String(a));
    }
    e
}

/// The first text line and the `@author` of the first `/** ... */` comment in `body`.
fn doc_comment(body: &[&str]) -> (Option<String>, Option<String>) {
    let Some(start) = body.iter().position(|l| l.contains("/**")) else {
        return (None, None);
    };
    let mut description = None;
    let mut author = None;
    for (i, raw) in body[start..].iter().enumerate() {
        let mut line = *raw;
        if i == 0 {
            line = line.split_once("/**").map_or("", |(_, rest)| rest);
        }
        let end = line.contains("*/");
        let line = line
            .split("*/")
            .next()
            .unwrap_or_default()
            .trim()
            .trim_start_matches('*')
            .trim();
        if let Some(a) = line.strip_prefix("@author") {
            if author.is_none() && !a.trim().is_empty() {
                author = Some(a.trim().to_owned());
            }
        } else if !line.is_empty() && !line.starts_with('@') && description.is_none() {
            description = Some(line.to_owned());
        }
        if end {
            break;
        }
    }
    (description, author)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lone_surrogates_become_replacement_characters() {
        let fixed = fix_lone_surrogates(r#""<a>\ud83c<b>""#);
        let v: String = serde_json::from_str(&fixed).expect("parses");
        assert_eq!(v, "<a>\u{FFFD}<b>");
        let pair: String =
            serde_json::from_str(&fix_lone_surrogates(r#""\ud83d\ude00""#)).expect("pair");
        assert_eq!(pair, "😀");
        let escaped = r#""\\ud83c""#;
        assert!(matches!(fix_lone_surrogates(escaped), Cow::Borrowed(_)));
        let low: String = serde_json::from_str(&fix_lone_surrogates(r#""x\uDC00""#)).expect("low");
        assert_eq!(low, "x\u{FFFD}");
    }

    const EVENTS: &str = r#"{"onload":{"description":"Fires on load","tags":[{"tag":"svg","code":"<svg onload=alert(1)>","browsers":["chrome"],"interaction":false}]}}"#;

    #[test]
    fn xss_events_and_arrays() {
        let events = parse_xss("json/events.json", EVENTS).expect("events");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "xss:events/onload/svg");
        assert_eq!(events[0].payload, "<svg onload=alert(1)>");
        assert_eq!(events[0].tags, ["onload", "svg"]);
        assert_eq!(events[0].interaction, Some(false));

        let arr = parse_xss(
            "json/classic.json",
            r#"[{"description":"d","code":"<img src=x>","browsers":["chrome"],"context":"html","url":"u"}]"#,
        )
        .expect("array");
        assert_eq!(arr[0].payload, "<img src=x>");
        assert_eq!(arr[0].browsers, ["chrome"]);
        assert_eq!(arr[0].context.as_deref(), Some("html"));
        assert_eq!(arr[0].extra.get("url"), Some(&Value::String("u".into())));
        assert!(arr[0].id.starts_with("xss:classic/"));

        let ng = parse_xss(
            "json/angularjs.json",
            r#"[{"vector":"{{constructor.constructor('alert(1)')()}}","version":"1.0.1","type":"sandbox"}]"#,
        )
        .expect("angular");
        assert_eq!(ng[0].title, "angularjs (1.0.1)");
        assert_eq!(ng[0].tags, ["sandbox"]);
        assert!(ng[0].extra.get("vector").is_none());
    }

    #[test]
    fn url_payloads_join_prefix_and_suffix() {
        let e = parse_url(
            "src/loopback.json",
            r#"{"name":"n","payloads":[{"id":"x","payload":"<attacker>","prefix":"http://","suffix":"/","description":"d","tags":["URL"],"filters":[]}]}"#,
        )
        .expect("url");
        assert_eq!(e[0].payload, "http://<attacker>/");
        assert_eq!(e[0].tags, ["URL"]);
        assert_eq!(e[0].category, "loopback");
    }

    #[test]
    fn bcheck_metadata_and_given() {
        let text = "metadata:\n    language: v2-beta\n    name: \"Cookie-SameSite-Disabled\"\n    description: \"SameSite none\"\n    author: \"Someone\"\n    tags: \"passive\",\"informative\"\n\ngiven response then\n    if true then\n    end if\n";
        let e = parse_bcheck(Source::Bchecks, "other/cookie.bcheck", text);
        assert_eq!(e.id, "bchecks:other/cookie");
        assert_eq!(e.title, "Cookie-SameSite-Disabled");
        assert_eq!(e.tags, ["passive", "informative"]);
        assert_eq!(e.extra["given"], "response");
        assert_eq!(e.extra["author"], "Someone");
        assert_eq!(e.category, "other");
        let spaced = parse_bcheck(Source::Bchecks, "other/Spring  beans actuator.bcheck", text);
        assert_eq!(spaced.id, "bchecks:other/Spring-beans-actuator");
        let custom = parse_bcheck(Source::Custom, "x.bcheck", text);
        assert_eq!(custom.id, "custom:bchecks/x");
        assert_eq!(custom.category, "root");
    }

    #[test]
    fn bambda_header_and_doc_comment() {
        let text = "id: 1234\nname: CookieInjection\nfunction: CUSTOM_ACTION\nlocation: REPEATER\nsource: |+\n  /**\n   * Injects a cookie.\n   * @author d0ge\n   **/\n  return true;\n";
        let e = parse_bambda(Source::Bambdas, "CustomAction/CookieInjection.bambda", text);
        assert_eq!(e.id, "bambdas:CustomAction/CookieInjection");
        assert_eq!(e.title, "CookieInjection");
        assert_eq!(e.tags, ["CUSTOM_ACTION", "REPEATER"]);
        assert_eq!(e.description.as_deref(), Some("Injects a cookie."));
        assert_eq!(e.extra["author"], "d0ge");
        assert_eq!(e.extra["bambda_id"], "1234");
        let bare = parse_bambda(Source::Custom, "mine.bambda", "return true;\n");
        assert_eq!(bare.title, "mine");
        assert_eq!(bare.tags, Vec::<String>::new());
    }
}
