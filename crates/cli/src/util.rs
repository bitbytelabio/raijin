//! Small helpers shared by the commands: UTC stamps, edit distance, owner-only writes.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// `yyyymmddThhmmssZ` for the current time.
pub fn utc_stamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    utc_stamp_at(secs)
}

pub fn utc_stamp_at(epoch_secs: u64) -> String {
    let days = i64::try_from(epoch_secs / 86_400).unwrap_or(0);
    let rem = epoch_secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's days-to-civil conversion (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Levenshtein distance over chars.
pub fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0; b.len() + 1];
    for (i, ca) in a.chars().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != *cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Whether one of `wanted` and `name` (both in [`norm`](crate::mcp::error::norm) form) contains the
/// other and the shorter is long enough to mean it: at least 4 chars and 60% of `wanted`, so `ai`
/// is not near `email` nor `log` near `catalog`.
pub fn contains_near(wanted: &str, name: &str) -> bool {
    if name.is_empty() || !(name.contains(wanted) || wanted.contains(name)) {
        return false;
    }
    let wanted_len = wanted.chars().count();
    let shorter = name.chars().count().min(wanted_len);
    shorter >= 4 && shorter * 10 >= wanted_len * 6
}

/// Up to `n` of `names` close to `wanted`, closest first: within edit distance
/// `max(2, len / 3)`, or one containing the other per [`contains_near`], compared in
/// [`norm`](crate::mcp::error::norm) form (case and `-`/`.`/`/`/space separators ignored). Same rule
/// as the extension's `ToolArgs.closest`.
pub fn suggest<'a>(
    wanted: &str,
    names: impl IntoIterator<Item = &'a str>,
    n: usize,
) -> Vec<&'a str> {
    let w = crate::mcp::error::norm(wanted);
    if w.is_empty() {
        return Vec::new();
    }
    let limit = (w.chars().count() / 3).max(2);
    let mut scored: Vec<(usize, &str)> = names
        .into_iter()
        .filter_map(|name| {
            let normed = crate::mcp::error::norm(name);
            let d = edit_distance(&w, &normed);
            let near = d <= limit || contains_near(&w, &normed);
            near.then_some((d, name))
        })
        .collect();
    scored.sort_unstable();
    scored.dedup_by(|a, b| a.1 == b.1);
    scored.into_iter().take(n).map(|(_, name)| name).collect()
}

/// A suggested call name; `same_words` when it says the same words as the name asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suggestion<'a> {
    pub name: &'a str,
    pub same_words: bool,
}

/// The words of a call name: [`norm`](crate::mcp::error::norm) form split on `_`, without stop
/// words, singular, and with synonyms in one form (`list`/`show` -> `get`, `create`/`include` ->
/// `add`, `find` -> `search`, `scanner` -> `scan`). Same rule as the extension's
/// `ToolArgs.intentTokens`.
fn intent_tokens(name: &str) -> BTreeSet<String> {
    const STOP_WORDS: [&str; 9] = ["to", "the", "a", "an", "of", "for", "in", "on", "by"];
    crate::mcp::error::norm(name)
        .split('_')
        .filter(|t| !t.is_empty() && !STOP_WORDS.contains(t))
        .map(|t| {
            if t.chars().count() > 3 && t.ends_with('s') && !t.ends_with("ss") {
                &t[..t.len() - 1]
            } else {
                t
            }
        })
        .map(|t| match t {
            "get" | "list" | "show" | "fetch" | "read" | "view" | "query" => "get".to_owned(),
            "add" | "create" | "new" | "include" | "insert" => "add".to_owned(),
            "find" | "search" | "grep" | "lookup" => "search".to_owned(),
            "scanner" => "scan".to_owned(),
            other => other.to_owned(),
        })
        .collect()
}

/// Up to `n` call names of `names` for `wanted`, by intent: first the ones with the same words
/// ([`intent_tokens`]), then the near ones of [`suggest`]'s rule (by edit distance), then the ones
/// holding every word of `wanted` (fewest extra words first). `ai` calls rank after the others of
/// their class. Same rule as the extension's `ToolArgs.closestCalls`.
pub fn suggest_call<'a>(
    wanted: &str,
    names: impl IntoIterator<Item = &'a str>,
    n: usize,
) -> Vec<Suggestion<'a>> {
    let w = crate::mcp::error::norm(wanted);
    if w.is_empty() {
        return Vec::new();
    }
    let limit = (w.chars().count() / 3).max(2);
    let want = intent_tokens(wanted);
    // (class, ai rank, sub-score, name)
    let mut ranked: Vec<(u8, u8, usize, &str)> = names
        .into_iter()
        .filter_map(|name| {
            let normed = crate::mcp::error::norm(name);
            let have = intent_tokens(name);
            let d = edit_distance(&w, &normed);
            let (class, sub) = if !want.is_empty() && have == want {
                (0, 0)
            } else if d <= limit || contains_near(&w, &normed) {
                (1, d)
            } else if !want.is_empty() && have.is_superset(&want) {
                (2, have.len() - want.len())
            } else {
                return None;
            };
            let ai = u8::from(normed == "ai" || normed.starts_with("ai_"));
            Some((class, ai, sub, name))
        })
        .collect();
    ranked.sort_unstable();
    ranked.dedup_by(|a, b| a.3 == b.3);
    ranked
        .into_iter()
        .take(n)
        .map(|(class, _, _, name)| Suggestion {
            name,
            same_words: class == 0,
        })
        .collect()
}

/// Creates `dir` and any missing parents as owner-only (0700): `.raijin/` and `~/.raijin/` hold
/// tool results, archives, tokens and logs. Existing directories keep their mode.
pub fn private_dir(dir: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

/// Writes `bytes` to `path` readable by the owner only (0600), replacing it atomically.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        private_dir(parent)?;
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
}

/// `text` safe to print on a terminal: control characters other than newline and tab (C0, DEL,
/// C1) become `\u{..}` escapes, so captured target bytes cannot drive the terminal (OSC 52 clipboard
/// writes, cursor moves that fake lines).
pub fn visible(text: &str) -> Cow<'_, str> {
    escape_controls(text, |c| c.is_control() && c != '\n' && c != '\t')
}

/// [`visible`] for one table row: newlines and tabs are escaped too, so a value cannot fake rows.
pub fn visible_line(text: &str) -> Cow<'_, str> {
    escape_controls(text, char::is_control)
}

fn escape_controls(text: &str, unsafe_char: impl Fn(char) -> bool) -> Cow<'_, str> {
    if !text.contains(&unsafe_char) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        if unsafe_char(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// `s` cut to at most `max` bytes on a char boundary.
pub fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_are_utc_calendar_dates() {
        assert_eq!(utc_stamp_at(0), "19700101T000000Z");
        assert_eq!(utc_stamp_at(1_787_630_518), "20260825T040158Z");
        assert_eq!(utc_stamp_at(951_782_400), "20000229T000000Z");
    }

    /// Real call names of the catalog and the gateway that compete for the cases below.
    const CALLS: [&str; 31] = [
        "http_send_request",
        "http_send_request_chain",
        "http_send_requests_parallel",
        "http_send_raw_bytes",
        "http_race",
        "http_fuzz",
        "http_send_pipeline",
        "analyze.request",
        "proxy_history",
        "proxy_history_search",
        "websocket.history_search",
        "history_search",
        "history_list",
        "util.base64_decode",
        "util.base64_encode",
        "util.decode_smart",
        "scope.include",
        "scope.exclude",
        "scope.check",
        "scope.list",
        "findings.add",
        "findings.list",
        "findings.remove",
        "scanner.start_audit",
        "scanner.start_crawl",
        "scanner.get_all_issues",
        "scanner_task.status",
        "ai.status",
        "burp_status",
        "turbo_run.status",
        "proxy_intercept.status",
    ];

    fn first_calls(wanted: &str) -> Vec<&'static str> {
        suggest_call(wanted, CALLS, 3)
            .into_iter()
            .map(|s| s.name)
            .collect()
    }

    #[test]
    fn call_suggestions_follow_what_the_name_asks_for() {
        assert_eq!(first_calls("http_request")[0], "http_send_request");
        assert_eq!(first_calls("search_history")[0], "history_search");
        assert_eq!(first_calls("decode_base64")[0], "util.base64_decode");
        assert_eq!(first_calls("add_to_scope")[0], "scope.include");
        assert_eq!(first_calls("add_finding")[0], "findings.add");
        assert_eq!(
            first_calls("start_scan")[..2],
            ["scanner.start_audit", "scanner.start_crawl"]
        );
        let list = suggest_call("list_findings", CALLS, 3);
        assert_eq!(
            list[0],
            Suggestion {
                name: "findings.list",
                same_words: true
            }
        );
        assert_eq!(list.iter().filter(|s| s.same_words).count(), 1);
        assert_ne!(first_calls("status")[0], "ai.status");
        assert_eq!(
            first_calls_of("status", &["ai.status", "burp_status", "turbo_run.status"])[0],
            "burp_status"
        );
    }

    fn first_calls_of<'a>(wanted: &str, names: &[&'a str]) -> Vec<&'a str> {
        suggest_call(wanted, names.iter().copied(), 3)
            .into_iter()
            .map(|s| s.name)
            .collect()
    }

    #[test]
    fn suggest_keeps_only_near_names() {
        let none: Vec<&str> = suggest("nope_tool", ["scope_list", "send_to_tool", "burp_down"], 3);
        assert_eq!(none, Vec::<&str>::new());
        assert_eq!(
            suggest(
                "proxy_histroy",
                ["proxy_history", "proxy_rule", "http_send_request"],
                3
            ),
            ["proxy_history"]
        );
        assert_eq!(
            suggest("History.List", ["history_list"], 1),
            ["history_list"]
        );
        let names = ["ai", "log", "findings", "scope"];
        assert_eq!(suggest("email", names, 3), Vec::<&str>::new());
        assert_eq!(suggest("catalog", names, 3), Vec::<&str>::new());
    }

    #[test]
    fn terminal_controls_are_escaped() {
        assert_eq!(visible("a\nb\tc"), "a\nb\tc");
        assert_eq!(
            visible("x\u{1b}]52;c;Zm9v\u{7}y\r"),
            "x\\u{1b}]52;c;Zm9v\\u{7}y\\u{d}"
        );
        assert_eq!(visible("\u{9b}2J"), "\\u{9b}2J");
    }

    #[test]
    fn truncation_keeps_char_boundaries() {
        assert_eq!(truncate_utf8("héllo", 2), "h");
        assert_eq!(truncate_utf8("abc", 10), "abc");
    }
}
