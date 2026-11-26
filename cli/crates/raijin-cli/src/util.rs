//! Small helpers shared by the commands: UTC stamps, edit distance, owner-only writes.

use std::borrow::Cow;
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

/// Up to `n` of `names` close to `wanted`, closest first: within edit distance
/// `max(2, len / 3)` or containing / contained in it, compared in [`norm`](crate::mcp::error::norm)
/// form (case and `-`/`.`/space separators ignored). Same rule as the extension's `ToolArgs.closest`.
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
            let near =
                d <= limit || (!normed.is_empty() && (normed.contains(&w) || w.contains(&normed)));
            near.then_some((d, name))
        })
        .collect();
    scored.sort_unstable();
    scored.dedup_by(|a, b| a.1 == b.1);
    scored.into_iter().take(n).map(|(_, name)| name).collect()
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
