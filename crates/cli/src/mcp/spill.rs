//! Large tool results go to a file; the agent gets the path and a preview.

use std::path::Path;

use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{Map, Value, json};

use crate::util::{truncate_utf8, utc_stamp, write_private};

const PREVIEW_BYTES: usize = 2048;
const HINT: &str = "Parse with jq/python or hand the file to a subagent; never read it whole.";

/// The `notes` array of a result that is one text block holding a JSON object.
fn notes_of(texts: &[&str]) -> Option<Value> {
    let [text] = texts else {
        return None;
    };
    // Parsing a large result only pays when it has notes to keep.
    if !text.contains("\"notes\"") {
        return None;
    }
    match serde_json::from_str::<Value>(text).ok()? {
        Value::Object(mut object) => object.remove("notes").filter(Value::is_array),
        _ => None,
    }
}

/// Returns `result` unchanged when its joined text fits `limit` bytes; otherwise writes the text to
/// `<dir>/<UTC stamp>-<tool>-<4 hex>.json` and returns `{saved_to, bytes, notes, preview, hint}`
/// (`notes` copied from the result when it has them), keeping `isError`.
pub fn apply(result: CallToolResult, tool: &str, limit: usize, dir: &Path) -> CallToolResult {
    let texts: Vec<&str> = result
        .content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
        .collect();
    let joined = texts.join("\n");
    if joined.len() <= limit {
        return result;
    }
    let safe_tool: String = tool
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut suffix = [0u8; 2];
    let _ = getrandom::fill(&mut suffix);
    let path = dir.join(format!(
        "{}-{safe_tool}-{:02x}{:02x}.json",
        utc_stamp(),
        suffix[0],
        suffix[1]
    ));
    let written = write_private(&path, joined.as_bytes());
    let is_error = result.is_error.unwrap_or(false);
    let summary = match written {
        Ok(()) => {
            let mut summary = Map::new();
            summary.insert("saved_to".to_owned(), json!(path.display().to_string()));
            summary.insert("bytes".to_owned(), json!(joined.len()));
            // What the server changed in the call stays in sight, ahead of the preview.
            if let Some(notes) = notes_of(&texts) {
                summary.insert("notes".to_owned(), notes);
            }
            summary.insert(
                "preview".to_owned(),
                json!(truncate_utf8(&joined, PREVIEW_BYTES)),
            );
            summary.insert("hint".to_owned(), json!(HINT));
            Value::Object(summary)
        }
        Err(e) => {
            return CallToolResult::error(vec![ContentBlock::text(format!(
                "result of {tool} is {} bytes, over the inline limit, and could not be saved to {}: {e:#}",
                joined.len(),
                path.display()
            ))]);
        }
    };
    let mut content = vec![ContentBlock::text(summary.to_string())];
    content.extend(result.content.into_iter().filter(|c| c.as_text().is_none()));
    if is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_results_pass_and_large_ones_are_saved() {
        let dir = tempfile::tempdir().expect("temp dir");
        let small = CallToolResult::success(vec![ContentBlock::text("ok")]);
        assert_eq!(apply(small.clone(), "t", 10, dir.path()), small);

        let big = CallToolResult::error(vec![ContentBlock::text("é".repeat(3000))]);
        let out = apply(big, "proxy/history", 100, dir.path());
        assert_eq!(out.is_error, Some(true));
        let summary: serde_json::Value =
            serde_json::from_str(&out.content[0].as_text().expect("text").text)
                .expect("json summary");
        let saved = summary["saved_to"].as_str().expect("path");
        assert!(saved.contains("-proxy_history-"), "{saved}");
        assert_eq!(
            std::fs::read_to_string(saved).expect("saved file").len(),
            6000
        );
        assert!(summary["preview"].as_str().expect("preview").len() <= PREVIEW_BYTES);
        assert!(summary.get("notes").is_none(), "{summary}");

        let noted = CallToolResult::success(vec![ContentBlock::text(
            json!({"rows": "x".repeat(3000), "notes": ["read 'see' as the call"]}).to_string(),
        )]);
        let out = apply(noted, "history_list", 100, dir.path());
        let text = &out.content[0].as_text().expect("text").text;
        let summary: serde_json::Value = serde_json::from_str(text).expect("json summary");
        assert_eq!(summary["notes"], json!(["read 'see' as the call"]));
        assert!(
            text.find("\"notes\"") < text.find("\"preview\""),
            "notes lead the preview: {text}"
        );
    }
}
