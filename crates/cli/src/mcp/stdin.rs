//! Repairs `tools/call` requests whose `arguments` is a JSON string, before the MCP layer reads
//! them: the protocol wants an object and would refuse the whole request, so the model never
//! learns what was wrong.

use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

use super::error;

/// The request `_meta` key the repair notes travel under, to `call_tool`.
pub const NOTES_META_KEY: &str = "io.bitbytelab.raijin/notes";

/// A repaired `line` (with a trailing newline) when it is a `tools/call` request whose
/// `params.arguments` is a string, else None. A string holding a JSON object becomes that object;
/// any other string becomes `guide`'s topic or `run`'s `do` (broken JSON stays `run`'s
/// `arguments`, which `run` refuses with where it breaks), and for another tool
/// `{"arguments": s}`, so the call fails as a parameter error and never runs without arguments.
/// Each reading is noted in `params._meta` under [`NOTES_META_KEY`].
pub fn repair(line: &[u8]) -> Option<Vec<u8>> {
    let mut request: Map<String, Value> = serde_json::from_slice(line).ok()?;
    if request.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    let params = request.get_mut("params")?.as_object_mut()?;
    let Some(Value::String(s)) = params.get("arguments") else {
        return None;
    };
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (arguments, note) = match json_object(s) {
        Some((object, 1)) => (
            object,
            Some("parsed 'arguments' from a JSON string".to_owned()),
        ),
        Some((object, layers)) => (
            object,
            Some(format!(
                "parsed 'arguments' from JSON encoded {layers} times (a JSON string inside a JSON string)"
            )),
        ),
        None => match error::norm(error::strip_server_prefix(name).unwrap_or(name)).as_str() {
            "guide" => (
                one("topic", s.trim()),
                Some("read string 'arguments' as guide's topic".to_owned()),
            ),
            // Broken JSON stays `arguments`, so `run` says where it breaks.
            "run" if s.trim_start().starts_with(['{', '[']) => (one("arguments", s), None),
            "run" => (
                one("do", s.trim()),
                Some("read string 'arguments' as \"do\"".to_owned()),
            ),
            _ => (one("arguments", s), None),
        },
    };
    params.insert("arguments".to_owned(), Value::Object(arguments));
    if let Some(note) = note {
        let meta = params
            .entry("_meta")
            .or_insert_with(|| Value::Object(Map::new()));
        if let Some(meta) = meta.as_object_mut() {
            match meta
                .entry(NOTES_META_KEY)
                .or_insert_with(|| Value::Array(Vec::new()))
            {
                Value::Array(notes) => notes.push(json!(note)),
                other => *other = json!([note]),
            }
        }
    }
    let mut out = serde_json::to_vec(&Value::Object(request)).ok()?;
    out.push(b'\n');
    Some(out)
}

/// Most parses [`json_object`] makes: an object inside up to two JSON strings.
const MAX_LAYERS: usize = 3;

/// `s` parsed as a JSON object, also when it is a JSON string holding one, encoded again up to
/// [`MAX_LAYERS`] in all (`"\"{\\\"a\\\":1}\""` takes 2): the object and the parses it took. Each
/// layer must be a string until the object; anything else is None.
pub fn json_object(s: &str) -> Option<(Map<String, Value>, usize)> {
    let mut text = s.to_owned();
    for layer in 1..=MAX_LAYERS {
        match serde_json::from_str::<Value>(&text).ok()? {
            Value::Object(object) => return Some((object, layer)),
            Value::String(inner) => text = inner,
            _ => return None,
        }
    }
    None
}

fn one(key: &str, value: &str) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert(key.to_owned(), json!(value));
    map
}

/// Stdin with every line passed through [`repair`]: a task copies stdin line by line into the
/// returned stream until EOF or the reader is gone.
pub fn repaired_stdin() -> DuplexStream {
    let (reader, mut writer) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let mut stdin = BufReader::new(tokio::io::stdin());
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match stdin.read_until(b'\n', &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let line = repair(&buf);
            if writer
                .write_all(line.as_deref().unwrap_or(&buf))
                .await
                .is_err()
            {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });
    reader
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repaired(line: &str) -> Option<Value> {
        repair(line.as_bytes()).map(|b| {
            assert_eq!(b.last(), Some(&b'\n'));
            serde_json::from_slice(&b).expect("json")
        })
    }

    #[test]
    fn string_arguments_become_an_object_with_a_note() {
        let v = repaired(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run","arguments":"{\"do\":\"burp_status\"}"}}"#,
        )
        .expect("repaired");
        assert_eq!(v["params"]["arguments"], json!({"do": "burp_status"}));
        assert_eq!(
            v["params"]["_meta"][NOTES_META_KEY],
            json!(["parsed 'arguments' from a JSON string"])
        );
        assert_eq!(v["id"], json!(3));
    }

    #[test]
    fn arguments_encoded_twice_are_decoded_whole() {
        let v = repaired(
            r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"run","arguments":"\"{\\\"do\\\":\\\"burp_status\\\"}\""}}"#,
        )
        .expect("repaired");
        assert_eq!(v["params"]["arguments"], json!({"do": "burp_status"}));
        assert_eq!(
            v["params"]["_meta"][NOTES_META_KEY],
            json!([
                "parsed 'arguments' from JSON encoded 2 times (a JSON string inside a JSON string)"
            ])
        );
        let thrice = json!(json!(json!({"a": 1}).to_string()).to_string()).to_string();
        assert_eq!(json_object(&thrice).map(|(_, n)| n), Some(3));
        let four = json!(thrice).to_string();
        assert_eq!(json_object(&four), None, "at most 3 parses");
    }

    #[test]
    fn a_plain_string_is_guide_topic_or_run_do() {
        let guide = repaired(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"guide","arguments":"util.hash"}}"#,
        )
        .expect("repaired");
        assert_eq!(guide["params"]["arguments"], json!({"topic": "util.hash"}));
        let run = repaired(
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"mcp__raijin__run","arguments":" history_list "}}"#,
        )
        .expect("repaired");
        assert_eq!(run["params"]["arguments"], json!({"do": "history_list"}));
        let other = repaired(
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"history_list","arguments":"x"}}"#,
        )
        .expect("repaired");
        assert_eq!(other["params"]["arguments"], json!({"arguments": "x"}));
        assert!(other["params"].get("_meta").is_none());
        let broken = repaired(
            r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"run","arguments":"{bad json"}}"#,
        )
        .expect("repaired");
        assert_eq!(
            broken["params"]["arguments"],
            json!({"arguments": "{bad json"})
        );
    }

    #[test]
    fn other_lines_pass_through() {
        assert!(repair(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
        assert!(
            repair(
                br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run","arguments":{"do":"x"}}}"#
            )
            .is_none()
        );
        assert!(repair(b"not json\n").is_none());
    }
}
