//! The error envelope every `raijin mcp` error result uses, shared with the extension
//! (`ToolArgs.error` in Kotlin): one JSON object with `error` and `code`, plus what helps fix the
//! call (`param`, `allowed`, `retry`, `example`, ...), and `retryable`.

use std::ops::Deref;

use rmcp::model::{CallToolResult, ContentBlock};
use serde::Serialize;
use serde_json::{Value, json};

/// Ends the `error` of every non-retryable envelope.
pub const FINAL_SENTENCE: &str = " Do not resend this call unchanged.";

/// What went wrong; [`Code::retryable`] says whether a changed call can succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    UnknownTool,
    UnknownTopic,
    UnknownParameter,
    MissingParameter,
    InvalidType,
    InvalidEnum,
    OutOfRange,
    InvalidArguments,
    NotFound,
    BurpNotRunning,
    ProjectNotRunning,
    ProjectRequired,
    NotSupported,
    RaijinUnreachable,
    ToolFailed,
    ConfigError,
    Internal,
}

impl Code {
    /// Whether the caller can fix the call; false for failures the call itself does not cause.
    pub fn retryable(self) -> bool {
        !matches!(
            self,
            Self::NotSupported
                | Self::RaijinUnreachable
                | Self::ToolFailed
                | Self::ConfigError
                | Self::Internal
        )
    }
}

/// One error result, boxed so `Result<_, ToolError>` stays small; fields are read through `Deref`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ToolError(Box<Envelope>);

impl Deref for ToolError {
    type Target = Envelope;

    fn deref(&self) -> &Envelope {
        &self.0
    }
}

/// The envelope's fields, in its field order; empty fields are left out.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Envelope {
    pub error: String,
    pub code: Code,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub got: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub did_you_mean: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<String>,
    pub retryable: bool,
    /// A call to make first: `{"do": ...}` goes to `run`, `{"guide": {...}}` holds `guide`'s arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub see: Option<Value>,
}

impl ToolError {
    /// An error with `code`; `error` ends as a sentence (a `.` is added when it ends in none, also
    /// after a closing parenthesis), and a non-retryable one says so at the end.
    pub fn new(code: Code, error: impl Into<String>) -> Self {
        let mut error = error.into().trim_end().to_owned();
        if !error.ends_with(['.', '!', '?']) {
            error.push('.');
        }
        if !code.retryable() {
            error.push_str(FINAL_SENTENCE);
        }
        Self(Box::new(Envelope {
            error,
            code,
            param: None,
            got: None,
            expected: None,
            allowed: Vec::new(),
            did_you_mean: Vec::new(),
            retry: None,
            example: None,
            usage: None,
            retryable: code.retryable(),
            see: None,
        }))
    }

    pub fn param(mut self, param: impl Into<String>) -> Self {
        self.0.param = Some(param.into());
        self
    }

    pub fn got(mut self, got: Value) -> Self {
        self.0.got = Some(got);
        self
    }

    pub fn expected(mut self, expected: impl Into<String>) -> Self {
        self.0.expected = Some(expected.into());
        self
    }

    pub fn allowed(mut self, allowed: Vec<Value>) -> Self {
        self.0.allowed = allowed;
        self
    }

    pub fn did_you_mean(mut self, names: Vec<String>) -> Self {
        self.0.did_you_mean = names;
        self
    }

    pub fn retry(mut self, call: Value) -> Self {
        self.0.retry = Some(call);
        self
    }

    pub fn example(mut self, call: Value) -> Self {
        self.0.example = Some(call);
        self
    }

    pub fn usage(mut self, usage: impl Into<String>) -> Self {
        self.0.usage = Some(usage.into());
        self
    }

    /// `call`: a `run` call (`{"do": ...}`) or a guide call ([`guide_call`]).
    pub fn see(mut self, call: Value) -> Self {
        self.0.see = Some(call);
        self
    }

    /// Without `example` (and `retry`): for errors where no call shape helps, such as `guide`'s.
    pub fn clear_example(mut self) -> Self {
        self.0.example = None;
        self.0.retry = None;
        self
    }

    /// The envelope as JSON.
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"error": self.error}))
    }

    /// An error result holding the envelope as one text block.
    pub fn into_result(self) -> CallToolResult {
        CallToolResult::error(vec![ContentBlock::text(self.to_value().to_string())])
    }
}

/// `result` with `notes` (what the server changed in the call) in its `notes` array. Only a result
/// that is one text block holding a JSON object takes them: `notes` is added, or appended to when it
/// is already an array. A text block that is not JSON at all gets them as a leading `note: ...`
/// line; any other result is returned as is. Same rule as the extension's `ToolArgs.withNotes`.
pub fn with_notes(mut result: CallToolResult, notes: &[String]) -> CallToolResult {
    if notes.is_empty() || result.content.len() != 1 {
        return result;
    }
    let Some(text) = result.content[0].as_text() else {
        return result;
    };
    let mut object = match serde_json::from_str::<Value>(&text.text) {
        Ok(Value::Object(object)) => object,
        Ok(_) => return result,
        // Plain text (a playbook, the overview): the notes go in front of it.
        Err(_) => {
            let prefixed = format!("note: {}\n\n{}", notes.join("; "), text.text);
            result.content[0] = ContentBlock::text(prefixed);
            return result;
        }
    };
    match object.get_mut("notes") {
        None => {
            object.insert("notes".to_owned(), json!(notes));
        }
        Some(Value::Array(existing)) => existing.extend(notes.iter().map(|n| json!(n))),
        Some(_) => return result,
    }
    result.content[0] = ContentBlock::text(Value::Object(object).to_string());
    result
}

/// `result` with its warnings also in `notes` (the old fields stay): `scope_warning` and
/// `headers_warning` strings, each `warnings` entry (a `{project, error}` object as
/// `"<project>: <error>"`, another object as compact JSON) and every `<x>_clamped_to` field as
/// `"<x> clamped to <value>"`. A note already present is not added twice. Same rule as the
/// extension's `ToolArgs.mirrorWarnings`.
pub fn mirror_warnings(result: CallToolResult) -> CallToolResult {
    if result.content.len() != 1 {
        return result;
    }
    // A full parse of every result (history bodies can be megabytes) only to find no warning
    // would cost more than the warnings are worth.
    let Some(text) = result.content[0].as_text() else {
        return result;
    };
    if !["_warning", "\"warnings\"", "_clamped_to"]
        .iter()
        .any(|hint| text.text.contains(hint))
    {
        return result;
    }
    let Ok(Value::Object(object)) = serde_json::from_str::<Value>(&text.text) else {
        return result;
    };
    let mut found = Vec::new();
    for key in ["scope_warning", "headers_warning"] {
        if let Some(Value::String(s)) = object.get(key) {
            found.push(s.clone());
        }
    }
    for warning in object
        .get("warnings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        found.push(match warning {
            Value::String(s) => s.clone(),
            Value::Object(w) => match (
                w.get("project").and_then(Value::as_str),
                w.get("error").and_then(Value::as_str),
            ) {
                (Some(project), Some(error)) if w.len() == 2 => format!("{project}: {error}"),
                _ => warning.to_string(),
            },
            other => other.to_string(),
        });
    }
    for (key, value) in &object {
        if let Some(what) = key.strip_suffix("_clamped_to") {
            found.push(format!("{what} clamped to {value}"));
        }
    }
    let existing: Vec<&str> = object
        .get("notes")
        .and_then(Value::as_array)
        .map(|n| n.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut fresh: Vec<String> = Vec::new();
    for note in found {
        if !existing.contains(&note.as_str()) && !fresh.contains(&note) {
            fresh.push(note);
        }
    }
    with_notes(result, &fresh)
}

/// `{"guide":{}}`, or `{"guide":{"topic":t}}`: a `see` that points at `guide`.
pub fn guide_call(topic: Option<&str>) -> Value {
    match topic {
        Some(t) => json!({"guide": {"topic": t}}),
        None => json!({"guide": {}}),
    }
}

/// Prefixes clients put before a tool name (`mcp__raijin__history_list`, `raijin.history_list`).
const SERVER_PREFIXES: [&str; 5] = [
    "mcp__raijin__",
    "raijin.",
    "raijin:",
    "raijin/",
    "functions.",
];

/// `name` without a server prefix ([`SERVER_PREFIXES`], any case), when it has one and something
/// follows it. Same list as the extension's `ToolNames.stripServerPrefix`.
pub fn strip_server_prefix(name: &str) -> Option<&str> {
    SERVER_PREFIXES.iter().find_map(|prefix| {
        let head = name.get(..prefix.len())?;
        let rest = &name[prefix.len()..];
        (head.eq_ignore_ascii_case(prefix) && !rest.trim().is_empty()).then_some(rest)
    })
}

/// `s` trimmed and without one pair of matching surrounding quotes (`"`, `'` or a backtick), or
/// None when it is not quoted. Same rule as the extension's `ToolArgs.unquote`.
pub fn unquote(s: &str) -> Option<&str> {
    let t = s.trim();
    let first = t.chars().next()?;
    (t.chars().count() >= 2 && matches!(first, '"' | '\'' | '`') && t.ends_with(first))
        .then(|| &t[1..t.len() - 1])
}

/// Name normal form: trimmed, lowercase, `-`, `.`, `/` and spaces as `_`.
pub fn norm(name: &str) -> String {
    name.trim()
        .to_lowercase()
        .chars()
        .map(|c| {
            if matches!(c, '-' | '.' | '/' | ' ') {
                '_'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_envelope_keeps_its_field_order_and_marks_final_errors() {
        let e = ToolError::new(Code::MissingParameter, "x needs 'a'.")
            .param("a")
            .example(json!({"do": "x", "a": 1}));
        assert_eq!(
            e.to_value().to_string(),
            r#"{"error":"x needs 'a'.","code":"missing_parameter","param":"a","example":{"do":"x","a":1},"retryable":true}"#
        );
        let final_ = ToolError::new(Code::ToolFailed, "boom.");
        assert_eq!(final_.error, "boom. Do not resend this call unchanged.");
        assert!(!final_.retryable);
        let unpunctuated = ToolError::new(Code::ToolFailed, "known: main");
        assert_eq!(
            unpunctuated.error,
            "known: main. Do not resend this call unchanged."
        );
        assert!(
            ToolError::new(Code::NotFound, "x (y)")
                .error
                .ends_with("(y).")
        );
    }

    #[test]
    fn server_prefixes_are_stripped() {
        assert_eq!(
            strip_server_prefix("mcp__raijin__history_list"),
            Some("history_list")
        );
        assert_eq!(
            strip_server_prefix("Raijin.scope.check"),
            Some("scope.check")
        );
        assert_eq!(strip_server_prefix("raijin."), None);
        assert_eq!(strip_server_prefix("history_list"), None);
    }

    #[test]
    fn warnings_are_mirrored_into_notes_once() {
        let result = CallToolResult::success(vec![ContentBlock::text(
            r#"{"warnings":[{"project":"p","error":"bad"},"w"],"limit_clamped_to":5,"notes":["w"]}"#,
        )]);
        let mirrored = mirror_warnings(result);
        let value: Value =
            serde_json::from_str(&mirrored.content[0].as_text().expect("text").text).expect("json");
        assert_eq!(value["notes"], json!(["w", "p: bad", "limit clamped to 5"]));
    }

    #[test]
    fn notes_join_a_json_object_result_or_lead_plain_text() {
        let plain = CallToolResult::success(vec![ContentBlock::text("not json")]);
        let led = with_notes(plain, &["n".to_owned(), "m".to_owned()]);
        assert_eq!(
            led.content[0].as_text().map(|t| t.text.as_str()),
            Some("note: n; m\n\nnot json")
        );
        let array = CallToolResult::success(vec![ContentBlock::text("[1]")]);
        assert_eq!(with_notes(array.clone(), &["n".to_owned()]), array);
        let object = CallToolResult::success(vec![ContentBlock::text(r#"{"a":1,"notes":["x"]}"#)]);
        let noted = with_notes(object, &["y".to_owned()]);
        assert_eq!(
            noted.content[0].as_text().map(|t| t.text.as_str()),
            Some(r#"{"a":1,"notes":["x","y"]}"#)
        );
    }

    #[test]
    fn names_normalise_case_and_separators() {
        assert_eq!(norm(" History.List "), "history_list");
        assert_eq!(norm("Burp-Down"), "burp_down");
        assert_eq!(norm("history/list"), "history_list");
    }
}
