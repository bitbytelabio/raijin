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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub see: Option<String>,
}

impl ToolError {
    /// An error with `code`; `error` ends as a sentence (a `.` is added when it ends in none), and
    /// a non-retryable one says so at the end.
    pub fn new(code: Code, error: impl Into<String>) -> Self {
        let mut error = error.into().trim_end().to_owned();
        if !error.ends_with(['.', '!', '?', ')']) {
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

    pub fn see(mut self, see: impl Into<String>) -> Self {
        self.0.see = Some(see.into());
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
/// is already an array; any other result is returned as is.
pub fn with_notes(mut result: CallToolResult, notes: &[String]) -> CallToolResult {
    if notes.is_empty() || result.content.len() != 1 {
        return result;
    }
    let Some(text) = result.content[0].as_text() else {
        return result;
    };
    let Ok(Value::Object(mut object)) = serde_json::from_str::<Value>(&text.text) else {
        return result;
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

/// Name normal form: trimmed, lowercase, `-`, `.` and spaces as `_`.
pub fn norm(name: &str) -> String {
    name.trim()
        .to_lowercase()
        .chars()
        .map(|c| if matches!(c, '-' | '.' | ' ') { '_' } else { c })
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
    }

    #[test]
    fn notes_join_a_json_object_result_only() {
        let plain = CallToolResult::success(vec![ContentBlock::text("not json")]);
        let same = with_notes(plain.clone(), &["n".to_owned()]);
        assert_eq!(same, plain);
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
    }
}
