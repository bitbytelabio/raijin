//! Arguments of the gateway's own tools: read leniently (a number sent as a string, an enum value
//! in another case), checked against the tool's JSON Schema, and refused with an error that says
//! which parameter is wrong and shows a call that works.

use std::collections::BTreeSet;

use rmcp::model::JsonObject;
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

use super::error::{Code, ToolError};
use crate::util::{suggest, truncate_utf8};

/// `T`'s JSON Schema as a tool `inputSchema`: no `$schema`/`title`, always a `properties` object.
pub fn schema_of<T: JsonSchema>() -> JsonObject {
    let mut value = serde_json::to_value(schemars::schema_for!(T))
        .unwrap_or_else(|_| json!({"type": "object"}));
    if let Some(obj) = value.as_object_mut() {
        obj.remove("$schema");
        obj.remove("title");
        if !obj.contains_key("properties") {
            obj.insert("properties".to_owned(), json!({}));
        }
        return obj.clone();
    }
    Map::new()
}

/// What one schema definition accepts, with `$ref`, `anyOf`, `oneOf` and `allOf` folded in.
#[derive(Debug, Default)]
struct Shape<'a> {
    /// JSON types (`"integer"`, `"null"`, ...); empty accepts anything.
    types: BTreeSet<&'a str>,
    /// String values an `enum` or `const` allows.
    enums: Vec<String>,
    /// Some branch takes any string, so `enums` does not restrict.
    free_string: bool,
    minimum: Option<f64>,
    items: Option<&'a Value>,
}

impl Shape<'_> {
    fn has(&self, kind: &str) -> bool {
        self.types.contains(kind)
    }

    fn closed_enum(&self) -> bool {
        !self.enums.is_empty() && !self.free_string
    }
}

fn shape<'a>(root: &'a JsonObject, def: &'a Value) -> Shape<'a> {
    let mut s = Shape::default();
    collect(root, def, &mut s, 0);
    if s.types.is_empty() && !s.enums.is_empty() {
        s.types.insert("string");
    }
    s
}

fn collect<'a>(root: &'a JsonObject, def: &'a Value, s: &mut Shape<'a>, depth: usize) {
    let Some(obj) = def.as_object() else {
        return;
    };
    if depth > 8 {
        return;
    }
    if let Some(name) = obj
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|r| r.strip_prefix("#/$defs/"))
        && let Some(target) = root.get("$defs").and_then(|d| d.get(name))
    {
        collect(root, target, s, depth + 1);
    }
    let own: Vec<&str> = match obj.get("type") {
        Some(Value::String(t)) => vec![t.as_str()],
        Some(Value::Array(ts)) => ts.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    let restricted = obj.contains_key("enum") || obj.contains_key("const");
    if own.contains(&"string") && !restricted {
        s.free_string = true;
    }
    s.types.extend(own);
    if let Some(values) = obj.get("enum").and_then(Value::as_array) {
        s.enums
            .extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    if let Some(value) = obj.get("const").and_then(Value::as_str) {
        s.enums.push(value.to_owned());
    }
    if let Some(min) = obj.get("minimum").and_then(Value::as_f64) {
        s.minimum = Some(min);
    }
    if s.items.is_none() {
        s.items = obj.get("items");
    }
    for key in ["anyOf", "oneOf", "allOf"] {
        for branch in obj.get(key).and_then(Value::as_array).into_iter().flatten() {
            collect(root, branch, s, depth + 1);
        }
    }
}

/// Enum comparison key: lowercase, without `-`, `_`, `.` and spaces.
fn enum_key(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

fn is_integer_text(s: &str) -> bool {
    let digits = s.strip_prefix('-').unwrap_or(s);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

fn is_number_text(s: &str) -> bool {
    let body = s.strip_prefix('-').unwrap_or(s);
    let (mantissa, exponent) = match body.find(['e', 'E']) {
        Some(i) => (&body[..i], Some(&body[i + 1..])),
        None => (body, None),
    };
    let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = |p: &str| p.bytes().all(|b| b.is_ascii_digit());
    let mantissa_ok = (!int.is_empty() || !frac.is_empty()) && digits(int) && digits(frac);
    let exponent_ok = exponent.is_none_or(|e| {
        let e = e.strip_prefix(['+', '-']).unwrap_or(e);
        !e.is_empty() && digits(e)
    });
    mantissa_ok && exponent_ok
}

/// The scalar of a one-item array `v` when `s` takes a scalar and no array (noted), else `v`.
fn unwrap_single(name: &str, s: &Shape<'_>, mut v: Value, notes: &mut Vec<String>) -> Value {
    if let Value::Array(items) = &mut v
        && let [item @ (Value::String(_) | Value::Number(_) | Value::Bool(_))] =
            items.as_mut_slice()
        && !s.has("array")
        && ["string", "integer", "number", "boolean"]
            .iter()
            .any(|t| s.has(t))
    {
        notes.push(format!("read '{name}' from a one-item array"));
        return item.take();
    }
    v
}

/// `v` moved toward `s` where the meaning is clear; each noted change goes to `notes`.
fn coerce(
    name: &str,
    s: &Shape<'_>,
    root: &JsonObject,
    v: Value,
    notes: &mut Vec<String>,
) -> Value {
    let mut v = unwrap_single(name, s, v, notes);
    if let Value::String(text) = &v
        && !s.has("string")
    {
        let t = text.trim();
        if s.has("integer") && is_integer_text(t) {
            if let Ok(n) = t.parse::<i64>() {
                notes.push(format!(
                    "coerced '{name}' from string \"{text}\" to integer"
                ));
                v = json!(n);
            }
        } else if s.has("number") && is_number_text(t) {
            if let Ok(n) = t.parse::<f64>()
                && n.is_finite()
            {
                notes.push(format!("coerced '{name}' from string \"{text}\" to number"));
                v = t.parse::<i64>().map_or_else(|_| json!(n), |i| json!(i));
            }
        } else if s.has("boolean")
            && let Some(b) = bool_word(t)
        {
            notes.push(format!(
                "coerced '{name}' from string \"{text}\" to boolean"
            ));
            v = json!(b);
        } else if s.has("array")
            && let Ok(Value::Array(items)) = serde_json::from_str::<Value>(t)
        {
            v = Value::Array(items);
        }
    }
    let numeric = s.has("integer") || s.has("number");
    if let Value::Number(n) = &v
        && s.has("boolean")
        && !numeric
        && let Some(i @ (0 | 1)) = n.as_u64()
    {
        notes.push(format!("coerced '{name}' from {n} to boolean"));
        v = json!(i == 1);
    }
    if let Value::Number(n) = &v
        && s.has("string")
        && !numeric
    {
        notes.push(format!("coerced '{name}' from {n} to string"));
        v = json!(n.to_string());
    }
    if let Value::Number(n) = &v
        && s.has("integer")
        && !s.has("number")
        && !n.is_i64()
        && !n.is_u64()
        && let Some(f) = n.as_f64()
        && f.is_finite()
        && f.fract() == 0.0
        && f.abs() < 9.0e15
    {
        notes.push(format!("coerced '{name}' from {n} to integer"));
        #[allow(clippy::cast_possible_truncation)]
        let i = f as i64;
        v = json!(i);
    }
    if s.has("array") && !v.is_array() && !v.is_null() && !s.types.contains(kind(&v)) {
        let own_number = matches!(kind(&v), "integer") && s.has("number");
        if !own_number {
            v = Value::Array(vec![v]);
        }
    }
    if let Value::String(text) = &v
        && s.closed_enum()
        && !s.enums.iter().any(|e| e == text)
    {
        let hit_of = |t: &str| -> Option<&String> {
            if let Some(exact) = s.enums.iter().find(|e| *e == t) {
                return Some(exact);
            }
            let key = enum_key(t);
            let hits: Vec<&String> = s.enums.iter().filter(|e| enum_key(e) == key).collect();
            match hits[..] {
                [hit] => Some(hit),
                _ => None,
            }
        };
        if let Some(hit) = hit_of(text).or_else(|| super::error::unquote(text).and_then(hit_of)) {
            notes.push(format!("matched '{name}' \"{text}\" to \"{hit}\""));
            v = json!(hit);
        }
    }
    if let (Value::Array(items), Some(item_def)) = (&mut v, s.items) {
        let item_shape = shape(root, item_def);
        for item in items.iter_mut() {
            *item = coerce(name, &item_shape, root, item.take(), notes);
        }
    }
    v
}

/// The JSON kind of `v` as a schema `type`.
fn kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn fits(s: &Shape<'_>, v: &Value) -> bool {
    let k = kind(v);
    s.types.is_empty() || s.has(k) || (k == "integer" && s.has("number"))
}

/// A schema `minimum` as written: `0`, not `0.0`.
fn format_min(min: f64) -> String {
    if min.fract() == 0.0 && min.abs() < 9.0e15 {
        format!("{min:.0}")
    } else {
        min.to_string()
    }
}

fn quoted(values: &[String]) -> String {
    values
        .iter()
        .map(|v| format!("\"{v}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// What `s` accepts, in words: `integer ≥ 0`, `true or false`, `list of string`, ...
fn expected(root: &JsonObject, s: &Shape<'_>) -> String {
    if s.closed_enum() {
        return format!("one of {}", quoted(&s.enums));
    }
    let types: Vec<&str> = s.types.iter().copied().filter(|t| *t != "null").collect();
    let item = || {
        s.items
            .map_or_else(|| "values".to_owned(), |i| expected(root, &shape(root, i)))
    };
    match types[..] {
        ["integer"] => match s.minimum {
            Some(min) => format!("integer ≥ {}", format_min(min)),
            None => "integer".to_owned(),
        },
        ["number"] => "number".to_owned(),
        ["boolean"] => "true or false".to_owned(),
        ["string"] => "string".to_owned(),
        ["array"] => format!("list of {}", item()),
        ["array", "string"] => "string or list of strings".to_owned(),
        [] => "any value".to_owned(),
        _ => types.join(" or "),
    }
}

/// `v` shown in an error message, cut short.
fn shown(v: &Value) -> String {
    let text = v.to_string();
    if text.len() > 80 {
        format!("{}...", truncate_utf8(&text, 77))
    } else {
        text
    }
}

/// One-line call signature, required parameters first (marked `*`), e.g.
/// `history_show(ref*: string, max_body: integer ≥ 0, full: true or false)`.
pub fn usage(tool: &str, schema: &JsonObject) -> String {
    let empty = Map::new();
    let props = schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let required = required_of(schema);
    let mut names: Vec<&String> = props
        .keys()
        .filter(|k| required.contains(k.as_str()))
        .collect();
    names.extend(props.keys().filter(|k| !required.contains(k.as_str())));
    let parts: Vec<String> = names
        .into_iter()
        .map(|name| {
            let s = shape(schema, &props[name]);
            let text = if s.closed_enum() {
                s.enums
                    .iter()
                    .map(|e| format!("\"{e}\""))
                    .collect::<Vec<_>>()
                    .join("|")
            } else {
                expected(schema, &s)
            };
            let star = if required.contains(name.as_str()) {
                "*"
            } else {
                ""
            };
            format!("{name}{star}: {text}")
        })
        .collect();
    format!("{tool}({})", parts.join(", "))
}

/// Parameter names that mean the same thing across tools and the APIs agents know: an undeclared
/// name maps to the one member of its group a tool declares. The extension's table
/// (`ToolArgs.PARAM_SYNONYMS`, `param_synonyms` in the catalog); a test keeps the two equal.
pub const PARAM_SYNONYMS: &[&[&str]] = &[
    &[
        "count",
        "limit",
        "max",
        "max_results",
        "max_items",
        "size",
        "max_events",
        "max_matches",
    ],
    &["start_index", "offset", "skip"],
    &["pattern", "query", "q", "regex", "search", "search_pattern"],
    &["data", "input", "text", "value", "string"],
    &["url", "uri"],
    &["request", "raw_request"],
    &["response", "raw_response"],
];

/// The parameter of `props` that `key` means by [`PARAM_SYNONYMS`], when exactly one fits.
fn synonym<'a>(key: &str, props: &'a JsonObject) -> Option<&'a str> {
    let group = PARAM_SYNONYMS.iter().find(|g| g.contains(&key))?;
    let mut fits = props
        .keys()
        .filter(|p| p.as_str() != key && group.contains(&p.as_str()));
    let one = fits.next()?;
    fits.next().is_none().then_some(one.as_str())
}

/// Text a boolean parameter takes for `true`; [`FALSE_WORDS`] for `false`. The extension's
/// `ToolArgs.BOOLEAN_WORDS` (`boolean_words` in the catalog); a test keeps the two equal.
pub const TRUE_WORDS: &[&str] = &["true", "1", "yes", "on"];
pub const FALSE_WORDS: &[&str] = &["false", "0", "no", "off"];

/// The boolean `text` means by [`TRUE_WORDS`] and [`FALSE_WORDS`], trimmed and in any case.
pub fn bool_word(text: &str) -> Option<bool> {
    let t = text.trim().to_lowercase();
    if TRUE_WORDS.contains(&t.as_str()) {
        Some(true)
    } else if FALSE_WORDS.contains(&t.as_str()) {
        Some(false)
    } else {
        None
    }
}

/// A parameter name in the form tools declare: trimmed, without surrounding `*`, camelCase split
/// with `_`, lowercase, `-` and spaces as `_` (`maxResults` -> `max_results`, `Limit*` -> `limit`).
/// Same rule as the extension's `ToolArgs.canonicalParam`.
pub fn canonical_param(key: &str) -> String {
    let t = key.trim().trim_matches('*').trim();
    let mut out = String::with_capacity(t.len() + 4);
    let mut prev: Option<char> = None;
    for c in t.chars() {
        if c.is_uppercase() && prev.is_some_and(|p| p.is_lowercase() || p.is_ascii_digit()) {
            out.push('_');
        }
        out.extend(c.to_lowercase());
        prev = Some(c);
    }
    out.chars()
        .map(|c| if matches!(c, '-' | ' ') { '_' } else { c })
        .collect()
}

/// `args` with undeclared names that clearly mean a declared one renamed, each change noted: the
/// canonical form of a name ([`canonical_param`]), a boolean `regex` flag dropped where `pattern` is
/// always a regex, and a [`PARAM_SYNONYMS`] member whose value fits the target's type. A target
/// already set, or claimed by an earlier rename, is left alone, as is every name of a `destructive`
/// call: those go to `unknown_parameter`. Same rule as the extension's `ToolArgs.renameParams`.
fn rename_params(
    props: &JsonObject,
    schema: &JsonObject,
    args: JsonObject,
    destructive: bool,
) -> (JsonObject, Vec<String>) {
    let mut notes = Vec::new();
    if destructive || args.keys().all(|k| props.contains_key(k)) {
        return (args, notes);
    }
    let given: BTreeSet<String> = args.keys().cloned().collect();
    let mut claimed: BTreeSet<String> = BTreeSet::new();
    let mut out = Map::new();
    for (k, v) in args {
        if props.contains_key(&k) {
            out.insert(k, v);
            continue;
        }
        let c = canonical_param(&k);
        if props.contains_key(&c) && !given.contains(&c) && !claimed.contains(&c) {
            notes.push(format!("read '{k}' as '{c}'"));
            claimed.insert(c.clone());
            out.insert(c, v);
            continue;
        }
        if c == "regex" && v.is_boolean() && props.contains_key("pattern") {
            notes.push("dropped 'regex': 'pattern' is always a regex here".to_owned());
            continue;
        }
        if let Some(t) = synonym(&c, props)
            && !given.contains(t)
            && !claimed.contains(t)
        {
            let s = shape(schema, &props[t]);
            let coerced = coerce(t, &s, schema, v.clone(), &mut Vec::new());
            if fits(&s, &coerced) {
                notes.push(format!("read '{k}' as '{t}'"));
                claimed.insert(t.to_owned());
                out.insert(t.to_owned(), v);
                continue;
            }
        }
        out.insert(k, v);
    }
    (out, notes)
}

/// Whether `args` makes a call `schema` accepts: every required key set, every key declared, and
/// each value of the declared type, enum and minimum once read leniently.
pub fn call_fits(schema: &JsonObject, args: &JsonObject) -> bool {
    let empty = Map::new();
    let props = schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    required_of(schema).iter().all(|k| args.contains_key(*k))
        && args.iter().all(|(k, v)| {
            props.get(k).is_some_and(|def| {
                let s = shape(schema, def);
                let v = coerce(k, &s, schema, v.clone(), &mut Vec::new());
                check("", k, schema, &s, v).is_ok()
            })
        })
}

/// Most `allowed` values an error lists; [`MAX_DID_YOU_MEAN`] for `did_you_mean`.
const MAX_ALLOWED: usize = 20;
const MAX_DID_YOU_MEAN: usize = 5;

/// `values` capped at [`MAX_ALLOWED`]: the 5 closest to `got` first, then the rest in declared
/// order; true when some were left out.
fn capped_allowed(got: &str, values: &[String]) -> (Vec<String>, bool) {
    if values.len() <= MAX_ALLOWED {
        return (values.to_vec(), false);
    }
    let mut out: Vec<String> = suggest(got, values.iter().map(String::as_str), MAX_DID_YOU_MEAN)
        .into_iter()
        .map(str::to_owned)
        .collect();
    for v in values {
        if out.len() >= MAX_ALLOWED {
            break;
        }
        if !out.contains(v) {
            out.push(v.clone());
        }
    }
    (out, true)
}

/// `unknown_parameter` for the `unknown` keys of `arguments`, each with its nearest declared name
/// (looked up in [`canonical_param`] form); `retry`, a `run` call with them renamed, is offered when
/// `offer_retry` and every one has a distinct suggestion not already set.
fn unknown_parameter(
    tool: &str,
    props: &JsonObject,
    arguments: &JsonObject,
    unknown: &[&String],
    offer_retry: bool,
) -> ToolError {
    let targets: Vec<Option<&str>> = unknown
        .iter()
        .map(|k| {
            let c = canonical_param(k);
            synonym(&c, props).or_else(|| {
                suggest(&c, props.keys().map(String::as_str), 1)
                    .first()
                    .copied()
            })
        })
        .collect();
    let chosen: Vec<&str> = targets.iter().flatten().copied().collect();
    let distinct: BTreeSet<&str> = chosen.iter().copied().collect();
    let certain = offer_retry
        && chosen.len() == unknown.len()
        && distinct.len() == chosen.len()
        && chosen.iter().all(|t| !arguments.contains_key(*t));
    let message = match (unknown, targets.first().copied().flatten()) {
        ([one], Some(target)) => format!("{tool} has no parameter '{one}'; use '{target}'."),
        ([one], None) => {
            format!("{tool} has no parameter '{one}'; 'usage' lists every parameter.")
        }
        _ => {
            let listed: Vec<String> = unknown
                .iter()
                .zip(&targets)
                .map(|(k, t)| match t {
                    Some(t) => format!("'{k}' (use '{t}')"),
                    None => format!("'{k}'"),
                })
                .collect();
            format!(
                "{tool} has no parameters {}; 'usage' lists every parameter.",
                listed.join(", ")
            )
        }
    };
    let mut error = ToolError::new(Code::UnknownParameter, message).did_you_mean(
        distinct
            .iter()
            .take(MAX_DID_YOU_MEAN)
            .map(|t| (*t).to_owned())
            .collect(),
    );
    if let Some(first) = unknown.first() {
        error = error.param(first.as_str());
    }
    if certain {
        let mut call = Map::new();
        call.insert("do".to_owned(), json!(tool));
        for (k, v) in arguments {
            let renamed = unknown
                .iter()
                .position(|u| *u == k)
                .and_then(|i| targets[i])
                .unwrap_or(k);
            call.insert(renamed.to_owned(), v.clone());
        }
        error = error.retry(Value::Object(call));
    }
    error
}

/// `value` of parameter `key` (shape `s`) when its type, enum and minimum allow it.
fn check(
    tool: &str,
    key: &str,
    schema: &JsonObject,
    s: &Shape<'_>,
    value: Value,
) -> Result<Value, ToolError> {
    let item_mismatch = match (&value, s.items) {
        (Value::Array(items), Some(item_def)) => {
            let item_shape = shape(schema, item_def);
            items.iter().any(|i| !fits(&item_shape, i))
        }
        _ => false,
    };
    if !fits(s, &value) || item_mismatch {
        let expected = expected(schema, s);
        return Err(ToolError::new(
            Code::InvalidType,
            format!("{tool}: '{key}' must be {expected}, got {}.", shown(&value)),
        )
        .param(key)
        .got(value)
        .expected(expected));
    }
    if let Value::String(text) = &value
        && s.closed_enum()
        && !s.enums.contains(text)
    {
        let (shown_values, cut) = capped_allowed(text, &s.enums);
        let message = format!(
            "{tool}: '{key}' is not one of the {} allowed values (see 'allowed'), got \"{text}\".",
            s.enums.len()
        );
        let mut error = ToolError::new(Code::InvalidEnum, message)
            .param(key)
            .got(value)
            .allowed(shown_values.iter().map(|e| json!(e)).collect());
        if cut {
            error = error.see(super::error::guide_call(Some(tool)));
        }
        return Err(error);
    }
    if let (Some(min), Some(n)) = (s.minimum, value.as_f64())
        && n < min
    {
        return Err(ToolError::new(
            Code::OutOfRange,
            format!(
                "{tool}: '{key}' must be an integer ≥ {}, got {value}.",
                format_min(min)
            ),
        )
        .param(key)
        .got(value));
    }
    Ok(value)
}

fn required_of(schema: &JsonObject) -> BTreeSet<&str> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

/// Reads `arguments` as `T` for `tool`: unknown keys, wrong types, values outside an enum or a
/// minimum and missing required keys are refused with a [`ToolError`] carrying `usage` and
/// `example`; strings that clearly mean a number or boolean, and enum values in another case, are
/// read as such and reported in the returned notes, as are names [`rename_params`] reads as a
/// declared one. `retry` (a corrected `run` call) is offered for a misspelled parameter unless the
/// tool is `destructive` or `example` is not a `run` call.
pub fn parse_args<T: DeserializeOwned + JsonSchema>(
    tool: &str,
    arguments: Option<JsonObject>,
    example: &Value,
    destructive: bool,
) -> Result<(T, Vec<String>), ToolError> {
    let arguments = arguments.unwrap_or_default();
    let schema = schema_of::<T>();
    let empty = Map::new();
    let props = schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let usage_line = usage(tool, &schema);
    let fail = |e: ToolError| e.usage(usage_line.clone()).example(example.clone());

    let (arguments, mut notes) = rename_params(props, &schema, arguments, destructive);
    let unknown: Vec<&String> = arguments
        .keys()
        .filter(|k| !props.contains_key(*k))
        .collect();
    if !unknown.is_empty() {
        let offer_retry = !destructive && example.get("do").is_some();
        return Err(fail(unknown_parameter(
            tool,
            props,
            &arguments,
            &unknown,
            offer_retry,
        )));
    }

    let mut checked = Map::new();
    let required = required_of(&schema);
    for (key, value) in arguments {
        let s = shape(&schema, &props[&key]);
        // Clients that fill every declared property send null for the ones they leave unset.
        if value.is_null() && !s.has("null") && !required.contains(key.as_str()) {
            continue;
        }
        let value = coerce(&key, &s, &schema, value, &mut notes);
        checked.insert(
            key.clone(),
            check(tool, &key, &schema, &s, value).map_err(fail)?,
        );
    }

    if let Some(missing) = required_of(&schema)
        .into_iter()
        .find(|k| !checked.contains_key(*k))
    {
        return Err(fail(
            ToolError::new(Code::MissingParameter, format!("{tool} needs '{missing}'."))
                .param(missing),
        ));
    }

    serde_json::from_value(Value::Object(checked))
        .map(|parsed| (parsed, notes))
        .map_err(|e| {
            fail(ToolError::new(
                Code::InvalidArguments,
                format!("{tool}: these arguments do not fit its parameters ({e}); see 'usage'."),
            ))
        })
}
