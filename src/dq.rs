//! DQ v1 JSON and authorization contracts, independent of registry persistence.
//!
//! Pattern adaptation rejects constructs without a verified Java equivalent.

use crate::{
    compatibility::{instant, java_pattern},
    config::DqSettings,
    util::{java_is_blank, sha256_hex},
};
use bigdecimal::BigDecimal;
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::{collections::BTreeSet, str::FromStr};

pub const DISPATCH_PAGE_BYTES: usize = 1024 * 1024;
const RECORD_BYTES: usize = 65_536;
pub(crate) const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}")]
pub struct DqError {
    pub status: u16,
    pub code: String,
}

impl DqError {
    fn new(status: u16, code: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
        }
    }
}

type Result<T> = std::result::Result<T, DqError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DqPrincipal {
    pub actor: String,
    pub roles: BTreeSet<String>,
    pub scopes: BTreeSet<String>,
}

impl DqPrincipal {
    pub fn internal() -> Self {
        Self {
            actor: "octopus-runtime".into(),
            roles: ["service".into()].into(),
            scopes: ["*".into()].into(),
        }
    }

    pub fn permits(&self, scope: &str) -> bool {
        self.scopes.contains("*") || self.scopes.contains(scope)
    }

    pub fn require_role(&self, allowed: &BTreeSet<String>) -> Result<()> {
        if self.roles.is_disjoint(allowed) {
            Err(DqError::new(403, "forbidden_role"))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DqOutbox {
    pub id: String,
    pub topic: String,
    pub key: String,
    pub payload: Value,
    pub owner: String,
    pub token: String,
    pub fence: i64,
}

pub fn dispatch_page(items: &[Value]) -> Result<Value> {
    let mut size = 12usize;
    let mut selected = Vec::new();
    for item in items {
        let length = item.to_string().len();
        let next = size
            .saturating_add(length)
            .saturating_add(usize::from(!selected.is_empty()));
        if next > DISPATCH_PAGE_BYTES {
            if selected.is_empty() {
                return Err(DqError::new(503, "dispatch_item_too_large"));
            }
            break;
        }
        selected.push(item.clone());
        size = next;
    }
    Ok(json!({"items": selected}))
}

fn decimal(value: &Value) -> Option<BigDecimal> {
    value
        .as_number()
        .and_then(|number| BigDecimal::from_str(&number.to_string()).ok())
        // Java BigDecimal uses a signed 32-bit scale, even for zero. Reject
        // unrepresentable input before normalization can hide that overflow.
        .filter(|number| i32::try_from(number.as_bigint_and_exponent().1).is_ok())
}

fn canonical_number(value: &Value) -> Result<String> {
    let number = decimal(value)
        .ok_or_else(|| DqError::new(400, "invalid_number"))?
        .normalized();
    let (digits, scale) = number.as_bigint_and_exponent();
    let precision = digits.to_str_radix(10).trim_start_matches('-').len();
    if scale.unsigned_abs() > 65_536 || precision > 65_536 {
        return Err(DqError::new(413, "number_too_large"));
    }
    // Check the scale before plain rendering, which otherwise could allocate
    // an attacker-selected exponent's worth of zeroes.
    Ok(number.to_plain_string())
}

fn append(output: &mut String, text: &str, limit: usize) -> Result<()> {
    if text.len() > limit.saturating_sub(output.len()) {
        return Err(DqError::new(413, "record_too_large"));
    }
    output.push_str(text);
    Ok(())
}

fn write_string(value: &str, output: &mut String, limit: usize) -> Result<()> {
    if value.len().saturating_add(2) > limit.saturating_sub(output.len()) {
        return Err(DqError::new(413, "record_too_large"));
    }
    append(output, "\"", limit)?;
    let mut start = 0;
    for (index, character) in value.char_indices() {
        let escaped = match character {
            '"' => r#"\""#,
            '\\' => r"\\",
            '\u{08}' => r"\b",
            '\u{0c}' => r"\f",
            '\n' => r"\n",
            '\r' => r"\r",
            '\t' => r"\t",
            '\u{2028}' => r"\u2028",
            '\u{2029}' => r"\u2029",
            character if character <= '\u{1f}' => {
                append(output, &value[start..index], limit)?;
                append(output, &format!("\\u{:04x}", u32::from(character)), limit)?;
                start = index + 1;
                continue;
            }
            _ => continue,
        };
        append(output, &value[start..index], limit)?;
        append(output, escaped, limit)?;
        start = index + character.len_utf8();
    }
    append(output, &value[start..], limit)?;
    append(output, "\"", limit)
}

fn write_canonical(value: &Value, depth: usize, output: &mut String, limit: usize) -> Result<()> {
    if depth > 128 {
        return Err(DqError::new(400, "json_depth_exceeded"));
    }
    match value {
        Value::Number(_) => append(output, &canonical_number(value)?, limit)?,
        Value::String(value) => write_string(value, output, limit)?,
        Value::Array(values) => {
            append(output, "[", limit)?;
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    append(output, ",", limit)?;
                }
                write_canonical(item, depth + 1, output, limit)?;
            }
            append(output, "]", limit)?;
        }
        Value::Object(values) => {
            append(output, "{", limit)?;
            if values.len() > limit.saturating_sub(output.len()) / 5 {
                return Err(DqError::new(413, "record_too_large"));
            }
            let mut entries: Vec<_> = values.iter().collect();
            // UTF-8 lexicographic ordering has the same order as Unicode
            // scalar values, unlike Java's default UTF-16 String ordering.
            entries.sort_by_key(|(key, _)| *key);
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index != 0 {
                    append(output, ",", limit)?;
                }
                write_string(key, output, limit)?;
                append(output, ":", limit)?;
                write_canonical(item, depth + 1, output, limit)?;
            }
            append(output, "}", limit)?;
        }
        _ => append(output, &value.to_string(), limit)?,
    }
    Ok(())
}

pub fn canonical(value: &Value) -> Result<String> {
    canonical_with_limit(value, MAX_ARTIFACT_BYTES)
}

pub(crate) fn canonical_with_limit(value: &Value, limit: usize) -> Result<String> {
    let mut output = String::new();
    write_canonical(value, 0, &mut output, limit)?;
    Ok(output)
}

pub fn sha256(value: &Value) -> Result<String> {
    Ok(sha256_hex(canonical_with_limit(value, RECORD_BYTES)?))
}
pub fn digest(value: &str) -> String {
    sha256_hex(value)
}

pub fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value
        .get(name)
        .ok_or_else(|| DqError::new(400, format!("missing_{name}")))
}
pub fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    optional(value, name).ok_or_else(|| DqError::new(400, format!("invalid_{name}")))
}
pub fn optional<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
    value.get(name).and_then(Value::as_str)
}

fn integer(value: &Value) -> Option<i64> {
    let number = decimal(value)?.normalized();
    let (digits, scale) = number.as_bigint_and_exponent();
    if !(-19..=0).contains(&scale) || digits.to_str_radix(10).trim_start_matches('-').len() > 19 {
        return None;
    }
    number.to_plain_string().parse().ok()
}
pub fn long(value: &Value, name: &str) -> Result<i64> {
    value
        .get(name)
        .and_then(integer)
        .ok_or_else(|| DqError::new(400, format!("invalid_{name}")))
}
pub fn int(value: &Value, name: &str) -> Result<i32> {
    long(value, name)
        .ok()
        .and_then(|n| i32::try_from(n).ok())
        .ok_or_else(|| DqError::new(400, format!("invalid_{name}")))
}
pub fn identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
}
pub fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn scope(parameters: &Value) -> Result<&str> {
    text(parameters, "authorized_scope")
}

pub fn scoped(principal: &DqPrincipal, request: &Value, settings: &DqSettings) -> Result<()> {
    if text(request, "installation_id")? != settings.installation_id
        || text(request, "namespace")? != settings.namespace
    {
        return Err(DqError::new(403, "forbidden_installation"));
    }
    let requested = match optional(request, "authorized_scope") {
        Some(scope) => Some(scope),
        None => request.get("parameters").map(scope).transpose()?,
    };
    if requested.is_some_and(|scope| !principal.permits(scope)) {
        return Err(DqError::new(403, "forbidden_scope"));
    }
    Ok(())
}
pub fn bounded(value: &Value) -> Result<()> {
    canonical_with_limit(value, RECORD_BYTES).map(drop)
}

/// Clock is explicit for deterministic admission tests. Java's extreme Instant
/// range beyond PostgreSQL/Chrono remains an explicit compatibility boundary.
pub fn deadline(request: &Value, now: DateTime<Utc>) -> Result<DateTime<Utc>> {
    match request.get("deadline_at") {
        None => now
            .checked_add_signed(Duration::seconds(3600))
            .ok_or_else(|| DqError::new(400, "invalid_deadline")),
        Some(value) => value
            .as_str()
            .and_then(|value| instant::parse(value).ok())
            .ok_or_else(|| DqError::new(400, "invalid_deadline")),
    }
}

fn equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(_), Value::Number(_)) => decimal(left)
            .zip(decimal(right))
            .is_some_and(|(a, b)| a == b),
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(k, v)| b.get(k).is_some_and(|other| equal(v, other)))
        }
        _ => left == right,
    }
}

const SCHEMA_KEYWORDS: &[&str] = &[
    "$schema",
    "$id",
    "title",
    "description",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "enum",
    "const",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "pattern",
    "items",
    "minItems",
    "maxItems",
    "default",
];

pub fn check_schema(schema: &Value) -> Result<()> {
    check_schema_at(schema, 0)
}
fn check_schema_at(schema: &Value, depth: usize) -> Result<()> {
    let invalid = || DqError::new(400, "invalid_parameter_schema");
    let obj = schema.as_object().ok_or_else(invalid)?;
    if depth > 16 {
        return Err(DqError::new(400, "schema_depth_exceeded"));
    }
    if obj
        .keys()
        .any(|key| !SCHEMA_KEYWORDS.contains(&key.as_str()))
    {
        return Err(DqError::new(400, "unsupported_schema_keyword"));
    }
    for name in ["$schema", "$id", "title", "description"] {
        if obj.get(name).is_some_and(|v| !v.is_string()) {
            return Err(invalid());
        }
    }
    if obj
        .get("$schema")
        .is_some_and(|v| v.as_str() != Some("https://json-schema.org/draft/2020-12/schema"))
    {
        return Err(invalid());
    }
    if obj.get("type").is_some_and(|v| {
        !v.as_str().is_some_and(|s| {
            [
                "object", "array", "string", "boolean", "integer", "number", "null",
            ]
            .contains(&s)
        })
    }) {
        return Err(invalid());
    }
    if obj
        .get("additionalProperties")
        .is_some_and(|v| !v.is_boolean())
    {
        return Err(invalid());
    }
    if let Some(properties) = obj.get("properties") {
        for item in properties.as_object().ok_or_else(invalid)?.values() {
            check_schema_at(item, depth + 1)?;
        }
    }
    for name in ["required", "enum"] {
        if let Some(value) = obj.get(name) {
            let values = value.as_array().ok_or_else(invalid)?;
            if (name == "required" && values.iter().any(|v| !v.is_string()))
                || (name == "enum" && values.is_empty())
                || values
                    .iter()
                    .enumerate()
                    .any(|(i, v)| values[..i].iter().any(|prior| equal(prior, v)))
            {
                return Err(invalid());
            }
        }
    }
    for name in ["minimum", "maximum"] {
        if obj.get(name).is_some_and(|v| decimal(v).is_none()) {
            return Err(invalid());
        }
    }
    for name in ["minLength", "maxLength", "minItems", "maxItems"] {
        if obj.get(name).is_some_and(|v| {
            integer(v)
                .and_then(|n| i32::try_from(n).ok())
                .is_none_or(|n| n < 0)
        }) {
            return Err(invalid());
        }
    }
    if let Some(items) = obj.get("items") {
        check_schema_at(items, depth + 1)?;
    }
    if let Some(pattern) = obj.get("pattern") {
        let pattern = pattern.as_str().ok_or_else(invalid)?;
        if java_pattern::compile(pattern).is_err() {
            return Err(DqError::new(400, "invalid_schema_pattern"));
        }
    }
    Ok(())
}

pub fn validate(schema: &Value, value: &Value) -> Result<()> {
    let invalid = || DqError::new(400, "invalid_parameters");
    let valid_type = optional(schema, "type").is_none_or(|kind| match kind {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => decimal(value).is_some_and(|n| n.normalized().as_bigint_and_exponent().1 <= 0),
        "number" => value.is_number(),
        "null" => value.is_null(),
        _ => false,
    });
    if !valid_type
        || schema
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|v| !v.iter().any(|item| equal(item, value)))
        || schema.get("const").is_some_and(|item| !equal(item, value))
    {
        return Err(invalid());
    }
    if let Some(obj) = value.as_object() {
        let properties = schema.get("properties").and_then(Value::as_object);
        if schema
            .get("required")
            .and_then(Value::as_array)
            .is_some_and(|names| {
                names
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|name| !obj.contains_key(name))
            })
            || (schema.get("additionalProperties") == Some(&Value::Bool(false))
                && obj
                    .keys()
                    .any(|key| properties.is_none_or(|p| !p.contains_key(key))))
        {
            return Err(invalid());
        }
        if let Some(properties) = properties {
            for (key, rule) in properties {
                if let Some(item) = obj.get(key) {
                    validate(rule, item)?;
                }
            }
        }
    }
    let outside_bounds = |size: usize, min: &str, max: &str| {
        schema
            .get(min)
            .and_then(integer)
            .is_some_and(|n| (size as u64) < n as u64)
            || schema
                .get(max)
                .and_then(integer)
                .is_some_and(|n| (size as u64) > n as u64)
    };
    if let Some(text) = value.as_str() {
        if outside_bounds(text.chars().count(), "minLength", "maxLength") {
            return Err(invalid());
        }
        if let Some(pattern) = optional(schema, "pattern") {
            let pattern = java_pattern::compile(pattern).map_err(|_| invalid())?;
            if !pattern.is_match(text).map_err(|_| invalid())? {
                return Err(invalid());
            }
        }
    }
    if let Some(number) = decimal(value) {
        if schema
            .get("minimum")
            .and_then(decimal)
            .is_some_and(|min| number < min)
            || schema
                .get("maximum")
                .and_then(decimal)
                .is_some_and(|max| number > max)
        {
            return Err(invalid());
        }
    }
    if let Some(values) = value.as_array() {
        if outside_bounds(values.len(), "minItems", "maxItems") {
            return Err(invalid());
        }
        if let Some(rule) = schema.get("items") {
            for item in values {
                validate(rule, item)?;
            }
        }
    }
    Ok(())
}

pub fn validate_artifacts(
    refs: &Value,
    settings: &DqSettings,
    run_id: &str,
    attempt_id: Option<&str>,
    input: bool,
) -> Result<()> {
    let values = refs
        .as_array()
        .ok_or_else(|| DqError::new(400, "invalid_artifacts"))?;
    if values.len() > 16 {
        return Err(DqError::new(400, "too_many_artifacts"));
    }
    for item in values {
        scoped(&DqPrincipal::internal(), item, settings)?;
        if !identifier(text(item, "artifact_id")?)
            || !hash(text(item, "sha256")?)
            || java_is_blank(text(item, "version_id")?)
            || java_is_blank(text(item, "etag")?)
            || long(item, "size_bytes")? < 0
        {
            return Err(DqError::new(400, "invalid_artifact_reference"));
        }
        let prefix = format!(
            "s3://{}/{}/{}/",
            settings.artifact_bucket, settings.installation_id, settings.namespace
        );
        let permitted = if input {
            format!("{prefix}inputs/")
        } else {
            format!(
                "{prefix}runs/{run_id}/attempts/{}/",
                attempt_id.unwrap_or("")
            )
        };
        let uri = text(item, "uri")?;
        if !uri.starts_with(&permitted) || uri.contains("..") || uri.contains(['?', '#', '@']) {
            return Err(DqError::new(403, "forbidden_artifact_reference"));
        }
        if !input
            && (optional(item, "producer_run_id") != Some(run_id)
                || optional(item, "producer_attempt_id") != attempt_id)
        {
            return Err(DqError::new(403, "forbidden_artifact_producer"));
        }
    }
    Ok(())
}
