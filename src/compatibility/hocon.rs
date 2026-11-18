//! Bounded HOCON reader for coordinator configuration. Unsupported syntax is
//! rejected rather than silently reverting to defaults.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Scalar(String),
    List(Vec<String>),
    Reference { name: String, optional: bool },
    Null,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid or unsupported HOCON configuration at line {line}")]
pub struct Error {
    pub line: usize,
}

struct Parser<'a> {
    input: &'a str,
    at: usize,
    line: usize,
    values: BTreeMap<String, Vec<Value>>,
}

impl Parser<'_> {
    fn fail<T>(&self) -> Result<T, Error> {
        Err(Error { line: self.line })
    }
    fn rest(&self) -> &str {
        &self.input[self.at..]
    }
    fn take(&mut self) -> Option<char> {
        let c = self.rest().chars().next()?;
        self.at += c.len_utf8();
        self.line += usize::from(c == '\n');
        Some(c)
    }
    fn spaces(&mut self, newline: bool) {
        loop {
            while self.rest().starts_with([' ', '\t', '\r'])
                || (newline && self.rest().starts_with('\n'))
            {
                self.take();
            }
            if self.rest().starts_with('#') || self.rest().starts_with("//") {
                while !self.rest().is_empty() && !self.rest().starts_with('\n') {
                    self.take();
                }
            } else {
                return;
            }
        }
    }
    fn quoted(&mut self) -> Result<String, Error> {
        if self.rest().starts_with("\"\"\"") {
            self.at += 3;
            let Some(end) = self.rest().find("\"\"\"") else {
                return self.fail();
            };
            let text = self.rest()[..end].to_owned();
            self.line += text.matches('\n').count();
            self.at += end + 3;
            return Ok(text);
        }
        let start = self.at;
        self.take();
        let mut escaped = false;
        while let Some(c) = self.take() {
            if c == '\n' {
                return self.fail();
            }
            if c == '"' && !escaped {
                return serde_json::from_str(&self.input[start..self.at])
                    .map_err(|_| Error { line: self.line });
            }
            escaped = c == '\\' && !escaped;
        }
        self.fail()
    }
    fn key(&mut self) -> Result<String, Error> {
        let mut parts = Vec::new();
        loop {
            self.spaces(false);
            let part = if self.rest().starts_with('"') {
                let value = self.quoted()?;
                // Literal dots in quoted path segments cannot map to an
                // AppConfig field. Reject instead of flattening ambiguously.
                if value.contains('.') {
                    return self.fail();
                }
                value
            } else {
                let start = self.at;
                while self
                    .rest()
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    self.take();
                }
                self.input[start..self.at].to_owned()
            };
            if part.is_empty() || part == "include" {
                return self.fail();
            }
            parts.push(part);
            self.spaces(false);
            if !self.rest().starts_with('.') {
                return Ok(parts.join("."));
            }
            self.take();
        }
    }
    fn value(&mut self) -> Result<Value, Error> {
        self.spaces(true);
        if self.rest().starts_with('"') {
            return self.quoted().map(Value::Scalar);
        }
        if self.rest().starts_with("${") {
            self.at += 2;
            let optional = self.rest().starts_with('?');
            self.at += usize::from(optional);
            let start = self.at;
            while self
                .rest()
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
            {
                self.take();
            }
            let name = self.input[start..self.at].to_owned();
            if name.is_empty() || self.take() != Some('}') {
                return self.fail();
            }
            return Ok(Value::Reference { name, optional });
        }
        if self.rest().starts_with('[') {
            self.take();
            let mut items = Vec::new();
            loop {
                self.spaces(true);
                if self.rest().starts_with(']') {
                    self.take();
                    return Ok(Value::List(items));
                }
                if self.rest().starts_with('[') {
                    return self.fail();
                }
                let Value::Scalar(value) = self.value()? else {
                    return self.fail();
                };
                items.push(value);
                self.spaces(false);
                match self.rest().chars().next() {
                    Some(',') => {
                        self.take();
                    }
                    Some(']' | '\n') => {}
                    _ => return self.fail(),
                }
            }
        }
        let start = self.at;
        while let Some(c) = self.rest().chars().next() {
            if matches!(c, '\n' | '\r' | ',' | '}' | ']' | '#') || self.rest().starts_with("//") {
                break;
            }
            if matches!(c, '$' | '{' | '[' | '"' | '=' | ':' | '+' | '\\') {
                return self.fail();
            }
            self.take();
        }
        let value = self.input[start..self.at].trim();
        if value.is_empty() {
            self.fail()
        } else if value == "null" {
            Ok(Value::Null)
        } else {
            Ok(Value::Scalar(value.to_owned()))
        }
    }
    fn object(&mut self, prefix: &str, closed: bool, depth: usize) -> Result<(), Error> {
        if depth > 32 {
            return self.fail();
        }
        loop {
            self.spaces(true);
            if self.rest().starts_with('}') {
                if !closed {
                    return self.fail();
                }
                self.take();
                return Ok(());
            }
            if self.rest().is_empty() {
                return if closed { self.fail() } else { Ok(()) };
            }
            let key = self.key()?;
            let path = if prefix.is_empty() {
                key
            } else {
                format!("{prefix}.{key}")
            };
            self.spaces(false);
            if self.rest().starts_with(['=', ':']) {
                self.take();
                self.spaces(true);
            } else if !self.rest().starts_with('{') {
                return self.fail();
            }
            if self.rest().starts_with('{') {
                self.values.remove(&path);
                self.take();
                self.object(&path, true, depth + 1)?;
            } else {
                let value = self.value()?;
                if !matches!(value, Value::Reference { .. }) {
                    let descendants = format!("{path}.");
                    let superseded: Vec<_> = self.values.range(descendants.clone()..)
                        .take_while(|(key, _)| key.starts_with(&descendants))
                        .map(|(key, _)| key.clone()).collect();
                    for key in superseded {
                        self.values.remove(&key);
                    }
                }
                self.values.entry(path).or_default().push(value);
            }
            self.spaces(false);
            match self.rest().chars().next() {
                None | Some('}' | '\n') => {}
                Some(',') => {
                    self.take();
                }
                _ => return self.fail(),
            }
        }
    }
}

fn resolve(
    key: &str,
    definitions: &BTreeMap<String, Vec<Value>>,
    env: &BTreeMap<String, String>,
    visiting: &mut BTreeSet<String>,
    completed: &mut BTreeMap<String, Option<Value>>,
) -> Result<Option<Value>, Error> {
    if let Some(value) = completed.get(key) {
        return Ok(value.clone());
    }
    if visiting.len() >= 128 || !visiting.insert(key.to_owned()) {
        return Err(Error { line: 0 });
    }
    let mut result = None;
    if let Some(values) = definitions.get(key) {
        let start = values.iter().rposition(|v| !matches!(v, Value::Reference { .. })).unwrap_or(0);
        for value in &values[start..] {
            match value {
                Value::Reference { name, optional } => {
                    let referenced = if name == key {
                        result
                            .clone()
                            .or_else(|| env.get(name).cloned().map(Value::Scalar))
                    } else if definitions.contains_key(name) {
                        resolve(name, definitions, env, visiting, completed)?
                    } else {
                        env.get(name).cloned().map(Value::Scalar)
                    };
                    if let Some(value) = referenced {
                        result = Some(value);
                    } else if !optional {
                        return Err(Error { line: 0 });
                    }
                }
                value => result = Some(value.clone()),
            }
        }
    }
    visiting.remove(key);
    completed.insert(key.to_owned(), result.clone());
    Ok(result)
}

pub fn parse(text: &str, env: &BTreeMap<String, String>) -> Result<BTreeMap<String, Value>, Error> {
    if text.len() > 1024 * 1024 {
        return Err(Error { line: 0 });
    }
    let mut parser = Parser {
        input: text,
        at: 0,
        line: 1,
        values: BTreeMap::new(),
    };
    parser.spaces(true);
    let braced = parser.rest().starts_with('{');
    if braced {
        parser.take();
    }
    parser.object("", braced, 0)?;
    parser.spaces(true);
    if !parser.rest().is_empty() {
        return parser.fail();
    }
    let mut result = BTreeMap::new();
    let mut visiting = BTreeSet::new();
    let mut completed = BTreeMap::new();
    for key in parser.values.keys() {
        if let Some(value) = resolve(key, &parser.values, env, &mut visiting, &mut completed)? {
            result.insert(key.clone(), value);
        }
    }
    Ok(result)
}
