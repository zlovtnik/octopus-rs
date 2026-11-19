//! Bounded, redacted errors for logs and durable poison records.

use regex::{Captures, Regex};
use std::{error::Error, sync::LazyLock};

static CONTROLS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\p{Cc}\p{Cf}]").unwrap());
static USERINFO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"://[^/?#\s]+@").unwrap());
static BEARER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)((?:authorization[ \t\n\x0B\f\r]*[:=]?[ \t\n\x0B\f\r]*)?Bearer[ \t\n\x0B\f\r]+)([A-Za-z0-9._~+/\-]+=*)").unwrap()
});
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(password|passwd|token|secret|api[-_]?key)[ \t\n\x0B\f\r]*[:=][ \t\n\x0B\f\r]*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^ \t\n\x0B\f\r,;]+)"#).unwrap()
});
static WHITESPACE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[ \t\n\x0B\f\r]+").unwrap());

pub fn sanitize(value: &str) -> String {
    let separated = WHITESPACE.replace_all(value, " ");
    let controls = CONTROLS.replace_all(&separated, "");
    let userinfo = USERINFO.replace_all(&controls, "://[REDACTED]@");
    let bearer = BEARER.replace_all(&userinfo, |c: &Captures<'_>| format!("{}[REDACTED]", &c[1]));
    let assigned =
        ASSIGNMENT.replace_all(&bearer, |c: &Captures<'_>| format!("{}=[REDACTED]", &c[1]));
    let compact = WHITESPACE.replace_all(&assigned, " ");
    // Scala's take(512) counts UTF-16 units. Avoid splitting a surrogate pair
    // into an unrepresentable Rust string at that boundary.
    let mut units = 0;
    compact
        .trim_matches(|c| c <= '\u{20}')
        .chars()
        .take_while(|c| {
            units += c.len_utf16();
            units <= 512
        })
        .collect()
}

pub fn message(error: &(dyn Error + 'static)) -> String {
    let mut current = Some(error);
    let mut seen = Vec::new();
    let mut states = Vec::new();
    while let Some(item) = current {
        let ptr = item as *const dyn Error as *const ();
        if seen.contains(&ptr) {
            break;
        }
        seen.push(ptr);
        if let Some(pg) = item.downcast_ref::<tokio_postgres::Error>() {
            if let Some(code) = pg.code() {
                states.push(code.code().to_owned());
            }
        }
        current = item.source();
    }
    if states.is_empty() {
        // Pool/transport errors may contain private connection inputs. The
        // structured PgError Display path deliberately excludes those inputs.
        return sanitize(&error.to_string());
    }
    let class = crate::postgres::PostgresErrorClass::classify(error).wire_value();
    states
        .iter()
        .take(4)
        .map(|state| format!("PostgreSQL SQLSTATE={state} classification={class}"))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_secrets_controls_and_bounds_output() {
        let input = format!(
            "database failed\npassword=hunter2 token:abc123 {}",
            "x".repeat(1000)
        );
        let result = sanitize(&input);
        assert!(!result.contains("hunter2"));
        assert!(!result.contains("abc123"));
        assert!(!result.chars().any(char::is_control));
        assert!(result.encode_utf16().count() <= 512);
        assert_eq!(
            sanitize("https://user:password@host/path"),
            "https://[REDACTED]@host/path"
        );
        assert_eq!(
            sanitize("api_key:xyz; secret=abcd"),
            "api_key=[REDACTED]; secret=[REDACTED]"
        );
    }

    #[test]
    fn bearer_and_unicode_bounds() {
        assert_eq!(
            sanitize("Authorization: Bearer header.token-value"),
            "Authorization: Bearer [REDACTED]"
        );
        assert_eq!(
            sanitize("request failed for Bearer standalone-token"),
            "request failed for Bearer [REDACTED]"
        );
        assert_eq!(
            sanitize(&"\u{1f600}".repeat(300)).encode_utf16().count(),
            512
        );
        assert_eq!(sanitize("\u{200d}abc\u{85}"), "abc");
    }
}
