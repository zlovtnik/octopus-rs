//! Compatibility boundaries for accepted JVM configuration and persisted values.

pub mod hocon;
pub mod instant;
pub mod java_pattern;
pub mod tls_identity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Unicode NFKC normalization is unavailable")]
pub struct NormalizationError;

/// Exact ASCII subset of Java NFKC + Locale.ROOT lowercase + `split("\\s+")`.
/// Non-ASCII input fails closed until the normalization dependency is approved;
/// silently using lowercase alone would change persisted search identities.
pub fn normalize_search_text(value: &str) -> Result<String, NormalizationError> {
    if !value.is_ascii() {
        return Err(NormalizationError);
    }
    Ok(value
        .split([' ', '\t', '\n', '\u{0b}', '\u{0c}', '\r'])
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" "))
}
