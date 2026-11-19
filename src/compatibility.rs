//! Compatibility boundaries for accepted JVM configuration and persisted values.

pub mod hocon;
pub mod instant;
pub mod java_pattern;
pub mod tls_identity;

use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Unicode NFKC normalization is unavailable")]
pub struct NormalizationError;

/// Java-style NFKC, locale-independent lowercase, and ASCII whitespace split.
pub fn normalize_search_text(value: &str) -> Result<String, NormalizationError> {
    let normalized: String = value.nfkc().collect();
    Ok(normalized
        .to_lowercase()
        .split([' ', '\t', '\n', '\u{0b}', '\u{0c}', '\r'])
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" "))
}
