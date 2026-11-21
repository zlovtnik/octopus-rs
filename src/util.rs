//! Compatibility helpers for persisted Scala identities and payload inspection.

use md5::Md5;
use serde::de::{MapAccess, Visitor};
use serde::Deserializer;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::fmt;

pub fn sha256_hex(value: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(value.as_ref()))
}

/// Java String.trim removes only characters at or below U+0020.
pub fn java_trim(value: &str) -> &str {
    value.trim_matches(|c: char| c <= '\u{20}')
}

/// Character.isWhitespace excludes the three nonbreaking Unicode spaces.
pub fn java_is_blank(value: &str) -> bool {
    value.chars().all(|c| {
        matches!(c, '\u{9}'..='\u{d}' | '\u{1c}'..='\u{20}' | '\u{1680}' |
            '\u{2000}'..='\u{2006}' | '\u{2008}'..='\u{200a}' | '\u{2028}' |
            '\u{2029}' | '\u{205f}' | '\u{3000}')
    })
}

pub fn utf16_length(value: &str) -> usize {
    value.encode_utf16().count()
}

/// Equivalent to Java's UUID.nameUUIDFromBytes for the supplied bytes.
pub(crate) fn java_name_uuid(value: &[u8]) -> String {
    md5_uuid(Md5::digest(value).into())
}

/// A name UUID over the coordinator's namespace and byte-length-framed parts.
pub fn stable_uuid(namespace: &str, parts: &[&str]) -> String {
    let prefix = format!("{namespace}:v2");
    let mut digest = Md5::new();
    for value in std::iter::once(prefix.as_str()).chain(parts.iter().copied()) {
        digest.update(format!("{}:", value.len()).as_bytes());
        digest.update(value.as_bytes());
    }
    md5_uuid(digest.finalize().into())
}

fn md5_uuid(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x30;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadMetadata {
    pub event_kind: Option<String>,
}

const INVALID_PAYLOAD: &str = "payload_ref resolved non-JSON payload";

/// Validate without retaining rows or materializing non-metadata values.
pub fn inspect_payload(payload: &str) -> Result<PayloadMetadata, String> {
    let raw: &RawValue = serde_json::from_str(payload).map_err(|_| INVALID_PAYLOAD)?;
    if raw.get() == "null" || !within_stream_limits(raw.get()) {
        return Err(INVALID_PAYLOAD.into());
    }
    if !raw.get().starts_with('{') {
        return Ok(PayloadMetadata { event_kind: None });
    }
    struct MetadataVisitor;
    impl<'de> Visitor<'de> for MetadataVisitor {
        type Value = PayloadMetadata;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let (mut primary, mut fallback) = (None, None);
            while let Some(key) = map.next_key::<String>()? {
                let raw: &RawValue = map.next_value()?;
                if key == "event_type" || key == "type" {
                    let value = serde_json::from_str::<String>(raw.get())
                        .ok()
                        .filter(|v| !v.is_empty());
                    if key == "event_type" {
                        primary = value;
                    } else {
                        fallback = value;
                    }
                }
            }
            Ok(PayloadMetadata {
                event_kind: primary.or(fallback),
            })
        }
    }
    let mut decoder = serde_json::Deserializer::from_str(raw.get());
    decoder
        .deserialize_map(MetadataVisitor)
        .map_err(|_| INVALID_PAYLOAD.into())
}

// Jackson's default stream constraints: 1000 nested containers / numeric digits.
// RawValue validates syntax iteratively; this pass enforces the compatibility
// bounds without retaining an AST or imposing Serde's normal 128-level limit.
fn within_stream_limits(value: &str) -> bool {
    let bytes = value.as_bytes();
    let (mut quoted, mut escaped, mut depth, mut i) = (false, false, 0usize, 0usize);
    let mut string_start = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
                let next = bytes[i + 1..].iter().find(|b| !b.is_ascii_whitespace());
                if next == Some(&b':') && i - string_start > 50_000 {
                    let Ok(name) = serde_json::from_str::<String>(&value[string_start..=i]) else {
                        return false;
                    };
                    if utf16_length(&name) > 50_000 {
                        return false;
                    }
                }
            }
        } else {
            match byte {
                b'"' => {
                    quoted = true;
                    string_start = i;
                }
                b'[' | b'{' => {
                    depth += 1;
                    if depth > 1000 {
                        return false;
                    }
                }
                b']' | b'}' => depth -= 1,
                b'-' | b'0'..=b'9' => {
                    let start = i;
                    while i + 1 < bytes.len()
                        && matches!(bytes[i + 1], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                    {
                        i += 1;
                    }
                    // Jackson counts integer/fraction/exponent digits, excluding
                    // signs, decimal points and the exponent marker.
                    if bytes[start..=i]
                        .iter()
                        .filter(|b| b.is_ascii_digit())
                        .count()
                        > 1000
                    {
                        return false;
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_character_semantics_and_sha() {
        assert_eq!(java_trim("\0\t a \n"), "a");
        assert_eq!(java_trim("\u{2003}a\u{2003}"), "\u{2003}a\u{2003}");
        assert!(java_is_blank("\u{2003}\u{1c}\t"));
        assert!(!java_is_blank("\u{a0}"));
        assert_eq!(utf16_length("a\u{1f600}"), 3);
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn uuid_uses_utf8_framing_and_java_md5_bits() {
        assert_eq!(
            stable_uuid("test", &["a", "b"]),
            "b2efc537-01dd-3da9-92bb-76486a34e5cc"
        );
        assert_ne!(
            stable_uuid("test", &["a:b", "c"]),
            stable_uuid("test", &["a", "b:c"])
        );
        assert_eq!(
            stable_uuid("test", &["\u{1f600}"]),
            "99b9c506-8cce-3ddb-a834-4afe2023774c"
        );
    }

    #[test]
    fn metadata_is_top_level_last_duplicate_and_primary_first() {
        for (raw, expected) in [
            (r#"{"event_type":"old","event_type":"new"}"#, Some("new")),
            (
                r#"{"event_type":"old","event_type":null,"type":"fallback"}"#,
                Some("fallback"),
            ),
            (r#"{"event_type":"","type":"fallback"}"#, Some("fallback")),
            (r#"{"event_type":"  ","type":"fallback"}"#, Some("  ")),
            (
                r#"{"nested":{"event_type":"no"},"type":"top"}"#,
                Some("top"),
            ),
            (r#"{"event_\u0074ype":"escaped"}"#, Some("escaped")),
            (r#"{"event_type":[1],"type":12}"#, None),
            (r#"["x",null,{}]"#, None),
            ("true", None),
            ("123", None),
        ] {
            assert_eq!(
                inspect_payload(raw).unwrap().event_kind.as_deref(),
                expected,
                "{raw}"
            );
        }
        for replacement in ["null", "false", "1", "[]", "{}", "\"\""] {
            for field in ["event_type", "type"] {
                let raw = format!(r#"{{"{field}":"old","{field}":{replacement}}}"#);
                assert_eq!(inspect_payload(&raw).unwrap().event_kind, None);
            }
        }
    }

    #[test]
    fn malformed_payloads_have_sanitized_errors() {
        for raw in [
            "",
            " \n\t",
            "null",
            " null ",
            "[1,]",
            "{",
            "[{}",
            "{} x",
            "{} {}",
            "[] null",
            "true false",
            "1 2",
            "\"ok\" []",
            "\"unterminated",
            r#"{"event_type":"valid","tail":"bad\x"}"#,
        ] {
            assert_eq!(inspect_payload(raw), Err(INVALID_PAYLOAD.into()), "{raw}");
        }
    }

    #[test]
    fn streaming_limits_do_not_impose_serde_ast_limits() {
        for depth in [128, 1000, 1001] {
            let raw = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
            assert_eq!(inspect_payload(&raw).is_ok(), depth <= 1000);
        }
        for digits in [1000, 1001] {
            assert_eq!(inspect_payload(&"9".repeat(digits)).is_ok(), digits <= 1000);
        }
        assert!(inspect_payload(&format!("-{}", "9".repeat(1000))).is_ok());
        assert!(inspect_payload(&format!("0.{}e+0", "9".repeat(998))).is_ok());
        assert!(inspect_payload(&format!("0.{}e+0", "9".repeat(999))).is_err());
        let kind = "k".repeat(20_000_001);
        assert_eq!(
            inspect_payload(&format!(r#"{{"event_type":"{kind}"}}"#))
                .unwrap()
                .event_kind,
            Some(kind)
        );
        for size in [50_000, 50_001] {
            assert_eq!(
                inspect_payload(&format!(r#"{{"{}":1}}"#, "k".repeat(size))).is_ok(),
                size <= 50_000
            );
            assert_eq!(
                inspect_payload(&format!(r#"{{"nested":{{"{}":1}}}}"#, "k".repeat(size))).is_ok(),
                size <= 50_000
            );
        }
    }
}
