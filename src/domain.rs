//! Broker, scan, load and result contracts retained during native migration.

use crate::util::{
    inspect_payload, java_is_blank, java_trim, sha256_hex, utf16_length, PayloadMetadata,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerRecordMetadata {
    pub topic: String,
    pub partition: i32,
    pub offset: i64,
    pub consumer_group: String,
    pub group_version: i32,
    pub artifact_sha256: String,
    pub message_key: Option<String>,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerConsumerContract {
    pub group_version: i32,
    pub contract_sha256: String,
}

impl BrokerConsumerContract {
    pub fn from(group_id: &str, topic: &str) -> Result<Self, String> {
        let group = java_trim(group_id);
        let topic = java_trim(topic);
        if group.is_empty() {
            return Err("consumer group must not be blank".into());
        }
        if topic.is_empty() {
            return Err("topic must not be blank".into());
        }
        let version = group
            .rfind(['-', '_', '.'])
            .and_then(|i| group[i + 1..].strip_prefix('v'));
        let version = version
            .filter(|v| {
                !v.is_empty() && !v.starts_with('0') && v.bytes().all(|b| b.is_ascii_digit())
            })
            .ok_or_else(|| {
                format!("consumer group must end in a non-zero version suffix such as -v1: {group}")
            })?;
        // Java's regex dot excludes line terminators, including Unicode ones.
        if group
            .chars()
            .any(|c| matches!(c, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}'))
        {
            return Err(format!(
                "consumer group must end in a non-zero version suffix such as -v1: {group}"
            ));
        }
        let group_version = version
            .parse::<i32>()
            .map_err(|_| format!("consumer group version is out of range: {group}"))?;
        let canonical = format!(
            "{}:{group}{}:{topic}",
            utf16_length(group),
            utf16_length(topic)
        );
        Ok(Self {
            group_version,
            contract_sha256: sha256_hex(canonical),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestionDisposition {
    Processed,
    Deduplicated,
    Retrying,
    Parked,
    Rejected,
}

impl IngestionDisposition {
    pub fn database_value(self) -> &'static str {
        match self {
            Self::Processed => "processed",
            Self::Deduplicated => "duplicate",
            Self::Retrying => "retrying",
            Self::Parked => "parked",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngestionDecision {
    pub disposition: IngestionDisposition,
    pub dedupe_key: String,
    pub job_id: String,
    pub batch_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanRequestRecord {
    request_json: String,
    source_record_sha256: String,
    stream_name: String,
    dedupe_key: String,
    observed_at: String,
    payload_ref: String,
}

impl ScanRequestRecord {
    pub const IDENTIFIER_MAX_LENGTH: usize = 255;
    pub const PAYLOAD_REF_MAX_BYTES: usize = 16_777_215;

    pub fn request_json(&self) -> &str {
        &self.request_json
    }
    pub fn source_record_sha256(&self) -> &str {
        &self.source_record_sha256
    }
    pub fn stream_name(&self) -> &str {
        &self.stream_name
    }
    pub fn dedupe_key(&self) -> &str {
        &self.dedupe_key
    }
    pub fn observed_at(&self) -> &str {
        &self.observed_at
    }
    pub fn payload_ref(&self) -> &str {
        &self.payload_ref
    }

    pub fn decode_wire(raw: &str) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Wire {
            stream_name: String,
            dedupe_key: String,
            observed_at: String,
            payload_ref: String,
        }
        // Circe retains the last duplicate field, unlike Serde struct decoding.
        let value: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
        let wire: Wire = serde_json::from_value(value).map_err(|e| e.to_string())?;
        Self::from_parts(raw.into(), wire.stream_name, wire.dedupe_key, wire.observed_at, wire.payload_ref)
    }

    /// Construct a discovery record from a direct event while retaining the
    /// exact broker bytes used by durable ingestion evidence.
    pub fn from_parts(
        request_json: String,
        stream_name: String,
        dedupe_key: String,
        observed_at: String,
        payload_ref: String,
    ) -> Result<Self, String> {
        for (name, value) in [
            ("stream_name", &stream_name),
            ("dedupe_key", &dedupe_key),
        ] {
            if java_is_blank(value) {
                return Err(format!("scan request {name} must not be empty"));
            }
            if utf16_length(value) > Self::IDENTIFIER_MAX_LENGTH {
                return Err(format!(
                    "scan request {name} must not exceed 255 characters"
                ));
            }
        }
        if java_is_blank(&payload_ref) {
            return Err("scan request payload_ref must not be empty".into());
        }
        if payload_ref.len() > Self::PAYLOAD_REF_MAX_BYTES {
            return Err(format!(
                "scan request payload_ref must not exceed {} UTF-8 bytes",
                Self::PAYLOAD_REF_MAX_BYTES
            ));
        }
        if !is_offset_datetime(&observed_at) {
            return Err("scan request observed_at must be RFC3339".into());
        }
        Ok(Self {
            source_record_sha256: sha256_hex(&request_json),
            request_json,
            stream_name,
            dedupe_key,
            observed_at,
            payload_ref,
        })
    }
}

/// Java OffsetDateTime's ISO parser accepts minute precision and offset seconds.
fn is_offset_datetime(value: &str) -> bool {
    let Some(t) = value.find(['T', 't']) else {
        return false;
    };
    let (local, offset) = if value.ends_with(['Z', 'z']) {
        (&value[..value.len() - 1], "Z")
    } else if let Some(i) = value[t + 1..].find(['+', '-']) {
        let i = t + 1 + i;
        (&value[..i], &value[i..])
    } else {
        return false;
    };
    if offset != "Z" {
        let parts: Vec<_> = offset[1..].split(':').collect();
        if !(1..=3).contains(&parts.len())
            || parts
                .iter()
                .any(|p| p.len() != 2 || !p.bytes().all(|b| b.is_ascii_digit()))
        {
            return false;
        }
        let numbers: Vec<u32> = parts
            .iter()
            .map(|p| p.parse().unwrap_or(u32::MAX))
            .collect();
        if numbers[0] > 18
            || numbers.get(1).is_some_and(|m| *m > 59)
            || numbers.get(2).is_some_and(|s| *s > 59)
            || (numbers[0] == 18 && numbers[1..].iter().any(|v| *v != 0))
        {
            return false;
        }
    }
    let time = &local[t + 1..];
    let date = &local[..t];
    let date_parts: Vec<_> = date.trim_start_matches(['+', '-']).split('-').collect();
    if date_parts.len() != 3
        || date_parts[0].len() < 4
        || date_parts[1].len() != 2
        || date_parts[2].len() != 2
    {
        return false;
    }
    let clock = time.split('.').next().unwrap_or("");
    let clock_parts: Vec<_> = clock.split(':').collect();
    if !(2..=3).contains(&clock_parts.len())
        || clock_parts
            .iter()
            .any(|p| p.len() != 2 || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    if time
        .split_once('.')
        .is_some_and(|(_, fraction)| fraction.len() > 9)
    {
        return false;
    }
    let mut local = local.replace('t', "T");
    if time.len() == 5 {
        local.push_str(":00");
    }
    // Reject leap seconds, which Chrono can represent but Java cannot.
    if time.get(6..8).is_some_and(|s| s == "60") {
        return false;
    }
    chrono::NaiveDateTime::parse_from_str(&local, "%Y-%m-%dT%H:%M:%S%.f").is_ok()
}

/// A validated payload and its derived hash/metadata form one immutable value.
/// Construct a replacement with [`Self::from`] to revalidate and recompute both.
///
/// ```compile_fail
/// use octopus::domain::ResolvedScanRequestRecord;
/// fn corrupt(record: &mut ResolvedScanRequestRecord) {
///     record.payload_json = "null".into();
/// }
/// ```
///
/// The source record cannot be mutated through the resolved record either.
///
/// ```compile_fail
/// use octopus::domain::ResolvedScanRequestRecord;
/// fn corrupt(record: &mut ResolvedScanRequestRecord) {
///     record.source().stream_name = "different".into();
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedScanRequestRecord {
    source: ScanRequestRecord,
    payload_json: String,
    event_payload_sha256: String,
    inspection: PayloadMetadata,
}

impl ResolvedScanRequestRecord {
    pub fn source(&self) -> &ScanRequestRecord {
        &self.source
    }
    pub fn payload_json(&self) -> &str {
        &self.payload_json
    }
    pub fn event_payload_sha256(&self) -> &str {
        &self.event_payload_sha256
    }
    pub fn inspection(&self) -> &PayloadMetadata {
        &self.inspection
    }

    pub fn from(source: ScanRequestRecord, payload_json: String) -> Result<Self, String> {
        let inspection = inspect_payload(&payload_json)?;
        let event_payload_sha256 = sha256_hex(&payload_json);
        Ok(Self {
            source,
            payload_json,
            event_payload_sha256,
            inspection,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SyncLoad {
    pub job_id: String,
    pub batch_id: String,
    pub batch_no: Option<i32>,
    pub stream_name: String,
    pub payload_ref: String,
    pub cursor_start: String,
    pub cursor_end: String,
    pub attempt: i32,
}

// Circe's JsonNumber.toInt accepts mathematically integral decimals/exponents.
fn json_i32(value: Value) -> Result<i32, String> {
    let Value::Number(number) = value else {
        return Err("expected a 32-bit integer".into());
    };
    let text = number.to_string();
    let (mantissa, exponent) = match text.find(['e', 'E']) {
        Some(i) => (
            &text[..i],
            text[i + 1..]
                .parse::<i64>()
                .map_err(|_| "integer exponent out of range")?,
        ),
        None => (text.as_str(), 0),
    };
    let negative = mantissa.starts_with('-');
    let mantissa = mantissa.trim_start_matches('-');
    let decimals = mantissa
        .split_once('.')
        .map_or(0, |(_, fractional)| fractional.len());
    let mut digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let scale = (decimals as i64)
        .checked_sub(exponent)
        .ok_or("integer exponent out of range")?;
    if digits.bytes().all(|b| b == b'0') {
        return Ok(0);
    }
    if scale > 0 {
        let scale = usize::try_from(scale).map_err(|_| "integer out of range")?;
        if scale >= digits.len() || !digits[digits.len() - scale..].bytes().all(|b| b == b'0') {
            return Err("expected a 32-bit integer".into());
        }
        digits.truncate(digits.len() - scale);
    }
    let digits = digits.trim_start_matches('0');
    let extra = if scale < 0 { scale.unsigned_abs() } else { 0 };
    if digits.len() as u64 + extra > 10 {
        return Err("integer out of range".into());
    }
    let mut text = if negative {
        format!("-{digits}")
    } else {
        digits.to_owned()
    };
    text.extend(std::iter::repeat_n('0', extra as usize));
    text.parse::<i32>()
        .map_err(|_| "integer out of range".into())
}

fn optional_i32<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<i32>, D::Error> {
    let value = Value::deserialize(deserializer)?;
    if value.is_null() {
        Ok(None)
    } else {
        json_i32(value).map(Some).map_err(serde::de::Error::custom)
    }
}

fn required_i32<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i32, D::Error> {
    json_i32(Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}

impl<'de> Deserialize<'de> for SyncLoad {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            job_id: String,
            batch_id: String,
            #[serde(default, deserialize_with = "optional_i32")]
            batch_no: Option<i32>,
            stream_name: String,
            payload_ref: String,
            cursor_start: String,
            cursor_end: String,
            #[serde(default, deserialize_with = "optional_i32")]
            attempt: Option<i32>,
        }
        let wire: Wire = serde_json::from_value(Value::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            job_id: wire.job_id,
            batch_id: wire.batch_id,
            batch_no: wire.batch_no,
            stream_name: wire.stream_name,
            payload_ref: wire.payload_ref,
            cursor_start: wire.cursor_start,
            cursor_end: wire.cursor_end,
            attempt: wire.attempt.unwrap_or(0),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PostgresResult {
    pub job_id: String,
    pub batch_id: String,
    pub status: String,
    pub row_count: i32,
    pub checksum: String,
    pub retryable: bool,
    pub error_class: String,
    pub error_text: String,
    pub finished_at: String,
}

impl<'de> Deserialize<'de> for PostgresResult {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            job_id: String,
            batch_id: String,
            status: String,
            #[serde(deserialize_with = "required_i32")]
            row_count: i32,
            checksum: Option<String>,
            retryable: Option<bool>,
            error_class: Option<String>,
            error_text: Option<String>,
            finished_at: String,
        }
        let wire: Wire = serde_json::from_value(Value::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)?;
        let error_class = wire.error_class.unwrap_or_default();
        let retryable = error_class == "retryable";
        if wire.retryable.is_some_and(|v| v != retryable) {
            return Err(serde::de::Error::custom(format!(
                "retryable={} conflicts with error_class={error_class}",
                !retryable
            )));
        }
        Ok(Self {
            job_id: wire.job_id,
            batch_id: wire.batch_id,
            status: wire.status,
            row_count: wire.row_count,
            checksum: wire.checksum.unwrap_or_default(),
            retryable,
            error_class,
            error_text: wire.error_text.unwrap_or_default(),
            finished_at: wire.finished_at,
        })
    }
}

impl PostgresResult {
    pub fn success(
        job_id: String,
        batch_id: String,
        row_count: i32,
        checksum: String,
        finished_at: String,
    ) -> Self {
        Self {
            job_id,
            batch_id,
            status: "success".into(),
            row_count,
            checksum,
            retryable: false,
            error_class: String::new(),
            error_text: String::new(),
            finished_at,
        }
    }
    pub fn failure(
        job_id: String,
        batch_id: String,
        error_class: String,
        error_text: String,
        finished_at: String,
    ) -> Self {
        Self {
            job_id,
            batch_id,
            status: "failed".into(),
            row_count: 0,
            checksum: String::new(),
            retryable: error_class == "retryable",
            error_class,
            error_text,
            finished_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Value {
        serde_json::json!({"stream_name":"proxy.events","dedupe_key":"dedupe","payload_ref":"payload.json","observed_at":"2026-08-03T12:34:56Z"})
    }

    #[test]
    fn broker_identity_versions_and_utf16_framing() {
        for invalid in [
            "",
            "group",
            "g-v0",
            "g-v01",
            "g-v-1",
            "g-v2147483648",
            "g\nx-v1",
        ] {
            assert!(
                BrokerConsumerContract::from(invalid, "topic").is_err(),
                "{invalid}"
            );
        }
        assert!(BrokerConsumerContract::from("g-v1", " ").is_err());
        assert_eq!(
            BrokerConsumerContract::from(" g-v2147483647 ", " topic ")
                .unwrap()
                .group_version,
            i32::MAX
        );
        let contract = BrokerConsumerContract::from("\u{1f600}-v1", "\u{20ac}").unwrap();
        assert_eq!(
            contract.contract_sha256,
            sha256_hex("5:\u{1f600}-v11:\u{20ac}")
        );
        assert_ne!(
            contract.contract_sha256,
            sha256_hex("7:\u{1f600}-v13:\u{20ac}")
        );
    }

    #[test]
    fn scan_validation_preserves_raw_record_and_distinct_payload_hash() {
        let raw = format!(" {} \n", request());
        let source = ScanRequestRecord::decode_wire(&raw).unwrap();
        assert_eq!(source.request_json, raw);
        assert_eq!(source.source_record_sha256, sha256_hex(&raw));
        let payload = " \n{\"event_type\":\"  kind  \",\"value\":\"\u{20ac}\"}\t";
        let record = ResolvedScanRequestRecord::from(source, payload.into()).unwrap();
        assert_eq!(record.payload_json, payload);
        assert_eq!(record.event_payload_sha256, sha256_hex(payload));
        assert_ne!(
            record.event_payload_sha256,
            record.source.source_record_sha256
        );
        assert_eq!(record.inspection.event_kind.as_deref(), Some("  kind  "));
        for invalid in ["null", "", "{} {}", "[1,broken]"] {
            assert!(
                ResolvedScanRequestRecord::from(record.source.clone(), invalid.into()).is_err()
            );
        }
    }

    #[test]
    fn scan_limits_use_utf16_identifiers_and_utf8_references() {
        for key in ["stream_name", "dedupe_key"] {
            for value in ["s".repeat(256), "\u{1f600}".repeat(128), "\u{2003}".into()] {
                let mut input = request();
                input[key] = value.into();
                assert!(ScanRequestRecord::decode_wire(&input.to_string()).is_err());
            }
            let mut input = request();
            input[key] = "\u{1f600}".repeat(127).into();
            assert!(ScanRequestRecord::decode_wire(&input.to_string()).is_ok());
        }
        let mut input = request();
        input["payload_ref"] = "\u{20ac}"
            .repeat(ScanRequestRecord::PAYLOAD_REF_MAX_BYTES / 3 + 1)
            .into();
        assert!(ScanRequestRecord::decode_wire(&input.to_string()).is_err());
    }

    #[test]
    fn resolved_replacement_revalidates_without_changing_original_evidence() {
        let source = ScanRequestRecord::decode_wire(&request().to_string()).unwrap();
        let original =
            ResolvedScanRequestRecord::from(source, r#"{"type":"original"}"#.into()).unwrap();
        let replacement = ResolvedScanRequestRecord::from(
            original.source().clone(),
            r#"{"type":"replacement"}"#.into(),
        )
        .unwrap();
        assert_eq!(
            original.inspection().event_kind.as_deref(),
            Some("original")
        );
        assert_eq!(
            replacement.inspection().event_kind.as_deref(),
            Some("replacement")
        );
        assert_eq!(
            original.event_payload_sha256(),
            sha256_hex(original.payload_json())
        );
        assert_eq!(
            replacement.event_payload_sha256(),
            sha256_hex(replacement.payload_json())
        );
        assert_ne!(
            original.event_payload_sha256(),
            replacement.event_payload_sha256()
        );
        assert_eq!(original.source(), replacement.source());
        assert_eq!(
            original.source().source_record_sha256(),
            sha256_hex(original.source().request_json())
        );
        for invalid in ["null", "", "[] {}", "[invalid]"] {
            assert!(
                ResolvedScanRequestRecord::from(original.source().clone(), invalid.into()).is_err()
            );
        }
        assert_eq!(
            original.inspection().event_kind.as_deref(),
            Some("original")
        );
        assert_eq!(original.source().stream_name(), "proxy.events");
        assert_eq!(original.source().dedupe_key(), "dedupe");
        assert_eq!(original.source().observed_at(), "2026-08-03T12:34:56Z");
        assert_eq!(original.source().payload_ref(), "payload.json");
    }

    #[test]
    fn timestamps_match_offset_datetime_precision_and_bounds() {
        for valid in [
            "2026-08-03T12:34:56-04:00",
            "2026-08-03T12:34Z",
            "2026-08-03t12:34:56.123456789z",
            "2026-08-03T12:34:56+01:02:03",
        ] {
            assert!(is_offset_datetime(valid), "{valid}");
        }
        for invalid in [
            "2026-08-03 12:34:56",
            "2026-02-30T12:00:00Z",
            "2026-08-03T12:34:60Z",
            "2026-08-03T12:34:56+18:01",
            "2026-08-03T12:34:56.1234567890Z",
        ] {
            assert!(!is_offset_datetime(invalid), "{invalid}");
        }
    }

    #[test]
    fn load_required_optional_null_default_and_roundtrip() {
        let raw = r#"{"job_id":"j","batch_id":"b","stream_name":"proxy.events","payload_ref":"inline://json/dGVzdA==","cursor_start":"","cursor_end":""}"#;
        let mut input: Value = serde_json::from_str(raw).unwrap();
        let load: SyncLoad = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(load.batch_no, None);
        assert_eq!(load.attempt, 0);
        input["attempt"] = Value::Null;
        input["batch_no"] = Value::Null;
        assert_eq!(
            serde_json::from_value::<SyncLoad>(input.clone()).unwrap(),
            load
        );
        input["batch_no"] = 2.into();
        input["attempt"] = 3.into();
        let load: SyncLoad = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(load.batch_no, Some(2));
        assert_eq!(load.attempt, 3);
        assert_eq!(
            serde_json::from_str::<SyncLoad>(&serde_json::to_string(&load).unwrap()).unwrap(),
            load
        );
        input.as_object_mut().unwrap().remove("cursor_start");
        assert!(serde_json::from_value::<SyncLoad>(input).is_err());
        assert!(serde_json::from_str::<SyncLoad>(r#"{"job_id":"j"}"#).is_err());
    }

    #[test]
    fn results_derive_retryability_and_reject_conflicts_and_missing_required() {
        let mut input = serde_json::json!({"job_id":"j","batch_id":"b","status":"success","row_count":2,"finished_at":"2026-08-03T12:00:00Z"});
        let result: PostgresResult = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(result.checksum, "");
        assert!(!result.retryable);
        assert_eq!(result.error_class, "");
        assert_eq!(result.error_text, "");
        input["error_class"] = "retryable".into();
        assert!(
            serde_json::from_value::<PostgresResult>(input.clone())
                .unwrap()
                .retryable
        );
        input["retryable"] = false.into();
        assert!(serde_json::from_value::<PostgresResult>(input.clone()).is_err());
        input["retryable"] = Value::Null;
        assert!(
            serde_json::from_value::<PostgresResult>(input.clone())
                .unwrap()
                .retryable
        );
        input.as_object_mut().unwrap().remove("row_count");
        assert!(serde_json::from_value::<PostgresResult>(input).is_err());
        let result = PostgresResult::failure(
            "j".into(),
            "b".into(),
            "permanent".into(),
            "bad".into(),
            "now".into(),
        );
        assert_eq!(
            serde_json::from_str::<PostgresResult>(&serde_json::to_string(&result).unwrap())
                .unwrap(),
            result
        );
    }

    #[test]
    fn integral_json_decimals_keep_circe_integer_semantics() {
        for (text, expected) in [
            ("1.0", 1),
            ("10e-1", 1),
            ("-2147483648.0", i32::MIN),
            ("2147483647", i32::MAX),
            ("0e999999", 0),
            ("1e2", 100),
        ] {
            assert_eq!(
                json_i32(serde_json::from_str(text).unwrap()).unwrap(),
                expected,
                "{text}"
            );
        }
        for text in [
            "1.1",
            "1e-1",
            "2147483648",
            "2147483647.0000000001",
            "-2147483649",
            "1e99999",
            "true",
            "\"1\"",
        ] {
            assert!(
                json_i32(serde_json::from_str(text).unwrap()).is_err(),
                "{text}"
            );
        }
        let result: PostgresResult = serde_json::from_str(r#"{"job_id":"j","batch_id":"b","status":"success","row_count":2.0,"finished_at":"now"}"#).unwrap();
        assert_eq!(result.row_count, 2);
    }
}
