use chrono::{TimeZone, Utc};
use octopus::{config::DqConfig, dq::*};
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn parsed(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap()
}
fn code<T: std::fmt::Debug>(result: Result<T, DqError>, expected: &str) {
    assert_eq!(result.unwrap_err().code, expected);
}

#[test]
fn canonical_exact_numbers_and_jsonb_equivalence() {
    for (raw, expected) in [
        ("1e3", "1000"),
        ("1.00", "1"),
        ("-0", "0"),
        ("1.2300e-2", "0.0123"),
        ("9007199254740993", "9007199254740993"),
    ] {
        assert_eq!(canonical(&parsed(raw)).unwrap(), expected);
        assert_eq!(
            sha256(&parsed(raw)).unwrap(),
            sha256(&parsed(expected)).unwrap()
        );
    }
    assert_eq!(
        canonical(&parsed(r#"{"b":1.0,"a":1e2,"b":2.00}"#)).unwrap(),
        r#"{"a":100,"b":2}"#
    );
    assert_eq!(
        digest("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn canonical_unicode_codepoint_order_and_separator_escaping() {
    let value = json!({"\u{1f600}":2,"\u{e000}":1,"text":"\u{2028}\u{2029}"});
    assert_eq!(
        canonical(&value).unwrap(),
        "{\"text\":\"\\u2028\\u2029\",\"\u{e000}\":1,\"\u{1f600}\":2}"
    );
    assert_eq!(canonical(&json!("\\u2028")).unwrap(), "\"\\\\u2028\"");
}

#[test]
fn canonical_limits_are_checked_before_exponent_expansion() {
    assert_eq!(canonical(&parsed("1e65536")).unwrap().len(), 65_537);
    code(canonical(&parsed("1e65537")), "number_too_large");
    code(canonical(&parsed("1e-65537")), "number_too_large");
    assert_eq!(
        canonical(&parsed(&"9".repeat(65_536))).unwrap().len(),
        65_536
    );
    code(canonical(&parsed(&"9".repeat(65_537))), "number_too_large");
    code(canonical(&parsed("1e2147483649")), "invalid_number");
    assert_eq!(canonical(&parsed("0e999999")).unwrap(), "0");
    let mut value = Value::Null;
    for _ in 0..128 {
        value = json!([value]);
    }
    assert!(canonical(&value).is_ok());
    code(canonical(&json!([value])), "json_depth_exceeded");
    assert!(bounded(&json!("x".repeat(65_534))).is_ok());
    code(bounded(&json!("x".repeat(65_535))), "record_too_large");
}

#[test]
fn dispatch_pages_keep_prefix_in_actual_utf8_budget() {
    let items: Vec<_> = (0..100)
        .map(|index| json!({"index":index,"manifest":"\u{1f600}".repeat(10_000)}))
        .collect();
    let page = dispatch_page(&items).unwrap();
    let selected = page["items"].as_array().unwrap();
    assert!(selected.len() > 1 && selected.len() < items.len());
    assert_eq!(selected, &items[..selected.len()]);
    assert!(page.to_string().len() <= DISPATCH_PAGE_BYTES);
    assert!(json!({"items":&items[..=selected.len()]}).to_string().len() > DISPATCH_PAGE_BYTES);
    assert_eq!(dispatch_page(&[]).unwrap(), json!({"items":[]}));
    code(
        dispatch_page(&[json!("x".repeat(DISPATCH_PAGE_BYTES))]),
        "dispatch_item_too_large",
    );
}

#[test]
fn malformed_and_unsupported_schemas_fail_closed() {
    for raw in [
        r#"{"type":["string","null"]}"#,
        r#"{"type":"unknown"}"#,
        r#"{"properties":[]}"#,
        r#"{"required":"id"}"#,
        r#"{"required":["id","id"]}"#,
        r#"{"additionalProperties":{}}"#,
        r#"{"minimum":"3"}"#,
        r#"{"minItems":-1}"#,
        r#"{"pattern":true}"#,
        r#"{"oneOf":[]}"#,
        r#"{"enum":[]}"#,
        r#"{"enum":[1,1.0]}"#,
    ] {
        assert!(check_schema(&parsed(raw)).is_err(), "{raw}");
    }
    assert!(
        check_schema(&json!({"$schema":"https://json-schema.org/draft/2020-12/schema"})).is_ok()
    );
    code(
        check_schema(&json!({"pattern":"["})),
        "invalid_schema_pattern",
    );
    code(
        check_schema(&json!({"pattern":"x".repeat(257)})),
        "invalid_schema_pattern",
    );
    let mut schema = json!({});
    for _ in 0..16 {
        schema = json!({"items":schema});
    }
    assert!(check_schema(&schema).is_ok());
    code(
        check_schema(&json!({"items":schema})),
        "schema_depth_exceeded",
    );
}

#[test]
fn schema_validation_uses_unicode_lengths_exact_decimals_and_numeric_equality() {
    let rule = json!({"type":"string","maxLength":1});
    validate(&rule, &json!("\u{1f600}")).unwrap();
    code(validate(&rule, &json!("ab")), "invalid_parameters");
    validate(
        &json!({"type":"integer"}),
        &parsed("999999999999999999999999999999"),
    )
    .unwrap();
    validate(&json!({"type":"integer"}), &parsed("1.00")).unwrap();
    code(
        validate(&json!({"type":"integer"}), &parsed("1.1")),
        "invalid_parameters",
    );
    validate(
        &parsed(r#"{"enum":[{"n":1}],"const":{"n":1.00}}"#),
        &parsed(r#"{"n":1e0}"#),
    )
    .unwrap();
    let rule = parsed(r#"{"type":"number","minimum":9007199254740993,"maximum":9007199254740994}"#);
    validate(&rule, &parsed("9007199254740993")).unwrap();
    code(
        validate(&rule, &parsed("9007199254740992")),
        "invalid_parameters",
    );
    code(
        validate(&rule, &parsed("9007199254740995")),
        "invalid_parameters",
    );
}

#[test]
fn supported_object_array_and_ascii_pattern_constraints() {
    let schema = parsed(
        r#"{"type":"object","required":["ids"],"additionalProperties":false,"properties":{"ids":{"type":"array","minItems":1,"maxItems":2,"items":{"type":"string","pattern":"^[a-f0-9]{2}$"}}}}"#,
    );
    check_schema(&schema).unwrap();
    validate(&schema, &json!({"ids":["ab"]})).unwrap();
    for value in [
        json!({}),
        json!({"ids":[]}),
        json!({"ids":["ab","bc","cd"]}),
        json!({"ids":["xy"]}),
        json!({"ids":["ab"],"extra":1}),
    ] {
        code(validate(&schema, &value), "invalid_parameters");
    }
    validate(&json!({"type":"null"}), &Value::Null).unwrap();
    validate(&json!({"type":"boolean"}), &json!(true)).unwrap();
}

#[test]
fn principals_scope_and_required_field_failures() {
    let settings = DqConfig::default().settings();
    let principal = DqPrincipal {
        actor: "user".into(),
        roles: ["viewer".into()].into(),
        scopes: ["allowed".into()].into(),
    };
    assert!(principal.permits("allowed"));
    assert!(!principal.permits("other"));
    code(
        principal.require_role(&BTreeSet::from(["service".into()])),
        "forbidden_role",
    );
    DqPrincipal::internal()
        .require_role(&BTreeSet::from(["service".into()]))
        .unwrap();
    let mut request = json!({"installation_id":settings.installation_id,"namespace":settings.namespace,"parameters":{"authorized_scope":"allowed"}});
    scoped(&principal, &request, &settings).unwrap();
    request["parameters"]["authorized_scope"] = json!("other");
    code(scoped(&principal, &request, &settings), "forbidden_scope");
    request["authorized_scope"] = json!("allowed");
    scoped(&principal, &request, &settings).unwrap();
    request["installation_id"] = json!("other");
    code(
        scoped(&principal, &request, &settings),
        "forbidden_installation",
    );
    code(text(&json!({}), "id"), "invalid_id");
    code(field(&json!({}), "id"), "missing_id");
    assert_eq!(field(&json!({"id":null}), "id").unwrap(), &Value::Null);
}

#[test]
fn integer_fields_identifiers_hash_and_deadline_contracts() {
    assert_eq!(
        long(&parsed(r#"{"n":9223372036854775807.0}"#), "n").unwrap(),
        i64::MAX
    );
    assert_eq!(
        long(&parsed(r#"{"n":-9223372036854775808}"#), "n").unwrap(),
        i64::MIN
    );
    assert_eq!(int(&json!({"n":2.0}), "n").unwrap(), 2);
    for value in [
        parsed("9223372036854775808"),
        parsed("1e1000000"),
        parsed("1.5"),
        Value::Null,
    ] {
        code(long(&json!({"n":value}), "n"), "invalid_n");
    }
    assert!(identifier("a._-09"));
    assert!(!identifier("_a"));
    assert!(!identifier("a/b"));
    assert!(!identifier(&"a".repeat(129)));
    assert!(hash(&"a".repeat(64)));
    assert!(!hash(&"A".repeat(64)));
    let now = Utc.with_ymd_and_hms(2026, 11, 17, 1, 0, 0).unwrap();
    assert_eq!(
        deadline(&json!({}), now).unwrap(),
        now + chrono::Duration::hours(1)
    );
    assert_eq!(
        deadline(&json!({"deadline_at":"2026-11-17T03:00:00+01:00"}), now).unwrap(),
        now + chrono::Duration::hours(1)
    );
    code(
        deadline(&json!({"deadline_at":"invalid"}), now),
        "invalid_deadline",
    );
}

#[test]
fn artifact_references_enforce_scope_paths_and_output_producers() {
    let settings = DqConfig::default().settings();
    let prefix = format!(
        "s3://{}/{}/{}/",
        settings.artifact_bucket, settings.installation_id, settings.namespace
    );
    let reference = json!({"installation_id":settings.installation_id,"namespace":settings.namespace,"artifact_id":"artifact","sha256":"a".repeat(64),"version_id":"v1","etag":"etag","size_bytes":2,"uri":format!("{prefix}inputs/run/object")});
    validate_artifacts(&json!([reference.clone()]), &settings, "run", None, true).unwrap();
    code(
        validate_artifacts(&json!([reference.clone()]), &settings, "other", None, true),
        "forbidden_artifact_reference",
    );
    let mut output = reference.clone();
    output["uri"] = json!(format!("{prefix}runs/run/attempts/attempt/object"));
    output["producer_run_id"] = json!("run");
    output["producer_attempt_id"] = json!("attempt");
    validate_artifacts(
        &json!([output.clone()]),
        &settings,
        "run",
        Some("attempt"),
        false,
    )
    .unwrap();
    output["producer_attempt_id"] = json!("other");
    code(
        validate_artifacts(&json!([output]), &settings, "run", Some("attempt"), false),
        "forbidden_artifact_producer",
    );
    for suffix in [
        "../object",
        "object?query",
        "object#fragment",
        "object@host",
    ] {
        let mut changed = reference.clone();
        changed["uri"] = json!(format!("{prefix}inputs/run/{suffix}"));
        code(
            validate_artifacts(&json!([changed]), &settings, "run", None, true),
            "forbidden_artifact_reference",
        );
    }
    let mut changed = reference.clone();
    changed["size_bytes"] = json!(-1);
    code(
        validate_artifacts(&json!([changed]), &settings, "run", None, true),
        "invalid_artifact_reference",
    );
    code(
        validate_artifacts(&json!(vec![reference; 17]), &settings, "run", None, true),
        "too_many_artifacts",
    );
    code(
        validate_artifacts(&Value::Null, &settings, "run", None, true),
        "invalid_artifacts",
    );
}
