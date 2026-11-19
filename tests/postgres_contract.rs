use octopus::postgres::{
    is_retryable_sqlstate, schema_problems, PostgresErrorClass, SchemaReadiness,
    REQUIRED_COLUMN_TYPES, REQUIRED_TABLES,
};
use std::collections::BTreeMap;

fn ready() -> SchemaReadiness {
    SchemaReadiness {
        required_version: "2026-11-16".into(),
        applied_version: Some("2026-11-16".into()),
        required_checksum: "a".repeat(64),
        applied_checksum: Some("A".repeat(64)),
        ready: true,
    }
}

fn columns() -> BTreeMap<(String, String), String> {
    REQUIRED_COLUMN_TYPES
        .iter()
        .map(|(table, column, ty)| ((table.to_string(), column.to_string()), ty.to_string()))
        .collect()
}

#[test]
fn canonical_preflight_requires_all_tables_types_and_executor_proof() {
    let tables = REQUIRED_TABLES
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let columns = columns();
    let row = ready();
    assert!(schema_problems(&tables, &columns, Some(&row), &"a".repeat(64)).is_empty());
    for absent in 0..tables.len() {
        let mut missing = tables.clone();
        missing.remove(absent);
        assert_eq!(
            schema_problems(&missing, &columns, Some(&row), &"a".repeat(64)).len(),
            1
        );
    }
    for key in columns.keys() {
        let mut invalid = columns.clone();
        invalid.insert(key.clone(), "varchar".into());
        assert_eq!(
            schema_problems(&tables, &invalid, Some(&row), &"a".repeat(64)).len(),
            1
        );
        invalid.remove(key);
        assert_eq!(
            schema_problems(&tables, &invalid, Some(&row), &"a".repeat(64)).len(),
            1
        );
    }
    assert_eq!(
        schema_problems(&tables, &columns, None, &"a".repeat(64)).len(),
        1
    );
    let invalid = SchemaReadiness {
        ready: false,
        applied_version: None,
        required_checksum: "b".repeat(64),
        applied_checksum: None,
        ..row
    };
    assert_eq!(
        schema_problems(&tables, &columns, Some(&invalid), &"a".repeat(64)).len(),
        4
    );
}

#[test]
fn structured_states_override_transient_subclasses_and_timeout_messages() {
    use PostgresErrorClass::{Permanent, Retryable};
    assert_eq!(
        PostgresErrorClass::classify_states_and_messages(&["23505"], &["timeout"], true),
        Permanent
    );
    for state in [
        "08006", "08s01", "40001", "40P01", "HYT00", "HYT01", "55P03", "57014", "57P03",
    ] {
        assert!(is_retryable_sqlstate(state));
        assert_eq!(
            PostgresErrorClass::classify_states_and_messages(&[state], &[], false),
            Retryable
        );
    }
    for state in ["23505", "42000", "42P01", "", "57P01"] {
        assert!(!is_retryable_sqlstate(state));
    }
    assert_eq!(
        PostgresErrorClass::classify_states_and_messages(&["23505", "08006"], &[], false),
        Retryable
    );
    assert_eq!(
        PostgresErrorClass::classify_states_and_messages(&[], &[], false),
        Permanent
    );
    assert_eq!(
        PostgresErrorClass::classify_states_and_messages(&[], &[], true),
        Retryable
    );
    for message in [
        "query TIMEOUT",
        "temporarily unavailable",
        "connection reset",
        "deadlock",
        "could not serialize access",
        "lock not available",
    ] {
        assert_eq!(
            PostgresErrorClass::classify_states_and_messages(&[], &[message], false),
            Retryable
        );
    }
}
