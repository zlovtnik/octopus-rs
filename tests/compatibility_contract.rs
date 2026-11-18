use octopus::{
    compatibility::{hocon, instant, java_pattern, tls_identity},
    config::AppConfig,
    dq,
};
use serde_json::json;
use std::collections::BTreeMap;

fn env(values: &[(&str, &str)]) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|(k, v)| ((*k).into(), (*v).into()))
        .collect()
}

#[test]
fn hocon_binds_the_actual_scala_application_resource() {
    let text = include_str!("../resources/application.conf");
    assert!(
        AppConfig::from_sources(&BTreeMap::new(), Some(text), &BTreeMap::new()).unwrap()
            == AppConfig::default()
    );
    let environment = env(&[
        ("COORDINATOR_HTTP_PORT", "8090"),
        ("OCTOPUS_ENVIRONMENT", "development"),
    ]);
    assert!(
        AppConfig::from_sources(&environment, Some(text), &BTreeMap::new()).unwrap()
            == AppConfig::from_env(&environment).unwrap()
    );
}

#[test]
fn search_normalization_ascii_is_exact_and_unicode_does_not_silently_change_hashes() {
    assert_eq!(
        octopus::compatibility::normalize_search_text("  EXAMPLE\t A\nB\u{0b}C\u{0c}D\r ").unwrap(),
        "example a b c d"
    );
    assert_eq!(
        octopus::compatibility::normalize_search_text("A\u{001c}B").unwrap(),
        "a\u{001c}b"
    );
    assert_eq!(
        octopus::compatibility::normalize_search_text("\t\n ").unwrap(),
        ""
    );
    assert!(octopus::compatibility::normalize_search_text("\u{ff21}").is_err());
    assert!(octopus::compatibility::normalize_search_text("caf\u{00e9}").is_err());
}

#[test]
fn hocon_nested_dotted_arrays_comments_substitutions_and_precedence() {
    let text = r#"
    # HOCON supports repeated keys and optional references.
    http { port = 8082 }
    http.port = ${?MISSING}
    processors.enabled = []
    runtime { environment = ${ENVIRONMENT} }
    public-stats.allowed-origins = ["https://one.test", "https://two.test"]
    sync.outbox-dir = """/var/lib/native outbox"""
    kafka.bootstrap-servers = ${BROKERS}
    // References resolve after the complete document is read.
    BROKERS = "broker:9092"
    "#;
    let environment = env(&[
        ("COORDINATOR_HTTP_PORT", "8090"),
        ("ENVIRONMENT", "development"),
    ]);
    let config =
        AppConfig::from_sources(&environment, Some(text), &env(&[("http.port", "8083")])).unwrap();
    assert_eq!(config.http.port, 8083);
    assert_eq!(config.runtime.environment, "development");
    assert_eq!(config.kafka.bootstrap_servers, "broker:9092");
    assert_eq!(
        config.public_stats.allowed_origins,
        ["https://one.test", "https://two.test"]
    );
    assert!(config.processors.enabled.is_empty());
    assert_eq!(config.sync.outbox_dir, "/var/lib/native outbox");
    assert_eq!(
        AppConfig::from_sources(&environment, Some(text), &BTreeMap::new())
            .unwrap()
            .http
            .port,
        8082
    );
}

#[test]
fn unsupported_hocon_and_invalid_typed_inputs_fail_without_leaking_values() {
    for text in [
        "include \"secret-file\"",
        "http.port = ${MISSING}",
        "a = ${b}\nb = ${a}",
        "a = first\"second\"",
        "a += value",
        "http { port = 80",
        "http.port = [8081]",
        "http.port = null",
        "postgres.password = secret\nhttp.port = secret",
    ] {
        let error = AppConfig::from_sources(&BTreeMap::new(), Some(text), &BTreeMap::new())
            .err()
            .unwrap();
        assert!(!error.to_string().contains("secret"), "{error}");
    }
    assert!(hocon::parse(&"x".repeat(1024 * 1024 + 1), &BTreeMap::new()).is_err());
    assert!(AppConfig::load_args(["--ignored".into()]).is_err());
    assert!(AppConfig::load_args(["-Dconfig.url=https://secret".into()]).is_err());
    assert!(AppConfig::load_args(["-Dconfig.file=/missing/secret".into()]).is_err());
}

#[test]
fn hocon_syntax_boundaries_handle_root_objects_lists_and_sanitized_failures() {
    let parsed = hocon::parse(
        "{ a: [one, two,], b=\"escaped\\nline\", \"c\".d = null, e=1, e=${e} } // trailing comment",
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(
        parsed["a"],
        hocon::Value::List(vec!["one".into(), "two".into()])
    );
    assert_eq!(parsed["b"], hocon::Value::Scalar("escaped\nline".into()));
    assert_eq!(parsed["c.d"], hocon::Value::Null);
    assert_eq!(parsed["e"], hocon::Value::Scalar("1".into()));
    assert!(hocon::parse("a=${?ABSENT}", &BTreeMap::new())
        .unwrap()
        .is_empty());
    assert_eq!(
        hocon::parse("a=${a}", &env(&[("a", "fallback")])).unwrap()["a"],
        hocon::Value::Scalar("fallback".into())
    );
    for text in [
        "}",
        "{",
        "{a=1} garbage",
        "a",
        "\"\"=1",
        "\"a.b\"=1",
        "a.=1",
        "a=",
        "a=\"unterminated",
        "a=\"literal\nnewline\"",
        "a=\"bad\\x\"",
        "a=\"\"\"unterminated",
        "a=${}",
        "a=${?}",
        "a=${missing",
        "a=${bad name}",
        "a=[{}]",
        "a=[null]",
        "a=[\"one\" \"two\"]",
        "a=[",
        "a=$",
        "a=1:2",
        "a=1+2",
        "a=1\\2",
        "a=\"one\"\"two\"",
    ] {
        assert!(hocon::parse(text, &BTreeMap::new()).is_err(), "{text}");
    }
    let nested = format!("{}a=1{}", "x {".repeat(34), "}".repeat(34));
    assert!(hocon::parse(&nested, &BTreeMap::new()).is_err());
}

#[test]
fn password_file_resolution_runs_after_hocon_and_property_overrides() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("password");
    std::fs::write(&path, " local secret \r\n").unwrap();
    let environment = env(&[("POSTGRES_PASSWORD_FILE", path.to_str().unwrap())]);
    let config = AppConfig::from_sources(&environment, None, &BTreeMap::new()).unwrap();
    assert_eq!(config.postgres.password, " local secret ");
    assert!(AppConfig::from_sources(
        &environment,
        Some("postgres.password = \"from-file\""),
        &BTreeMap::new()
    )
    .is_err());
}

#[test]
fn java_pattern_golden_results_cover_ascii_unicode_and_line_terminators() {
    // Independently evaluated by OpenJDK 25 Pattern.compile(...).matcher(...).find().
    for (pattern, text, expected) in [
        (r"^\d+$", "123", true),
        (r"^\d+$", "\u{0661}", false),
        (r"^\w+$", "cafe\u{00e9}", false),
        (r"^\w+$", "cafe", true),
        (r"^\s+$", "\u{00a0}", false),
        (r"^\s+$", "\t\r\n", true),
        (r"^.$", "\u{0085}", false),
        (r"^.$", "\u{2028}", false),
        (r"^.$", "\u{1f600}", true),
        (r"x$", "x\r\n", true),
        (r"x$", "x\u{2029}", true),
        (r"\Q[a].\E", "[a].", true),
        (r"(?<=x)y", "xy", true),
        (r"(a)\1", "aa", true),
        (r"(?<letter>a)\k<letter>", "aa", true),
        (r"(?>a|ab)c", "abc", false),
        (r"a++a", "aa", false),
        (r"\p{javaWhitespace}", "\u{001c}", true),
        (r"\p{javaWhitespace}", "\u{00a0}", false),
        (r"(?U)^\d+$", "\u{0661}", true),
        (r"(?s)^.$", "\u{2028}", true),
        ("\\b\u{00e9}\\b", "\u{00e9}", false),
        (r"\R", "\r\n", true),
        ("()", "", true),
    ] {
        let compiled =
            java_pattern::compile(pattern).unwrap_or_else(|error| panic!("{pattern}: {error}"));
        assert_eq!(compiled.is_match(text).unwrap(), expected, "{pattern}");
        let schema = json!({"type":"string","pattern":pattern});
        dq::check_schema(&schema).unwrap();
        assert_eq!(
            dq::validate(&schema, &json!(text)).is_ok(),
            expected,
            "{pattern}"
        );
    }
    for pattern in [
        "(?i)x",
        "(?m)x",
        "\\p{javaLowerCase}",
        "x(?U:y)",
        "[",
        "(?P<rust>x)",
        "(?#comment)x",
        "(?<bad_name>x)",
        "(?<1name>x)",
        r"\K",
        r"\u{0061}",
    ] {
        assert!(java_pattern::compile(pattern).is_err(), "{pattern}");
        assert!(dq::check_schema(&json!({"pattern":pattern})).is_err());
    }
}

#[test]
fn malformed_small_patterns_never_panic_or_bypass_schema_registration() {
    // Delimiter and UTF-8 combinations exercise the translator before the regex
    // compiler. Syntax failures must remain sanitized registration errors.
    let symbols = ['(', ')', '?', '[', ']', '\\', '{', '}', '.', '\u{00e9}'];
    for a in symbols {
        for b in symbols {
            for c in symbols {
                let pattern = format!("{a}{b}{c}");
                let _ = java_pattern::compile(&pattern);
            }
        }
    }
}

#[test]
fn java_instant_golden_results_cover_leap_seconds_offsets_and_end_of_day() {
    // Independently evaluated by OpenJDK 25 Instant.parse(value).toString().
    for (input, expected) in [
        ("2026-11-18t01:02:03z", "2026-11-18T01:02:03Z"),
        ("2026-11-18T24:00:00Z", "2026-11-19T00:00:00Z"),
        ("2016-12-31T23:59:60Z", "2016-12-31T23:59:59Z"),
        ("2016-12-31T23:59:60+01:00", "2016-12-31T22:59:59Z"),
        ("2026-11-18T01:02:03+01:02:03", "2026-11-18T00:00:00Z"),
        ("2026-11-18T01:02:03.Z", "2026-11-18T01:02:03Z"),
    ] {
        assert_eq!(
            instant::parse(input).unwrap().to_rfc3339(),
            expected.replace('Z', "+00:00")
        );
    }
    for input in [
        "2026-11-18T01:02:03+18:01",
        "2026-11-18T01:02:03+19:00",
        "2026-11-18T24:00:00.1Z",
        "2026-11-18T22:59:60Z",
        "2026-11-18T01:02:03.1234567890Z",
        "2026-1-18T01:02:03Z",
        "2026-11-8T01:02:03Z",
        "+2026-11-18T01:02:03Z",
        "-0000-11-18T01:02:03Z",
        "2026-11-18T+1:02:03Z",
    ] {
        assert!(instant::parse(input).is_err(), "{input}");
    }
}

// Ephemeral, self-signed EC identity generated by keytool 25 for this fixture.
// This public test key grants no trust and must never be used in deployment.
const JKS: &str = "/u3+7QAAAAIAAAABAAAAAQAVY29tcGF0aWJpbGl0eS1maXh0dXJlAAABoe8oXZcAAAB9MHswDAYKKwYBBAEqAhEBAQRrw4xC5/Qbb2oOB9v3AggH3stNfv9bTnb3FDNs63Y6AFhuLex4cFsmuJFCw92yulv2jBpD02Sht+/vJGRaw0gpev4ytrPNGWJtWbQrQcPkNE5noI369InVGRAQ6i1zZ0g05Cb/Si+1SwVSU/sAAAABAAVYLjUwOQAAAW0wggFpMIIBD6ADAgECAghXh7yxP9clFTAKBggqhkjOPQQDAzAoMSYwJAYDVQQDEx1PY3RvcHVzIENvbXBhdGliaWxpdHkgRml4dHVyZTAgFw0yNjExMTgxNDU2MDJaGA8yMTI2MTAyNTE0NTYwMlowKDEmMCQGA1UEAxMdT2N0b3B1cyBDb21wYXRpYmlsaXR5IEZpeHR1cmUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARNBbkmvHSpTIRqaV96SjAV6J8ODucvwMmWZK+hr5w9tckpf4Vn0PQnULDq4PlKGDKBEHVxQfyIB+YLFRwa1gLQoyEwHzAdBgNVHQ4EFgQUKe9zj6/Lb8sXBpocEP1v0RvR+qowCgYIKoZIzj0EAwMDSAAwRQIhAOOlVf78URcJX4FB9KtefYn4Menm8mF4f48vP013Ee/5AiAfqbf0x0KD3HjGIQtGYRboHC9f2YIRs6ydeXyAb5vFPefp5NHDl8p0jo3Xk+mFtsRoLLH8";

#[test]
fn jks_java_fixture_and_pkcs12_support_verify_integrity_password_and_key() {
    let bytes = openssl::base64::decode_block(JKS).unwrap();
    let identity = tls_identity::decode(&bytes, "compatibility-fixture", "JKS").unwrap();
    assert_eq!(
        tls_identity::certificate_sha256(&identity).unwrap(),
        "f8a24cd3f2a8482478c98f26734d1fc41fb21c6a59e4352ce3120c331cb0db80"
    );
    assert!(tls_identity::decode(&bytes, "wrong", "JKS").is_err());
    assert!(tls_identity::decode(&bytes, "compatibility-fixture", "PEM").is_err());
    for index in [0, 3, 7, 16, 100, bytes.len() - 1] {
        let mut corrupted = bytes.clone();
        corrupted[index] ^= 1;
        assert!(tls_identity::decode(&corrupted, "compatibility-fixture", "JKS").is_err());
    }
    for length in [0, 31, 100, bytes.len() - 1] {
        assert!(tls_identity::decode(&bytes[..length], "compatibility-fixture", "JKS").is_err());
    }
    let pkcs12 = openssl::pkcs12::Pkcs12::builder()
        .name("fixture")
        .pkey(&identity.private_key)
        .cert(&identity.certificate)
        .build2("pkcs12-fixture")
        .unwrap()
        .to_der()
        .unwrap();
    let decoded = tls_identity::decode(&pkcs12, "pkcs12-fixture", "PKCS12").unwrap();
    assert_eq!(
        tls_identity::certificate_sha256(&decoded).unwrap(),
        tls_identity::certificate_sha256(&identity).unwrap()
    );
    assert!(tls_identity::decode(&pkcs12, "wrong", "PKCS12").is_err());
}

#[test]
#[ignore = "independent Java oracle; run explicitly with the baseline JDK"]
fn java_oracle_differential_patterns_instants_and_jks() {
    let patterns = [
        (r"^\d+$", "123"),
        (r"^\d+$", "\u{0661}"),
        (r"^\w+$", "caf\u{00e9}"),
        (r"^\w+$", "cafe"),
        (r"^\s+$", "\u{00a0}"),
        (r"^\s+$", "\t\r\n"),
        (r"^.$", "\u{0085}"),
        (r"^.$", "\u{2028}"),
        (r"^.$", "\u{1f600}"),
        (r"x$", "x\r\n"),
        (r"x$", "x\u{2029}"),
        (r"\Q[a].\E", "[a]."),
        (r"(?<=x)y", "xy"),
        (r"(a)\1", "aa"),
        (r"(?<letter>a)\k<letter>", "aa"),
        (r"(?>a|ab)c", "abc"),
        (r"a++a", "aa"),
        (r"\p{javaWhitespace}", "\u{001c}"),
        (r"\p{javaWhitespace}", "\u{00a0}"),
        (r"(?U)^\d+$", "\u{0661}"),
        (r"(?s)^.$", "\u{2028}"),
        ("\\b\u{00e9}\\b", "\u{00e9}"),
        (r"\R", "\r\n"),
        ("()", ""),
    ];
    let instants = [
        "2026-11-18t01:02:03z",
        "2026-11-18T24:00:00Z",
        "2016-12-31T23:59:60Z",
        "2016-12-31T23:59:60+01:00",
        "2026-11-18T01:02:03+01:02:03",
        "2026-11-18T01:02:03.Z",
        "2026-11-18T01:02:03+18:01",
        "2026-11-18T01:02:03+19:00",
        "2026-11-18T24:00:00.1Z",
        "2026-11-18T22:59:60Z",
        "2026-11-18T01:02:03.1234567890Z",
        "2026-1-18T01:02:03Z",
        "2026-11-8T01:02:03Z",
        "+2026-11-18T01:02:03Z",
        "-0000-11-18T01:02:03Z",
    ];
    let mut source = String::from("import java.time.Instant; import java.util.regex.Pattern; import java.security.*; import java.io.*; import java.util.HexFormat; class NativeCompatibilityOracle { public static void main(String[] args) throws Exception {");
    let mut expected = Vec::new();
    for (pattern, text) in patterns {
        source.push_str(&format!(
            "System.out.println(Pattern.compile({}).matcher({}).find());",
            serde_json::to_string(pattern).unwrap(),
            serde_json::to_string(text).unwrap()
        ));
        expected.push(
            java_pattern::compile(pattern)
                .unwrap()
                .is_match(text)
                .unwrap()
                .to_string(),
        );
    }
    for value in instants {
        source.push_str(&format!("try{{System.out.println(Instant.parse({}).toString());}}catch(Exception e){{System.out.println(\"invalid\");}}",serde_json::to_string(value).unwrap()));
        expected.push(
            instant::parse(value)
                .map(|v| v.to_rfc3339().replace("+00:00", "Z"))
                .unwrap_or_else(|_| "invalid".into()),
        );
    }
    source.push_str("KeyStore store=KeyStore.getInstance(\"JKS\");try(var input=new FileInputStream(args[0])){store.load(input,\"compatibility-fixture\".toCharArray());}System.out.println(HexFormat.of().formatHex(MessageDigest.getInstance(\"SHA-256\").digest(store.getCertificate(\"compatibility-fixture\").getEncoded())));}}");
    let bytes = openssl::base64::decode_block(JKS).unwrap();
    expected.push(
        tls_identity::certificate_sha256(
            &tls_identity::decode(&bytes, "compatibility-fixture", "JKS").unwrap(),
        )
        .unwrap(),
    );
    let directory = tempfile::tempdir().unwrap();
    let java = directory.path().join("NativeCompatibilityOracle.java");
    let store = directory.path().join("identity.jks");
    std::fs::write(&java, source).unwrap();
    std::fs::write(&store, bytes).unwrap();
    let output = std::process::Command::new("java")
        .arg(java)
        .arg(store)
        .output()
        .expect("independent Java oracle is required for this explicit test");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        expected
    );
}
