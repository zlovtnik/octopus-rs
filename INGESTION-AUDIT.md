# Octopus Rust capability migration ledger

> **Status: Native library migration in progress.** Initial library slices and
> delivery tooling exist. Every runtime capability below remains Scala-owned.

The [Scala capability audit](../octopus/INGESTION-AUDIT.md) is the behavioral
baseline. Its implementation links and historical test results describe Scala,
not this native library. No claim of full Rust parity, database readiness or broker handling
is made here.

## Current native slices

The independent [manifest](Cargo.toml) and [lockfile](Cargo.lock) build
[src/lib.rs](src/lib.rs). Current work covers
[configuration](src/config.rs), [wire/domain contracts](src/domain.rs),
[processor catalog, selection and retries](src/processor.rs), and
[identity/payload utilities](src/util.rs). Tests live alongside these modules.
The [PostgreSQL base](src/postgres.rs), [raw intake](src/ingestion.rs),
[wireless hydration](src/ingestion/wireless.rs), [broker adapter](src/kafka.rs),
[error redaction](src/errors.rs) and [DQ contracts](src/dq.rs) also exist.
The [entrypoint](src/main.rs) and [application startup](src/application/mod.rs)
build with the [broker-drain workload assembly](src/application/workloads.rs).
The assembly connects the five consumer lanes, job planner, backlog recovery,
load dispatch and outbox publisher. Other processor selections fail validation.

Configuration currently binds environment variables and defaults; HOCON file
and JVM system-property overrides remain unimplemented. Per-slice tests must
preserve UTF-16 consumer-contract hashing, UTF-8 stable UUID identity, raw payload
hashes, disabled defaults, secret handling, consumer union and ownership rules.
Successful pure-library checks cannot establish durable intake or DQ parity.

[core.sh](scripts/ci/core.sh) validates formatting, Clippy, locked tests and a
release library build. On 2026-11-18 it passed 62 native tests with Docker required
under Rust 1.100.0. These include canonical PostgreSQL intake and transaction
tests, DQ contracts and a librdkafka mock restart test; the mock does not prove
Redpanda parity. [The tooling runner](scripts/ci/test.sh) has 49 passing tests,
including real compiler/LLVM coverage exclusion checks.
[The migration checker](scripts/check_migration.py) reconciles all 262
baseline files; all [ledger](migration-ledger.json) dispositions remain pending.
Its completion mode fails until independently verified dispositions exist.
All seven [coverage domains](coverage-policy.json) have source mappings.
Acceptance requires a successful runtime build and a passing measured report.

The dated [advisor execution checkpoint](../../advisor-plans/010-octopus-rust-file-inventory.md#execution-checkpoint-2026-11-18)
lists finished slices, evidence limits and the next implementation order.
G1/G2 remain open. G3 has opt-in CI, Compose, image and DQ validation paths
in the [native delivery instructions](README.md). Actual Linux connectivity,
runtime parity, image execution and DQ acceptance still require evidence.

## Runtime activation evidence

| Capability | Baseline | Rust evidence required before activation |
| --- | --- | --- |
| Five main broker consumers | [Consumer inventory](../octopus/INGESTION-AUDIT.md#consumer-inventory) | Preserve subscriptions, group identities, earliest-retained startup for new groups, committed-offset restart and durable handling before commit. |
| Raw intake and thirteen typed load targets | [Typed load capabilities](../octopus/INGESTION-AUDIT.md#typed-load-capabilities) | Transactional evidence/dedupe, unknown-stream raw intake, authorized loads, bounded transforms and replay/failure cases. |
| Twenty-six processor workloads | [Downstream inventory](../octopus/INGESTION-AUDIT.md#downstream-processor-inventory) | Preserve IDs, disabled defaults, consumer union, dependency selection, fenced leases/retries and family scenario coverage. Search-owned embedding execution remains outside Octopus. |
| Archive, retention and external I/O | [Runtime support](../octopus/INGESTION-AUDIT.md#runtime-support-and-external-io) | Archive hash checks, durable metadata, archive-before-delete, tombstones and failure/restart behavior. |
| DQ coordination | [Scala audit](../octopus/INGESTION-AUDIT.md) and [DQ acceptance](../dq/tests/acceptance.md) | Registry, admission, leases, reports, receipts, fenced projection application and service/principal authorization. Adapt the native acceptance launcher together with the runtime. |
| HTTP, metrics and tracing | [HTTP inventory](../octopus/INGESTION-AUDIT.md#http-capability-inventory) | Route/status/payload parity, bounded readiness, telemetry freshness and graceful shutdown. A listening port is not evidence of ingestion readiness. |
| PostgreSQL schema and TLS | [Schema manifests](../../sql/postgres/) and [Scala configuration](../octopus/README.md#deployment-configuration) | Executor-recorded manifest verification, scoped credentials, verified TLS and no application DDL. |

For each future slice, record actual Rust source/test links, tested scenarios,
test command/output and remaining discrepancies here. Keep G2 through G5 in the
[migration inventory](../../advisor-plans/010-octopus-rust-file-inventory.md#prerequisite-gates)
open until their evidence exists. Scaffold tests and coverage-parser fixtures
cannot close runtime parity gates.
