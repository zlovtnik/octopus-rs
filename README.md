# Octopus Rust migration

> **Status: Native Octopus runs in local Compose.** Production still uses Scala.
> The [native assembly](src/application/workloads.rs) supports the sync profile.
> Enabling a processor without native wiring fails startup.

## Local development and native candidate validation

Use the following entry points from an umbrella checkout. Image and DQ
provenance checks require a clean parent commit pinning this Rust submodule.

| Consumer | Native candidate invocation |
| --- | --- |
| Parent Jenkins | Enable `RUN_OCTOPUS_NATIVE` to run native coverage, the release build and image checks alongside Scala. |
| Standalone Jenkins | Enable `RUN_NATIVE` and supply the pinning parent SHA in `PARENT_REVISION` for the canonical schema and executor fixtures. |
| Local runtime Compose | `make local-up` builds the stack and verifies that Octopus PID 1 is `/app/octopus`. `make local-check` verifies schema readiness, Search, and native scan evidence and broker commit. |
| Build-only Compose | `OCTOPUS_BUILD_DOCKERFILE=services/octopus-rs/templates/Dockerfile docker compose -f docker-compose.build.yaml build java-coordinator` |
| Image contract | `make octopus-native-image-check` builds linux/amd64 and verifies both OCI revision labels, the ELF entrypoint and configuration behavior. |
| DQ acceptance | In the [DQ test environment](../dq/tests/acceptance.md), run `python3 services/dq/tests/acceptance/run.py --octopus-native`. |

The Compose builds use local development labels by default. The image contract
build derives both revision labels from Git. G3 still requires a passing
Linux run, native DQ acceptance and the coordinated default switch after G1/G2.

## G4 deployment rehearsal

From the parent checkout, run `python3 scripts/octopus_rehearse_promotion.py --fixture`
to render the production app-stack, change the coordinator digest and remove its
JVM option in a temporary Git repository, then revert the commit. The check
compares the entire candidate render against those two expected changes and
requires byte-identical manifests after revert.

With a clean parent revision pinning the native source and the published
linux/amd64 candidate digest in `DIGEST`, run:

```sh
python3 scripts/octopus_g4_smoke.py "$DIGEST" --config-only
python3 scripts/octopus_g4_smoke.py "$DIGEST"
python3 scripts/octopus_rehearse_promotion.py --digest "$DIGEST" > /tmp/octopus-promotion.patch
```

The [runtime check](../../scripts/octopus_g4_smoke.py) needs Docker and registry
access to the candidate, production Scala rollback image and pinned schema
executor. It starts a unique Compose project with disposable PostgreSQL and
Redpanda storage. It uses production topic files, group IDs, broker-drain
selection, schema checksum, port, resource limits and non-root security
settings. It checks health and metrics aliases, sends SIGTERM, restarts with
the broker offline, then checks recovery. Repeated delivery on partition zero
must advance the Kafka commit, retain one event and preserve evidence for each
offset across native restart and Scala rollback.

The fixture connects directly to PostgreSQL with verified TLS. It samples CPU
and memory for one scan record per phase. PgBouncer, archive/DQ dependencies,
other consumer lanes and resource sizing under representative traffic require
separate evidence. Review the [promotion diff](../../scripts/octopus_rehearse_promotion.py)
only after image, parity, rollback and resource checks pass.

## Validate the scaffold

From the umbrella repository root, with Python 3.11+ and Bash:

```bash
bash services/octopus-rs/scripts/ci/test.sh
python3 scripts/check-docs.py
```

The first command runs Python tests for coverage validation, compiler/coverage
orchestration and CI lifecycle behavior, then shell syntax checks. Tests use
temporary fixtures and mocked tools; they do not exercise coordinator behavior
or contact a database, broker or Docker daemon. No Python packages are required.

The [Jenkinsfile](Jenkinsfile) runs tooling checks by default. Native validation
is available in both checkout layouts as described above.

## Native build contract

The active [Cargo.toml](Cargo.toml) defines an independent Rust workspace with
its own [Cargo.lock](Cargo.lock). Its `[workspace]` prevents Cargo from selecting
the parent proxy workspace. [src/lib.rs](src/lib.rs) exposes implemented library
slices. The [coordinator entrypoint](src/main.rs) builds as `octopus`. It loads
defaults, environment settings, HOCON from `-Dconfig.file` and explicit
`-Dkey=value` overrides in that order. Password-file resolution and validation
run before runtime startup.

[rust-toolchain.toml](rust-toolchain.toml) pins Rust
1.100.0 and includes rustfmt, Clippy and matching LLVM tools. The active
manifest uses edition 2021, forbids unsafe code and declares the approved
dependencies needed by the current slices.
The native CI runner selects `linux/amd64` on a Debian Bookworm builder; the
runtime image template uses the matching GNU/libc environment. Other targets
require their own dependency and image verification.

Validate the implemented library from the umbrella root:

```bash
bash services/octopus-rs/scripts/ci/core.sh
```

[core.sh](scripts/ci/core.sh) runs formatting, warnings-as-errors Clippy, locked
tests and a locked release library build. It does not build a coordinator
executable or establish database/broker integration, coverage or runtime parity.
The canonical database fixture requires the umbrella schema and executor.

Run native validation with

```bash
bash services/octopus-rs/scripts/ci/native.sh
```

The runner checks the manifest, lockfile, entrypoint and coverage mappings,
then stages the crate, canonical SQL and schema executor into the Linux builder.
It runs [the native task](scripts/ci/tasks/native.sh). That task installs Python in the
builder, checks formatting and Clippy warnings, runs locked instrumented Cargo
tests, enforces coverage and performs a locked release build. It sets
`OCTOPUS_REQUIRE_DOCKER=true`; future integration tests must honor that contract
and fail when their database/broker prerequisites are unavailable.

Native validation collects `artifacts/octopus-coverage/` and the
`artifacts/octopus` binary before container cleanup. Shared
[common.sh](scripts/ci/common.sh) and [cleanup.sh](scripts/ci/cleanup.sh) remain
byte-identical to the parent scripts. The Linux builder uses host networking so
PostgreSQL tests can reach the daemon host's loopback-published ports. It mounts
the test daemon at `/var/run/docker.sock` and installs the Docker CLI before
required tests. Remote/TLS daemon arrangements need explicit integration validation.

## Coverage contract

[run_coverage.py](scripts/run_coverage.py) uses compiler
[instrumentation-based coverage](https://doc.rust-lang.org/rustc/instrument-coverage.html)
and the matching `llvm-tools-preview` tools. It compiles normal production and
test targets, executes tests with fresh per-run profiles, and exports
[LCOV](https://llvm.org/docs/CommandGuide/llvm-cov.html#export-command).
Only test functions matching normal-build compiler regions contribute hits;
inline test functions are excluded. Normal production mappings retain uncalled
functions at zero hits. The runner also writes `executable-sources.json` beside
the report, recording source hashes for files with production executable lines.
It does not install a third-party Cargo coverage plugin. The native suite uses
`--all-targets`; future library doctests and feature combinations need explicit
additional test policy before runtime parity can be claimed.

[coverage-policy.json](coverage-policy.json) preserves the existing line floors:

| Scope | Minimum |
| --- | ---: |
| Overall | 55% |
| Config | 97% |
| Dispatch | 31% |
| HTTP | 8% |
| Observability | 64% |
| Persistence | 57% |
| PostgreSQL | 29% |
| Processor | 86% |

The policy maps seven domains to production source paths.
The checker rejects empty/nonexistent mappings, overlapping domain paths,
escaping paths and domains with no measured executable lines. Exact file
mappings require executable coverage for that file. Directory mappings reject
omitted files identified as executable by the normal-build evidence, while
allowing declaration-only files with no instrumented lines. Missing or stale
source evidence fails validation. Overall coverage counts the
instrumented production sources in the report; it cannot prove that every
intended module was compiled. Review source inclusion and feature coverage as
part of runtime parity.

From this directory, after the runtime and mappings exist:

```bash
python3 scripts/check_coverage.py --validate-policy
python3 scripts/check_coverage.py artifacts/octopus-coverage/lcov.info
```

Exit codes are 0 for success, 1 for a coverage-floor failure and 2 for invalid
or incomplete inputs. Missing, empty and malformed reports fail. Repeated
records merge by source file and line; test/dependency/external files do not
inflate production percentages. Scala coverage remains authoritative for the
running coordinator. Preserving floor numbers does not establish cross-language
behavioral equivalence; rebaselines still require measured evidence and review.

## Image and activation prerequisites

The [candidate Dockerfile](templates/Dockerfile) takes the parent checkout as
its build context and packages the native binary, runtime resources and
Redpanda bootstrap files. The [image checker](../../scripts/octopus_image_contract.py)
verifies the parent and Rust gitlink revisions against a clean checkout.
Production activation also requires Docker-backed database and broker tests,
DQ acceptance, deployment smoke tests and reviewed digest promotion.

## Local development resources

[setup-wireless-redpanda.sh](setup-wireless-redpanda.sh) retains the original
compatibility wrapper and delegates to the parent
[bootstrap](../../docker/redpanda/bootstrap.sh) and
[topic manifest](../../docker/redpanda/topics.manifest). It requires the full
workspace layout and is not run by scaffold tests. No topic definitions are
duplicated in Rust.

## Migration tracking and verification

[migration-ledger.json](migration-ledger.json) records all 262 tracked baseline
files, with every disposition still pending independent parity evidence.
[check_migration.py](scripts/check_migration.py) checks the recorded revisions,
inventory reconciliation and evidence references. From the umbrella root:

```bash
python3 services/octopus-rs/scripts/check_migration.py
python3 services/octopus-rs/scripts/check_migration.py --require-complete
```

The inventory check reconciles 262 pending rows; completion mode exits 1.
Recorded evidence validation does not execute tests or prove behavioral parity.
The delivery/tooling suite now contains 45 passing tests, including 13 ledger
validation tests. These counts exclude native coordinator behavior.

Verified on 2026-11-16: all 32 scaffold tests passed, shell/Python syntax and TOML
template checks passed, and the repository documentation/link checker passed.
Native validation rejects missing runtime inputs before invoking build tools.
The Docker image, actual LLVM coverage execution and complete coordinator
behavior remain unverified. Library verification evidence is recorded as slices
finish; passing library checks does not close G1 or G2.

The corrected Scala baseline reported 719 passing tests and one skipped probe
out of 720, with 76 passing tests in the targeted persistence suite. The existing
Scala formatting check still reports debt in 23 files. Those baseline results
do not establish native parity or a passing Scala formatting gate.

Verified on 2026-11-18 with Rust 1.100.0: 49 tooling tests passed, including
the real compiler/LLVM fixture proving executed inline tests cannot cover an
uncalled production function on the same line. The core runner passed formatting,
Clippy, 62 native tests (with required PostgreSQL Docker tests and the librdkafka
mock restart test), and a locked release library build. The mock broker is not
Redpanda parity evidence. The CI Docker CLI package installs on Bookworm; host
networking requires a Linux CI daemon and was not validated by this Docker
Desktop setup. No native runtime executable, image or cutover is claimed.
