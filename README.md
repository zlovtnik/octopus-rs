# Octopus Rust migration

> **Status: Native library migration in progress.** An independent Cargo library
> and lockfile exist. The full coordinator runtime, binary and image remain pending.

The running coordinator remains [Scala Octopus](../octopus/README.md). This
folder contains delivery tooling and the first native library slices from the
[migration inventory](../../advisor-plans/010-octopus-rust-file-inventory.md#build-delivery-and-documentation)
without changing its production build, image, schema, broker consumers or DQ
acceptance path. [The capability ledger](INGESTION-AUDIT.md) records the runtime
work still required. Configuration, domain contracts, processor selection and
identity/payload utilities are being ported; PostgreSQL base work is in progress.
The executable and complete runtime coverage are prerequisites for cutover.

## Validate the scaffold

From the umbrella repository root, with Python 3.11+ and Bash:

```bash
bash services/octopus-rust/scripts/ci/test.sh
python3 scripts/check-docs.py
```

The first command runs Python tests for coverage validation, compiler/coverage
orchestration and CI lifecycle behavior, then shell syntax checks. Tests use
temporary fixtures and mocked tools; they do not exercise coordinator behavior
or contact a database, broker or Docker daemon. No Python packages are required.

The [Jenkinsfile](Jenkinsfile) supports either an umbrella checkout or a future
standalone checkout of this directory. Its default stage validates the scaffold.
`RUN_NATIVE=true` additionally requires native tests, coverage and a release
artifact. A green scaffold-only job is not native validation or release approval.
No Jenkins job registration, parent pipeline, image publication or deployment
configuration is changed. The nested `.github/` files preserve ownership and
branch-source policy for a future standalone repository; GitHub does not execute
workflows nested inside a service directory in the umbrella repository.

## Native build contract

The active [Cargo.toml](Cargo.toml) defines an independent library workspace with
its own [Cargo.lock](Cargo.lock). Its `[workspace]` prevents Cargo from selecting
the parent proxy workspace. [src/lib.rs](src/lib.rs) exposes implemented library
slices; the intended package and future binary are `octopus`. There is no
`src/main.rs` or placeholder executable. The
[binary manifest template](templates/Cargo.toml.example) remains inactive.

[rust-toolchain.toml](rust-toolchain.toml) pins Rust
1.100.0 and includes rustfmt, Clippy and matching LLVM tools. The active
manifest uses edition 2021, forbids unsafe code and declares the approved
dependencies needed by the current slices.
The native CI runner selects `linux/amd64` on a Debian Bookworm builder; the
runtime image template uses the matching GNU/libc environment. Other targets
require their own dependency and image verification.

Validate the implemented library from the umbrella root:

```bash
bash services/octopus-rust/scripts/ci/core.sh
```

[core.sh](scripts/ci/core.sh) runs formatting, warnings-as-errors Clippy, locked
tests and a locked release library build. It does not build a coordinator
executable or establish database/broker integration, coverage or runtime parity.
Comparisons against the Scala configuration resource and canonical processor
contract run when those umbrella files are available; standalone checkouts skip
those comparisons at runtime and can compile the library tests. Complete
standalone fixture packaging remains a G1 prerequisite.
The configuration binding currently supports defaults and environment variables;
Scala HOCON file and JVM system-property overrides remain a compatibility gap.

Future native validation is invoked explicitly:

```bash
bash services/octopus-rust/scripts/ci/native.sh
```

**Today this exits 2 with a missing-runtime diagnostic.** Before any Cargo or
Docker command, it requires nonempty service-local `Cargo.toml`, `Cargo.lock`
and `src/main.rs`, plus complete coverage mappings. It never builds the parent
proxy as a substitute. The manifest and real lockfile now exist; implementing
the executable and completing coverage mappings remain required. Do not add a
placeholder runtime to satisfy the guard.

Once those inputs exist, [the runner](scripts/ci/native.sh) requires a working
Docker daemon, stages this folder into a named container, and runs
[the native task](scripts/ci/tasks/native.sh). That task installs Python in the
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

Each domain's `paths` is intentionally empty. During runtime implementation,
map each domain to real service-relative production files or directories under
`src/`; for example, a `src/config` directory is valid only once it exists.
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

[templates/Dockerfile](templates/Dockerfile) is deliberately inactive. It expects
the umbrella repository as its build context and a future executable target.
It describes a multi-stage native build, UID/GID 1000, port 8081,
`/health` image check, canonical topic bootstrap assets and an executable
entrypoint. The future binary must implement health behavior; no HTTP server is
included here. Native TLS libraries, schema manifests, authority data and other
runtime resources must be inventoried and packaged when their code is ported.

The template requires `PARENT_COMMIT` and `OCTOPUS_COMMIT` labels. While this
folder lives in the parent repository, the parent revision identifies its native
source; the Octopus submodule revision identifies the Scala migration baseline.
Before release, reconcile those semantics and native binary validation with the
existing [image contract checker](../../scripts/octopus_image_contract.py).
That checker still expects the production JAR and must remain in force for Scala.

Activation also requires runtime parity, Docker-backed database/broker tests,
native image smoke tests under the deployment security context, DQ acceptance,
resource measurements and reviewed Git/Argo CD digest promotion. Preserve group
identities, offsets, schema manifests and ingestion evidence. The parent
[Makefile](../../Makefile), [CI runner](../../scripts/ci/octopus.sh),
[DQ acceptance harness](../dq/tests/acceptance/run.py) and
[production manifests](../../cyber-stack/base/java-coordinator/deployment.yaml)
continue to target Scala until that coordinated change is verified.

## Local development resources

[setup-wireless-redpanda.sh](setup-wireless-redpanda.sh) retains the original
compatibility wrapper and delegates to the parent
[bootstrap](../../docker/redpanda/bootstrap.sh) and
[topic manifest](../../docker/redpanda/topics.manifest). It requires the full
workspace layout and is not run by scaffold tests. No topic definitions are
duplicated in Rust.

The parent [local runtime configuration](../../docker-compose.yaml) still
launches the Scala JAR. Changing an image entrypoint alone will not convert that
path; it remains a separate activation prerequisite.

## Migration tracking and verification

[migration-ledger.json](migration-ledger.json) records all 262 tracked baseline
files, with every disposition still pending independent parity evidence.
[check_migration.py](scripts/check_migration.py) checks the recorded revisions,
inventory reconciliation and evidence references. From the umbrella root:

```bash
python3 services/octopus-rust/scripts/check_migration.py
python3 services/octopus-rust/scripts/check_migration.py --require-complete
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
