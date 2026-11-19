# Octopus Rust delivery scaffold

- This folder contains build/delivery infrastructure and native library slices.
  Runtime migration follows the approved G1-G5 plan; do not add a placeholder server
  or binary to make delivery checks green.
- `Cargo.toml` defines an independent library workspace with its own lockfile.
  Guard against Cargo walking up to the parent proxy workspace.
- `scripts/ci/test.sh` validates the scaffold. `scripts/ci/native.sh` is the
  future native validation entry point and must reject absent runtime inputs.
- `scripts/ci/core.sh` checks implemented library slices; it cannot establish
  full coordinator parity or authorize delivery cutover.
- Keep coverage domain paths empty until they map to implemented source. The
  checker must reject missing mappings/reports rather than count scaffold tests
  as coordinator runtime coverage.
- `templates/Dockerfile` uses the umbrella repository as its build context.
  It is a template and is not wired into image publication or deployment.
- Keep `scripts/ci/common.sh` and `scripts/ci/cleanup.sh` byte-identical to their
  parent counterparts; put Rust-specific behavior in the native runner/task.
- Keep activation prerequisites and evidence in `README.md` and
  `INGESTION-AUDIT.md` accurate as real behavior is ported.
