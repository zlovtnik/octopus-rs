#!/usr/bin/env bash
set -euo pipefail
cd /workspace
bash scripts/ci/require-runtime.sh
apt-get update
apt-get install -y --no-install-recommends python3 docker.io cmake pkg-config libssl-dev
python3 scripts/check_coverage.py --validate-policy
export OCTOPUS_REQUIRE_DOCKER=true
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
python3 scripts/run_coverage.py
python3 scripts/check_coverage.py artifacts/octopus-coverage/lcov.info
cargo build --locked --release --bin octopus
