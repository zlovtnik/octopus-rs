#!/usr/bin/env bash
# Validate implemented library behavior while full runtime delivery stays gated.
set -euo pipefail
cd "$(dirname -- "$0")/../.."
for input in Cargo.toml Cargo.lock src/lib.rs; do
  if [ ! -s "$input" ]; then
    echo "Native core validation unavailable: missing $input" >&2
    exit 2
  fi
done
export OCTOPUS_REQUIRE_DOCKER=true
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release --lib
