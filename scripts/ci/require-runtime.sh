#!/usr/bin/env bash
# Check before any Cargo invocation: otherwise Cargo may select the parent proxy.
set -euo pipefail
cd "$(dirname -- "$0")/../.."
for input in Cargo.toml Cargo.lock src/main.rs; do
  if [ ! -s "$input" ]; then
    echo "Native validation unavailable: missing $input in services/octopus-rust; this is a delivery scaffold." >&2
    exit 2
  fi
done
