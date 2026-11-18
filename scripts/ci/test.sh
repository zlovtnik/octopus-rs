#!/usr/bin/env bash
# Scaffold checks only. Native validation is a separate, fail-closed entry point.
set -euo pipefail
cd "$(dirname -- "$0")/../.."
export PYTHONDONTWRITEBYTECODE=1
python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v
while IFS= read -r -d '' script; do
  bash -n "$script"
done < <(find scripts/ci -name '*.sh' -print0)
sh -n setup-wireless-redpanda.sh
