#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname -- "$0")/../.."
bash scripts/ci/require-runtime.sh
python3 scripts/check_coverage.py --validate-policy
source scripts/ci/common.sh
ci_install_cleanup
docker_cmd info >/dev/null
coverage_container="$(ci_container_name octopus-rust)"
fixtures="${OCTOPUS_UMBRELLA_ROOT:-$PWD/../..}"
if [ ! -s "$fixtures/sql/postgres/octopus_core/manifest.yaml" ] ||
   [ ! -s "$fixtures/k8s/postgres-schema-executor/entrypoint.sh" ]; then
  echo "OCTOPUS_UMBRELLA_ROOT must contain the canonical schema and executor" >&2
  exit 2
fi
# PostgreSQL helpers publish dynamic ports on the Docker host's loopback.
task_status=0
tar -cf - -C "$PWD" Cargo.toml Cargo.lock rust-toolchain.toml coverage-policy.json \
  src resources tests scripts -C "$fixtures" sql/postgres k8s/postgres-schema-executor \
  | ci_run octopus-rust --platform linux/amd64 --network host -i -w /workspace \
  -e OCTOPUS_TEST_ROOT=/workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  rust:1.100.0-bookworm \
  bash -o pipefail -ec 'tar --no-same-owner -xf -
    mkdir -p artifacts/octopus-coverage
    bash scripts/ci/tasks/native.sh 2>&1 | tee artifacts/octopus-coverage/native-task.log' || task_status=$?
coverage_status=0
mkdir -p artifacts/octopus-coverage &&
  docker_cmd cp "$coverage_container:/workspace/artifacts/octopus-coverage/." artifacts/octopus-coverage/ || coverage_status=$?
if [ "$task_status" -ne 0 ]; then
  exit "$task_status"
fi
if [ "$coverage_status" -ne 0 ]; then
  exit "$coverage_status"
fi
docker_cmd cp "$coverage_container:/workspace/target/release/octopus" artifacts/octopus
