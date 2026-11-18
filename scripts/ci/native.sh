#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname -- "$0")/../.."
bash scripts/ci/require-runtime.sh
python3 scripts/check_coverage.py --validate-policy
source scripts/ci/common.sh
ci_install_cleanup
docker_cmd info >/dev/null
coverage_container="$(ci_container_name octopus-rust)"
# PostgreSQL helpers publish dynamic ports on the Docker host's loopback.
tar --exclude=./target --exclude=./artifacts --exclude=./.git \
  --exclude=./.env --exclude='./.env.*' --exclude=./secrets \
  -cf - . | ci_run octopus-rust --platform linux/amd64 --network host -i -w /workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  rust:1.100.0-bookworm \
  sh -c 'tar --no-same-owner -xf - && bash /workspace/scripts/ci/tasks/native.sh'
mkdir -p artifacts/octopus-coverage
docker_cmd cp "$coverage_container:/workspace/artifacts/octopus-coverage/." artifacts/octopus-coverage/
docker_cmd cp "$coverage_container:/workspace/target/release/octopus" artifacts/octopus
