from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class DeliveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.root = self.base / "scaffold"
        shutil.copytree(ROOT / "scripts", self.root / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy(ROOT / "coverage-policy.json", self.root / "coverage-policy.json")
        self.log = self.base / "docker.jsonl"
        commands = self.base / "commands"
        commands.mkdir()
        docker = commands / "docker"
        docker.write_text("""#!/usr/bin/env python3
import json
import os
import sys
args = sys.argv[1:]
with open(os.environ['DOCKER_CALLS'], 'a') as log:
    log.write(json.dumps(args) + '\\n')
if args[0] == 'run':
    sys.stdin.buffer.read()
if args[0] == 'ps':
    print('owned-container')
if args[0] == os.environ.get('FAIL_DOCKER_COMMAND'):
    sys.exit(17)
""", encoding="utf-8")
        docker.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{commands}:{os.environ['PATH']}",
                        DOCKER_CALLS=str(self.log), CI_USE_DOCKER_CONTEXT="false")
        self.env["OCTOPUS_UMBRELLA_ROOT"] = str(self.base)
        for name in ("sql/postgres/octopus_core/manifest.yaml", "k8s/postgres-schema-executor/entrypoint.sh"):
            path = self.base / name
            path.parent.mkdir(parents=True)
            path.write_text("fixture\n")

    def runtime_inputs(self, map_domains: bool = True) -> None:
        # Temporary inputs exercise the delivery guard; no application is built.
        shutil.copy(ROOT / "templates/Cargo.toml.example", self.root / "Cargo.toml")
        (self.root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        (self.root / "src").mkdir()
        for directory in ("resources", "tests"):
            (self.root / directory).mkdir()
        shutil.copy(ROOT / "rust-toolchain.toml", self.root)
        (self.root / "src/main.rs").write_text("// preflight fixture\n", encoding="utf-8")
        policy = json.loads((self.root / "coverage-policy.json").read_text())
        for name, domain in policy["domains"].items():
            path = f"src/{name}.rs"
            (self.root / path).write_text("// policy mapping fixture\n", encoding="utf-8")
            domain["paths"] = [path]
        if not map_domains:
            policy["domains"]["config"]["paths"] = []
        (self.root / "coverage-policy.json").write_text(json.dumps(policy), encoding="utf-8")

    def run_native(self, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["bash", str(self.root / "scripts/ci/native.sh")],
                              cwd=self.base, env=dict(self.env, **env),
                              capture_output=True, text=True, timeout=15)

    def calls(self) -> list[list[str]]:
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_missing_runtime_fails_before_docker_or_parent_cargo(self) -> None:
        result = self.run_native()
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertIn("missing Cargo.toml", result.stderr)
        self.assertEqual([], self.calls())
        self.runtime_inputs()
        for missing in ("Cargo.lock", "src/main.rs"):
            path = self.root / missing
            content = path.read_text()
            path.unlink()
            result = self.run_native()
            self.assertEqual(2, result.returncode, result.stderr)
            self.assertIn(f"missing {missing}", result.stderr)
            self.assertEqual([], self.calls())
            path.write_text(content)

    def test_unmapped_coverage_blocks_native_validation(self) -> None:
        self.runtime_inputs(map_domains=False)
        result = self.run_native()
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertIn("unmapped coverage domain", result.stderr)
        self.assertEqual([], self.calls())

    def test_artifacts_are_copied_before_cleanup(self) -> None:
        self.runtime_inputs()
        result = self.run_native()
        self.assertEqual(0, result.returncode, result.stderr)
        calls = self.calls()
        copies = [i for i, args in enumerate(calls) if args[0] == "cp"]
        removal = next(i for i, args in enumerate(calls) if args[0] == "rm")
        self.assertEqual(2, len(copies))
        self.assertLess(max(copies), removal)
        run = next(args for args in calls if args[0] == "run")
        self.assertNotIn("--rm", run)
        self.assertIn("rust:1.100.0-bookworm", run)
        self.assertIn("/var/run/docker.sock:/var/run/docker.sock", run)
        self.assertEqual("host", run[run.index("--network") + 1])

    def test_native_task_provisions_required_test_tools_before_docker_gate(self) -> None:
        task = (ROOT / "scripts/ci/tasks/native.sh").read_text()
        install = next(line for line in task.splitlines() if line.startswith("apt-get install "))
        packages = install.split()
        for package in ("python3", "docker.io", "cmake", "pkg-config", "libssl-dev"):
            self.assertIn(package, packages)
        self.assertLess(task.index(install), task.index("export OCTOPUS_REQUIRE_DOCKER=true"))
        self.assertLess(task.index(install), task.index("python3 scripts/run_coverage.py"))

    def test_container_failure_collects_diagnostics_before_cleanup(self) -> None:
        self.runtime_inputs()
        result = self.run_native(FAIL_DOCKER_COMMAND="run")
        self.assertEqual(17, result.returncode, result.stderr)
        calls = self.calls()
        copies = [args for args in calls if args[0] == "cp"]
        run = next(args for args in calls if args[0] == "run")
        container = run[run.index("--name") + 1]
        self.assertEqual(copies, [[
            "cp", f"{container}:/workspace/artifacts/octopus-coverage/.",
            "artifacts/octopus-coverage/",
        ]])
        self.assertLess(calls.index(copies[0]), next(i for i, args in enumerate(calls) if args[0] == "rm"))

    def test_artifact_copy_failure_is_preserved_during_cleanup(self) -> None:
        self.runtime_inputs()
        result = self.run_native(FAIL_DOCKER_COMMAND="cp")
        self.assertEqual(17, result.returncode, result.stderr)
        self.assertTrue(any(args[0] == "rm" for args in self.calls()))

    def test_unavailable_docker_cannot_skip_native_tests(self) -> None:
        self.runtime_inputs()
        result = self.run_native(FAIL_DOCKER_COMMAND="info")
        self.assertEqual(17, result.returncode, result.stderr)
        self.assertFalse(any(args[0] in {"run", "cp"} for args in self.calls()))

    def test_shared_helpers_match_umbrella_repository(self) -> None:
        parent = ROOT.parents[1] / "scripts/ci"
        if not parent.is_dir():
            self.skipTest("standalone scaffold checkout has no umbrella helpers")
        for filename in ("common.sh", "cleanup.sh"):
            self.assertEqual((parent / filename).read_bytes(),
                             (ROOT / "scripts/ci" / filename).read_bytes())


if __name__ == "__main__":
    unittest.main()
