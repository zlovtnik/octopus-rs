from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "run_coverage.py"
SPEC = importlib.util.spec_from_file_location("run_coverage", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class CoverageRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        for relative in ("Cargo.toml", "Cargo.lock", "src/main.rs"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("temporary fixture\n")
        self.sysroot = self.root / "toolchain"
        self.host = "x86_64-unknown-linux-gnu"
        for name in ("llvm-cov", "llvm-profdata"):
            path = self.sysroot / "lib/rustlib" / self.host / "bin" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        self.test_binary = self.root / "test-binary"
        self.app_binary = self.root / "app-binary"
        self.test_binary.touch()
        self.app_binary.touch()
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.failure: str | None = None
        self.produce_profiles = True
        self.produce_test = True
        self.produce_normal = True
        self.report = self.root / "artifacts/octopus-coverage/lcov.info"

    def llvm_json(self, test: bool) -> str:
        function = {"name": "production", "filenames": [str(self.root / "src/main.rs")],
                    "regions": [[1, 1, 1, 10, 0 if not test else 1, 0, 0, 0]]}
        functions = [function]
        if test:
            functions.append({"name": "inline_test", "filenames": [str(self.root / "src/main.rs")],
                              "regions": [[2, 1, 2, 10, 1, 0, 0, 0]]})
        return json.dumps({"data": [{"functions": functions}]})

    def fake_command(self, arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        env = dict(kwargs["env"])
        self.calls.append((arguments, env))
        stdout = ""
        code = 0
        if arguments == ["rustc", "--print", "sysroot"]:
            stdout = str(self.sysroot) + "\n"
        elif arguments == ["rustc", "-vV"]:
            stdout = f"rustc 1.100.0\nhost: {self.host}\n"
        elif arguments[0] == "cargo" and "--no-run" in arguments:
            if self.failure == "compile":
                code = 5
            messages = []
            for binary, test in ((self.test_binary, self.produce_test), (self.app_binary, False)):
                messages.append({"reason": "compiler-artifact", "executable": str(binary),
                                 "target": {"kind": ["bin"]}, "profile": {"test": test}})
            stdout = "\n".join(json.dumps(message) for message in messages)
        elif arguments[:2] == ["cargo", "build"]:
            stdout = json.dumps({"reason": "compiler-artifact", "executable": str(self.app_binary),
                                 "target": {"kind": ["bin"]}, "profile": {"test": False}}) if self.produce_normal else ""
        elif arguments[0] == "cargo":
            if self.failure == "cargo":
                code = 7
            elif self.produce_profiles:
                Path(env["LLVM_PROFILE_FILE"]).with_name("test.profraw").write_text("new profile")
            stdout = "running tests\n"
        elif arguments[1] == "merge":
            if self.failure == "merge":
                code = 9
        elif arguments[1] == "export":
            if self.failure == "export":
                code = 11
            if "-format=lcov" in arguments:
                stdout = "SF:src/main.rs\nDA:1,1\nend_of_record\n"
            else:
                stdout = self.llvm_json(str(self.test_binary) in arguments)
        elif arguments[1] == "show":
            if self.failure == "summary":
                code = 13
            stdout = "production:\n    1|      1|fn production() {}\n"
        else:
            raise AssertionError(arguments)
        return subprocess.CompletedProcess(arguments, code, stdout, "")

    def execute(self, environment: dict[str, str] | None = None) -> int:
        with patch.object(runner.subprocess, "run", side_effect=self.fake_command), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return runner.run(self.root, environment or {})

    def stale_report(self) -> None:
        self.report.parent.mkdir(parents=True, exist_ok=True)
        self.report.write_text("old successful coverage")

    def test_missing_runtime_fails_before_any_tool_and_removes_stale_report(self) -> None:
        (self.root / "Cargo.toml").unlink()
        self.stale_report()
        self.assertEqual(2, self.execute())
        self.assertEqual([], self.calls)
        self.assertFalse(self.report.exists())

    def test_conflicting_flags_or_cross_target_are_rejected(self) -> None:
        for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET"):
            with self.subTest(key=key):
                self.assertEqual(2, self.execute({key: "conflicting value"}))
                self.assertEqual([], self.calls)

    def test_collects_test_and_application_objects_with_identical_host_instrumentation(self) -> None:
        self.assertEqual(0, self.execute({"OCTOPUS_REQUIRE_DOCKER": "true"}))
        compile_call = next(call for call in self.calls if "--no-run" in call[0])
        test_call = next(call for call in self.calls if call[0][:2] == ["cargo", "test"] and "--no-run" not in call[0])
        self.assertEqual(compile_call[1], test_call[1])
        self.assertEqual("true", test_call[1]["OCTOPUS_REQUIRE_DOCKER"])
        self.assertEqual("-Cinstrument-coverage", test_call[1]["CARGO_ENCODED_RUSTFLAGS"])
        self.assertIn("--locked", test_call[0])
        self.assertIn("--all-targets", test_call[0])
        self.assertEqual(self.host, test_call[0][-1])
        export = next(arguments for arguments, _ in self.calls if "show" in arguments)
        self.assertIn(str(self.test_binary), export)
        self.assertIn(str(self.app_binary), export)
        self.assertEqual(2, export.count("-object"))
        self.assertIn("SF:src/main.rs", self.report.read_text())
        selector = next(arg for arg in export if arg.startswith("-name-regex="))
        self.assertIn("production", selector)
        self.assertNotIn("inline_test", selector)
        self.assertTrue(self.report.with_name("executable-sources.json").is_file())
        self.assertIn("running tests", (self.report.parent / "tests.log").read_text())

    def test_only_profiles_from_this_invocation_are_merged(self) -> None:
        old = self.root / "target/coverage/profiles-old/old.profraw"
        old.parent.mkdir(parents=True)
        old.write_text("stale")
        self.assertEqual(0, self.execute())
        merge = next(arguments for arguments, _ in self.calls if "merge" in arguments)
        self.assertNotIn(str(old), merge)
        fresh = [Path(value) for value in merge if value.endswith(".profraw")]
        self.assertEqual(1, len(fresh))
        self.assertEqual("test.profraw", fresh[0].name)
        self.assertFalse(fresh[0].parent.exists())
        self.assertTrue(old.exists())

    def test_command_failures_propagate_and_do_not_publish_old_coverage(self) -> None:
        for command, expected in (("compile", 5), ("cargo", 7), ("merge", 9),
                                  ("export", 11), ("summary", 13)):
            with self.subTest(command=command):
                self.stale_report()
                self.failure = command
                self.assertEqual(expected, self.execute())
                self.assertFalse(self.report.exists())

    def test_absent_profiles_or_test_executables_fail_closed(self) -> None:
        self.produce_profiles = False
        self.assertEqual(2, self.execute())
        self.assertFalse(self.report.exists())
        self.produce_profiles = True
        self.produce_test = False
        self.assertEqual(2, self.execute())
        self.assertFalse(self.report.exists())
        self.produce_test = True
        self.produce_normal = False
        self.assertEqual(2, self.execute())
        self.assertFalse(self.report.exists())

    def test_missing_llvm_component_fails_before_cargo(self) -> None:
        (self.sysroot / "lib/rustlib" / self.host / "bin/llvm-cov").unlink()
        self.assertEqual(2, self.execute())
        self.assertFalse(any(arguments[0] == "cargo" for arguments, _ in self.calls))
        self.assertFalse(self.report.exists())


class RealProductionCoverageTest(unittest.TestCase):
    def test_pinned_toolchain_excludes_inline_tests_but_keeps_production_hits(self) -> None:
        available = subprocess.run(["rustup", "toolchain", "list"], text=True, capture_output=True)
        if available.returncode or not any(line.startswith("1.100.0-") for line in available.stdout.splitlines()):
            self.skipTest("Rust 1.100.0 is unavailable for the real compiler fixture")
        with tempfile.TemporaryDirectory(prefix="octopus-production-coverage-") as directory:
            root = Path(directory).resolve()
            (root / "src").mkdir()
            (root / "Cargo.toml").write_text('[package]\nname="coverage_probe"\nversion="0.1.0"\nedition="2021"\n[workspace]\n')
            (root / "src/lib.rs").write_text("pub mod config;\n")
            (root / "src/config.rs").write_text(
                "pub fn uncalled() -> i32 { 42 } #[cfg(test)] #[test] fn test_on_same_line() { assert_eq!(1, 1); }\n"
                "pub fn called() -> i32 { 7 }\n"
                "#[cfg(test)]\nmod tests {\n    #[test]\n"
                "    fn exercised() { assert_eq!(super::called(), 7); }\n}\n")
            (root / "src/main.rs").write_text('fn main() { println!("{}", coverage_probe::config::called()); }\n')
            env = dict(os.environ, RUSTUP_TOOLCHAIN="1.100.0")
            for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET"):
                env.pop(key, None)
            subprocess.run(["cargo", "generate-lockfile", "--offline"], cwd=root, env=env,
                           capture_output=True, text=True, check=True)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(0, runner.run(root, env))
            report = root / "artifacts/octopus-coverage/lcov.info"
            source = None
            counts = {}
            for line in report.read_text().splitlines():
                if line.startswith("SF:"):
                    source = Path(line[3:])
                elif line.startswith("DA:") and source == Path("src/config.rs"):
                    number, hit = map(int, line[3:].split(",")[:2])
                    counts[number] = max(counts.get(number, 0), hit)
            self.assertEqual({1: 0, 2: 1}, counts,
                             "uncalled production must stay uncovered and inline test lines must be absent")
            self.assertEqual(50.0, 100 * sum(hit > 0 for hit in counts.values()) / len(counts))
            evidence = json.loads(report.with_name("executable-sources.json").read_text())
            self.assertIn("src/config.rs", evidence["sources"])
            self.assertNotIn("src/lib.rs", evidence["sources"], "declarations are not executable")


if __name__ == "__main__":
    unittest.main()
