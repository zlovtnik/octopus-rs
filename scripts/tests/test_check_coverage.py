from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "check_coverage.py"
SPEC = importlib.util.spec_from_file_location("check_coverage", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)


class CoverageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.policy = self.root / "coverage-policy.json"
        self.report = self.root / "lcov.info"
        self.data = {"overall_minimum_line_percentage": 50, "domains": {}}
        for name in sorted(coverage.DOMAINS):
            self.source(f"src/{name}/mod.rs")
            self.data["domains"][name] = {"minimum_line_percentage": 50, "paths": [f"src/{name}"]}
        self.write_policy()
        self.write_report()
        self.write_evidence()

    def write_evidence(self, extra: tuple[str, ...] = ()) -> None:
        files = [f"src/{name}/mod.rs" for name in sorted(coverage.DOMAINS)] + list(extra)
        self.report.with_name("executable-sources.json").write_text(json.dumps({
            "version": 1,
            "sources": {path: hashlib.sha256((self.root / path).read_bytes()).hexdigest() for path in files},
        }))

    def source(self, relative: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("// synthetic production source\n", encoding="utf-8")
        return path

    def write_policy(self) -> None:
        self.policy.write_text(json.dumps(self.data), encoding="utf-8")

    def record(self, source: str, hits: tuple[int, ...] = (1, 0)) -> str:
        return f"SF:{source}\n" + "".join(f"DA:{line},{hit}\n" for line, hit in enumerate(hits, 1)) + "end_of_record\n"

    def write_report(self, absolute: bool = False) -> None:
        self.report.write_text("".join(self.record(str(self.root / f"src/{name}/mod.rs")
                                                      if absolute else f"src/{name}/mod.rs")
                                       for name in sorted(coverage.DOMAINS)), encoding="utf-8")

    def check(self, report: Path | None = None, validate_only: bool = False) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return coverage.check(report or self.report, self.policy, self.root, validate_only)

    def test_equal_threshold_passes(self) -> None:
        self.assertEqual(0, self.check())

    def test_below_domain_or_overall_floor_fails(self) -> None:
        for change in ("domain", "overall"):
            with self.subTest(change=change):
                if change == "domain":
                    self.data["domains"]["config"]["minimum_line_percentage"] = 51
                else:
                    self.data["overall_minimum_line_percentage"] = 51
                self.write_policy()
                self.assertEqual(1, self.check())

    def test_absolute_and_relative_sources_are_equivalent(self) -> None:
        relative = coverage.load_lcov(self.report, self.root)
        self.write_report(absolute=True)
        self.assertEqual(relative, coverage.load_lcov(self.report, self.root))

    def test_repeated_records_merge_by_line_without_inflating_denominator(self) -> None:
        with self.report.open("a") as report:
            report.write(self.record("src/config/mod.rs", (0, 1)))
            report.write(self.record(str(self.root / "src/config/mod.rs"), (2, 0)))
        lines = coverage.load_lcov(self.report, self.root)[Path("src/config/mod.rs")]
        self.assertEqual({1: 2, 2: 1}, lines)

    def test_default_policy_preserves_floors_and_maps_production_sources(self) -> None:
        committed = SCRIPT.parents[1] / "coverage-policy.json"
        policy = json.loads(committed.read_text())
        self.assertEqual(55, policy["overall_minimum_line_percentage"])
        self.assertEqual({"config": 97, "dispatch": 31, "http": 8, "observability": 64,
                          "persistence": 57, "postgres": 29, "processor": 86},
                         {name: domain["minimum_line_percentage"] for name, domain in policy["domains"].items()})
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, coverage.check(None, committed, committed.parent, True))

    def test_validate_policy_requires_all_domains_and_real_sources(self) -> None:
        self.assertEqual(0, self.check(validate_only=True))
        for paths in ([], ["src/missing"]):
            self.data["domains"]["config"]["paths"] = paths
            self.write_policy()
            self.assertEqual(2, self.check(validate_only=True))
        del self.data["domains"]["config"]
        self.write_policy()
        self.assertEqual(2, self.check())

    def test_invalid_floors_fail(self) -> None:
        for value in (-1, 101, 10 ** 1000, float("nan"), float("inf"), "50", True):
            with self.subTest(value=value):
                self.data["overall_minimum_line_percentage"] = value
                self.write_policy()
                self.assertEqual(2, self.check())

    def test_paths_cannot_escape_or_overlap(self) -> None:
        for value in (".", "../src/config", "/src/config", "src/../src/config", "tests/config"):
            with self.subTest(value=value):
                self.data["domains"]["config"]["paths"] = [value]
                self.write_policy()
                self.assertEqual(2, self.check())
        self.data["domains"]["config"]["paths"] = ["src/dispatch/mod.rs"]
        self.write_policy()
        self.assertEqual(2, self.check())

    def test_prefix_collisions_do_not_expand_domains(self) -> None:
        extra = self.source("src/config_extra/mod.rs")
        with self.report.open("a") as report:
            report.write(self.record(str(extra), (0, 0)))
        self.data["overall_minimum_line_percentage"] = 0
        self.write_policy()
        self.assertEqual(0, self.check())

    def test_test_dependency_and_external_sources_do_not_inflate_coverage(self) -> None:
        paths = [self.source(path) for path in ("tests/integration.rs", "src/tests/helpers.rs",
                                               "src/tests.rs", "vendor/dependency/src/lib.rs")]
        paths.append(self.root.parent / "external.rs")
        with self.report.open("a") as report:
            report.write("".join(self.record(str(path), (1,) * 20) for path in paths))
        self.assertEqual(7, len(coverage.load_lcov(self.report, self.root)))
        self.assertEqual(0, self.check())

    def test_declaration_only_modules_may_be_absent_or_have_no_executable_lines(self) -> None:
        declarations = self.source("src/config/declarations.rs")
        declarations.write_text("pub struct Settings;\n")
        self.source("src/lib.rs").write_text("pub mod config;\n")
        self.assertEqual(0, self.check())
        with self.report.open("a") as report:
            report.write(self.record("src/config/declarations.rs", ()))
            report.write(self.record("src/lib.rs", ()))
        self.assertEqual(0, self.check())

    def test_directory_domain_requires_some_measured_executable_coverage(self) -> None:
        records = [self.record(f"src/{name}/mod.rs") for name in sorted(coverage.DOMAINS)
                   if name != "config"]
        self.report.write_text("".join(records))
        self.assertEqual(2, self.check())
        with self.report.open("a") as report:
            report.write(self.record("src/config/mod.rs", ()))
        self.assertEqual(2, self.check())

    def test_exact_file_mappings_require_the_selected_file_to_be_measured(self) -> None:
        self.source("src/config/settings.rs")
        self.data["domains"]["config"]["paths"] = ["src/config/settings.rs"]
        self.write_policy()
        self.assertEqual(2, self.check())
        with self.report.open("a") as report:
            report.write(self.record("src/config/settings.rs", ()))
        self.assertEqual(2, self.check())
        with self.report.open("a") as report:
            report.write(self.record("src/config/settings.rs"))
        self.assertEqual(0, self.check())

    def test_directory_mapping_rejects_omitted_executable_sources(self) -> None:
        executable = self.source("src/config/omitted.rs")
        executable.write_text("pub fn uncalled() -> i32 { 42 }\n")
        self.write_evidence(("src/config/omitted.rs",))
        self.assertEqual(2, self.check())
        with self.report.open("a") as report:
            report.write(self.record("src/config/omitted.rs", (0,)))
        self.data["domains"]["config"]["minimum_line_percentage"] = 0
        self.data["overall_minimum_line_percentage"] = 0
        self.write_policy()
        self.assertEqual(0, self.check())

    def test_overall_rejects_omitted_executable_source_outside_domains(self) -> None:
        self.source("src/main.rs").write_text("fn main() {}\n")
        self.write_evidence(("src/main.rs",))
        self.assertEqual(2, self.check())

    def test_missing_and_stale_executable_evidence_fail_closed(self) -> None:
        evidence = self.report.with_name("executable-sources.json")
        original = evidence.read_text()
        for value in ("{}", "[]", '{"version":1,"sources":{}}'):
            evidence.write_text(value)
            self.assertEqual(2, self.check())
        evidence.unlink()
        self.assertEqual(2, self.check())
        evidence.write_text(original)
        (self.root / "src/config/mod.rs").write_text("pub fn changed() {}\n")
        self.assertEqual(2, self.check())

    def test_all_zero_line_records_fail(self) -> None:
        self.report.write_text("".join(self.record(f"src/{name}/mod.rs", ())
                                       for name in sorted(coverage.DOMAINS)))
        self.assertEqual(2, self.check())

    def test_source_symlink_cannot_escape(self) -> None:
        (self.root / "src/config/outside.rs").symlink_to(self.root.parent / "outside.rs")
        self.data["domains"]["config"]["paths"] = ["src/config/outside.rs"]
        self.write_policy()
        self.assertEqual(2, self.check())

    def test_missing_empty_zero_line_and_malformed_reports_fail(self) -> None:
        for report in ("", "SF:src/config/mod.rs\nend_of_record\n", "invalid\n",
                       "SF:src/config/mod.rs\nDA:1,1\n", "DA:1,1\nend_of_record\n",
                       "SF:src/config/mod.rs\nDA:1,1\nLF:2\nend_of_record\n"):
            with self.subTest(report=report):
                self.report.write_text(report)
                self.assertEqual(2, self.check())
        self.report.unlink()
        self.assertEqual(2, self.check())

    def test_invalid_line_and_hit_counts_fail(self) -> None:
        for value in ("0,1", "-1,1", "1,-1", "1,nan", "1,inf", "1,1.5", "1", "1,1,a,b"):
            with self.subTest(value=value):
                self.report.write_text(f"SF:src/config/mod.rs\nDA:{value}\nend_of_record\n")
                self.assertEqual(2, self.check())

    def test_function_branch_and_summary_counts_are_validated(self) -> None:
        for field in ("LF:-1", "LH:nan", "FNDA:-1,function", "FN:0,function",
                      "FNDA:1", "BRDA:1,0,0,-1", "BRDA:1,0,0,nan", "BRDA:1,0"):
            with self.subTest(field=field):
                self.report.write_text(f"SF:src/config/mod.rs\nDA:1,1\n{field}\nend_of_record\n")
                self.assertEqual(2, self.check())


if __name__ == "__main__":
    unittest.main()
