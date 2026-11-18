from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "check_migration.py"
SPEC = importlib.util.spec_from_file_location("check_migration", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
migration = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(migration)


class MigrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.files = {"src/main/Runtime.scala", "src/test/RuntimeSuite.scala"}
        self.data = {
            "schema_version": 1,
            "baseline": {"parent_commit": "a" * 40, "octopus_commit": "b" * 40},
            "files": [{"source": source, "status": "pending", "replacement_files": [],
                       "tests": [], "verification": [], "reason": ""} for source in sorted(self.files)],
        }
        for source in self.files:
            self.write("services/octopus/" + source, "baseline fixture\n")
        self.write("services/octopus-rust/src/lib.rs", "pub fn contract() {}\n")
        self.write("services/octopus-rust/tests/contract.rs", "fn preserves_contract() {}\n")
        self.write("artifacts/native-test.log", "test preserves_contract ... ok\n")

    def write(self, name: str, content: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def validate(self):
        return migration.validate(self.data, self.files, self.files, self.root)

    def complete(self, status: str = "ported") -> dict:
        row = self.data["files"][0]
        row.update(status=status, replacement_files=["services/octopus-rust/src/lib.rs"],
                   tests=[{"path": "services/octopus-rust/tests/contract.rs", "identifiers": ["preserves_contract"]}],
                   verification=[{"command": "cargo test --locked", "report": "artifacts/native-test.log", "exit_code": 0}])
        return row

    def test_pending_inventory_is_valid_without_claiming_completion(self):
        self.assertEqual({"pending": 2}, self.validate())

    def test_each_completed_disposition_needs_real_evidence(self):
        for status in ("ported", "replaced", "retained"):
            with self.subTest(status=status):
                self.complete(status)
                self.assertEqual(1, self.validate()[status])
                for field in ("replacement_files", "tests", "verification"):
                    saved = self.data["files"][0][field]
                    self.data["files"][0][field] = []
                    with self.assertRaises(migration.InvalidLedger):
                        self.validate()
                    self.data["files"][0][field] = saved

    def test_retirement_requires_a_specific_reason(self):
        row = self.data["files"][0]
        row["status"] = "retired"
        with self.assertRaisesRegex(migration.InvalidLedger, "retirement reason"):
            self.validate()
        row["reason"] = "JVM-only bytecode assertion replaced at native cutover"
        self.assertEqual(1, self.validate()["retired"])

    def test_missing_duplicate_and_unknown_sources_fail(self):
        original = copy.deepcopy(self.data)
        for rows in (original["files"][:1], original["files"] * 2,
                     original["files"] + [dict(original["files"][0], source="unknown.scala")]):
            self.data = dict(original, files=rows)
            with self.assertRaises(migration.InvalidLedger):
                self.validate()

    def test_added_and_removed_tracked_inputs_require_reconciliation(self):
        for current in (self.files | {"new.scala"}, self.files - {"src/main/Runtime.scala"}):
            with self.assertRaisesRegex(migration.InvalidLedger, "current tracked inventory mismatch"):
                migration.validate(self.data, self.files, current, self.root)
        with self.assertRaisesRegex(migration.InvalidLedger, "baseline mismatch"):
            migration.validate(self.data, self.files | {"omitted.scala"}, self.files, self.root)

    def test_missing_and_invalid_status_or_schema_fail(self):
        for status in (None, "complete", [], True):
            self.data["files"][0]["status"] = status
            with self.assertRaises(migration.InvalidLedger):
                self.validate()
        self.data["schema_version"] = True
        with self.assertRaisesRegex(migration.InvalidLedger, "schema_version"):
            self.validate()

    def test_missing_empty_or_escaping_evidence_fails(self):
        row = self.complete()
        self.write("empty.rs", "")
        for name in ("missing.rs", "empty.rs", "../external.rs", "/etc/passwd", "src/../lib.rs", "src//lib.rs"):
            row["replacement_files"] = [name]
            with self.assertRaises(migration.InvalidLedger):
                self.validate()

    def test_evidence_symlink_may_not_escape_repository(self):
        row = self.complete()
        outside = Path(self.directory.name).parent / (self.root.name + "-outside.rs")
        outside.write_text("external fixture\n")
        self.addCleanup(outside.unlink)
        (self.root / "escape.rs").symlink_to(outside)
        row["replacement_files"] = ["escape.rs"]
        with self.assertRaises(migration.InvalidLedger):
            self.validate()

    def test_unknown_test_identifier_and_failed_verification_fail(self):
        row = self.complete()
        row["tests"][0]["identifiers"] = ["missing_test"]
        with self.assertRaisesRegex(migration.InvalidLedger, "test identifier absent"):
            self.validate()
        row = self.complete()
        for exit_code in (1, -1, None, False, "0"):
            row["verification"][0]["exit_code"] = exit_code
            with self.assertRaisesRegex(migration.InvalidLedger, "exit_code"):
                self.validate()
        row = self.complete()
        row["verification"][0]["command"] = " "
        with self.assertRaisesRegex(migration.InvalidLedger, "command"):
            self.validate()

    def check(self, complete: bool = False, pin: bytes | None = None) -> int:
        ledger = self.write("ledger.json", json.dumps(self.data))
        inventory = ("\0".join(sorted(self.files)) + "\0").encode()
        with mock.patch.object(migration, "git", side_effect=[pin or ("b" * 40).encode(), inventory, inventory]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return migration.check(ledger, self.root, complete)

    def test_complete_mode_distinguishes_pending_from_invalid(self):
        self.assertEqual(0, self.check())
        self.assertEqual(1, self.check(complete=True))
        self.assertEqual(2, self.check(pin=("c" * 40).encode()))
        self.complete()
        self.data["files"][1]["status"] = "retired"
        self.data["files"][1]["reason"] = "JVM harness intentionally replaced"
        self.assertEqual(0, self.check(complete=True))

    def test_deleted_working_tree_source_fails_even_when_still_tracked(self):
        (self.root / "services/octopus/src/main/Runtime.scala").unlink()
        self.assertEqual(2, self.check())

    def test_malformed_json_and_missing_revision_fail_without_git(self):
        for content in ("{", "[]", '{"baseline":{}}'):
            ledger = self.write("invalid.json", content)
            with mock.patch.object(migration, "git") as git, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(2, migration.check(ledger, self.root))
                git.assert_not_called()

    def test_committed_ledger_has_every_baseline_row(self):
        data = json.loads((SCRIPT.parents[1] / "migration-ledger.json").read_text())
        self.assertEqual("9a89488e872cded6b76735fb30750e0042609e31", data["baseline"]["parent_commit"])
        self.assertEqual("6e94b74f219ab56a6c6104c4baa5bedf75fbce28", data["baseline"]["octopus_commit"])
        self.assertEqual(262, len(data["files"]))
        self.assertEqual(262, len({row["source"] for row in data["files"]}))
        self.assertTrue(all(row["status"] in migration.STATUSES for row in data["files"]))


if __name__ == "__main__":
    unittest.main()
