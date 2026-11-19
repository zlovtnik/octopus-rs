#!/usr/bin/env python3
"""Reconcile migration evidence; this does not execute or prove runtime parity.

Paths in evidence are relative to the umbrella repository. Each completed row
names replacement/retained files, test files with test identifiers, and a saved
verification command/report/exit code. Retired rows require a rationale instead.
Exit 0: valid inventory, 1: incomplete in --require-complete mode, 2: invalid.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


STATUSES = frozenset({"pending", "ported", "replaced", "retained", "retired"})
REVISION = re.compile(r"[0-9a-f]{40}")


class InvalidLedger(ValueError):
    pass


def relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise InvalidLedger(f"{label}: expected a relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {".", "..", ""} for part in value.split("/")):
        raise InvalidLedger(f"{label}: path must not escape or contain empty/dot components")
    return value


def evidence_file(root: Path, value: object, label: str) -> Path:
    relative = relative_path(value, label)
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file() or path.stat().st_size == 0:
        raise InvalidLedger(f"{label}: evidence must be a nonempty file inside the repository: {relative}")
    return path


def nonblank(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InvalidLedger(f"{label}: expected nonblank text")
    return value


def nonempty_list(value: object, label: str) -> list:
    if not isinstance(value, list) or not value:
        raise InvalidLedger(f"{label}: expected a nonempty list")
    return value


def validate(data: object, baseline_files: set[str], current_files: set[str], root: Path) -> Counter:
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise InvalidLedger("schema_version must be 1")
    baseline = data.get("baseline")
    if not isinstance(baseline, dict):
        raise InvalidLedger("missing baseline metadata")
    for name in ("parent_commit", "octopus_commit"):
        if not isinstance(baseline.get(name), str) or not REVISION.fullmatch(baseline[name]):
            raise InvalidLedger(f"baseline.{name}: expected a full lowercase Git revision")
    rows = nonempty_list(data.get("files"), "files")
    seen: set[str] = set()
    statuses: Counter = Counter()
    for row in rows:
        if not isinstance(row, dict):
            raise InvalidLedger("file row must be an object")
        source = relative_path(row.get("source"), "source")
        if source in seen:
            raise InvalidLedger(f"duplicate source row: {source}")
        seen.add(source)
        status = row.get("status")
        if not isinstance(status, str) or status not in STATUSES:
            raise InvalidLedger(f"{source}: missing or invalid status")
        statuses[status] += 1
        files, tests, verification = (row.get(key) for key in ("replacement_files", "tests", "verification"))
        if any(not isinstance(value, list) for value in (files, tests, verification)):
            raise InvalidLedger(f"{source}: replacement_files, tests and verification must be lists")
        for value in files:
            evidence_file(root, value, f"{source} replacement")
        for test in tests:
            if not isinstance(test, dict):
                raise InvalidLedger(f"{source}: test evidence must be an object")
            path = evidence_file(root, test.get("path"), f"{source} test")
            contents = path.read_text(encoding="utf-8")
            for identifier in nonempty_list(test.get("identifiers"), f"{source} test identifiers"):
                nonblank(identifier, f"{source} test identifier")
                if identifier not in contents:
                    raise InvalidLedger(f"{source}: test identifier absent from {test['path']}: {identifier}")
        for run in verification:
            if not isinstance(run, dict):
                raise InvalidLedger(f"{source}: verification evidence must be an object")
            nonblank(run.get("command"), f"{source} verification command")
            evidence_file(root, run.get("report"), f"{source} verification report")
            if type(run.get("exit_code")) is not int or run["exit_code"] != 0:
                raise InvalidLedger(f"{source}: verification must record successful integer exit_code 0")
        if status == "retired":
            nonblank(row.get("reason"), f"{source} retirement reason")
        elif status != "pending":
            for name, value in (("replacement_files", files), ("tests", tests), ("verification", verification)):
                nonempty_list(value, f"{source} completed {name}")
    for label, expected in (("baseline", baseline_files), ("current tracked inventory", current_files)):
        missing, extra = sorted(expected - seen), sorted(seen - expected)
        if missing or extra:
            raise InvalidLedger(f"{label} mismatch: missing rows={missing}; removed or unexpected rows={extra}")
    return statuses


def git(root: Path, *args: str) -> bytes:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)
    if result.returncode:
        raise InvalidLedger(f"Git inventory lookup failed: {' '.join(args)}")
    return result.stdout


def check(ledger: Path, root: Path, require_complete: bool = False) -> int:
    try:
        data = json.loads(ledger.read_text(encoding="utf-8"))
        # Validate shape before using revisions as Git arguments.
        if not isinstance(data, dict) or not isinstance(data.get("baseline"), dict):
            raise InvalidLedger("missing baseline metadata")
        baseline = data["baseline"]
        for name in ("parent_commit", "octopus_commit"):
            if not isinstance(baseline.get(name), str) or not REVISION.fullmatch(baseline[name]):
                raise InvalidLedger(f"baseline.{name}: expected a full lowercase Git revision")
        source = root / "services/octopus"
        pin = git(root, "rev-parse", f"{baseline['parent_commit']}:services/octopus").decode().strip()
        if pin != baseline["octopus_commit"]:
            raise InvalidLedger("baseline parent gitlink does not match octopus_commit")
        original = set(git(source, "ls-tree", "-rz", "--name-only", baseline["octopus_commit"]).decode().split("\0")) - {""}
        current = set(git(source, "ls-files", "-z").decode().split("\0")) - {""}
        statuses = validate(data, original, current, root)
        for name in current:
            if not (source / name).is_file():
                raise InvalidLedger(f"tracked source is missing from working tree: {name}")
        print(f"Reconciled {sum(statuses.values())} files: " + ", ".join(f"{key}={statuses[key]}" for key in sorted(statuses)))
        if require_complete and statuses["pending"]:
            print("Migration incomplete: pending dispositions remain", file=sys.stderr)
            return 1
        print("Recorded evidence validated; behavioral parity requires independent review and execution.")
        return 0
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Invalid migration ledger: {error}", file=sys.stderr)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--ledger", type=Path, default=Path(__file__).resolve().parents[1] / "migration-ledger.json")
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    return check(args.ledger, args.repo_root.resolve(), args.require_complete)


if __name__ == "__main__":
    sys.exit(main())
