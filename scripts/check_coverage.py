#!/usr/bin/env python3
"""Enforce Octopus Rust line coverage from LCOV; unmapped domains fail closed."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path


DOMAINS = {"config", "dispatch", "http", "observability", "persistence", "postgres", "processor"}
EXCLUDED_PARTS = {"test", "tests", "benches", "examples", "vendor", "target", ".cargo"}


def percentage(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("coverage floors must be numbers")
    if not 0 <= value <= 100 or not math.isfinite(value):
        raise ValueError("coverage floors must be finite percentages between 0 and 100")
    return float(value)


def production_path(path: Path, root: Path) -> Path | None:
    try:
        relative = path.resolve().relative_to(root)
    except ValueError:
        return None
    if (len(relative.parts) < 2 or relative.parts[0] != "src" or relative.suffix != ".rs"
            or EXCLUDED_PARTS.intersection(relative.parts)
            or relative.name in {"test.rs", "tests.rs"}):
        return None
    return relative


def load_policy(path: Path, root: Path) -> tuple[float, dict[str, tuple[float, set[Path], set[Path]]]]:
    policy = json.loads(path.read_text(encoding="utf-8"))
    overall = percentage(policy["overall_minimum_line_percentage"])
    domains = policy["domains"]
    if not isinstance(domains, dict) or set(domains) != DOMAINS:
        raise ValueError("policy must map exactly these domains: " + ", ".join(sorted(DOMAINS)))
    mapped: dict[str, tuple[float, set[Path], set[Path]]] = {}
    prefixes: list[Path] = []
    for name, domain in sorted(domains.items()):
        floor = percentage(domain["minimum_line_percentage"])
        paths = domain["paths"]
        if not isinstance(paths, list) or not paths:
            raise ValueError(f"unmapped coverage domain: {name}")
        files: set[Path] = set()
        exact_files: set[Path] = set()
        for raw in paths:
            if not isinstance(raw, str) or not raw or "\\" in raw:
                raise ValueError(f"invalid coverage path in {name}")
            relative = Path(raw)
            if (not relative.parts or relative.is_absolute() or ".." in relative.parts
                    or relative.parts[0] != "src"):
                raise ValueError(f"coverage path must stay under src/: {raw}")
            absolute = (root / relative).resolve()
            if not absolute.is_relative_to(root / "src"):
                raise ValueError(f"coverage path escapes src/: {raw}")
            canonical = absolute.relative_to(root)
            if any(canonical == prior or canonical.is_relative_to(prior)
                   or prior.is_relative_to(canonical) for prior in prefixes):
                raise ValueError(f"overlapping coverage path: {raw}")
            prefixes.append(canonical)
            candidates = absolute.rglob("*.rs") if absolute.is_dir() else [absolute]
            selected = {item for candidate in candidates
                        if candidate.is_file() and (item := production_path(candidate, root)) is not None}
            if not selected:
                raise ValueError(f"coverage path has no production Rust files: {raw}")
            files.update(selected)
            if absolute.is_file():
                exact_files.update(selected)
        mapped[name] = (floor, files, exact_files)
    return overall, mapped


def integer(raw: str, context: str, minimum: int = 0) -> int:
    if not re.fullmatch(r"[0-9]+", raw) or int(raw) < minimum:
        raise ValueError(f"invalid {context}: {raw}")
    return int(raw)


def load_lcov(path: Path, root: Path) -> dict[Path, dict[int, int]]:
    coverage: dict[Path, dict[int, int]] = {}
    source: Path | None = None
    lines: dict[int, int] = {}
    summaries: dict[str, int] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw:
            continue
        if raw == "end_of_record":
            if source is None:
                raise ValueError(f"LCOV record has no source at line {number}")
            if "LF" in summaries and summaries["LF"] != len(lines):
                raise ValueError("LCOV LF does not match executable lines")
            if "LH" in summaries and summaries["LH"] != sum(hit > 0 for hit in lines.values()):
                raise ValueError("LCOV LH does not match covered lines")
            relative = production_path(source, root)
            if relative is not None:
                if not source.is_file():
                    raise ValueError(f"LCOV source does not exist: {relative}")
                if lines:
                    merged = coverage.setdefault(relative, {})
                    for line, hit in lines.items():
                        merged[line] = max(merged.get(line, 0), hit)
            source, lines, summaries = None, {}, {}
            continue
        key, separator, value = raw.partition(":")
        if not separator:
            raise ValueError(f"malformed LCOV at line {number}")
        if key == "TN" and source is None:
            continue
        if key == "SF":
            if source is not None or not value:
                raise ValueError(f"invalid LCOV source at line {number}")
            source = Path(value)
            if not source.is_absolute():
                source = root / source
            continue
        if source is None:
            raise ValueError(f"LCOV field outside a source record at line {number}")
        if key == "DA":
            parts = value.split(",")
            if len(parts) not in (2, 3):
                raise ValueError(f"invalid LCOV DA at line {number}")
            line, hit = integer(parts[0], "line number", 1), integer(parts[1], "hit count")
            lines[line] = max(lines.get(line, 0), hit)
        elif key in {"LF", "LH", "FNF", "FNH", "BRF", "BRH"}:
            summaries[key] = integer(value, key)
        elif key in {"FN", "FNDA"}:
            count, comma, name = value.partition(",")
            if not comma or not name:
                raise ValueError(f"invalid LCOV {key} at line {number}")
            integer(count, key, 1 if key == "FN" else 0)
        elif key == "BRDA":
            parts = value.split(",")
            if len(parts) != 4 or not parts[2]:
                raise ValueError(f"invalid LCOV BRDA at line {number}")
            integer(parts[0], "branch line", 1)
            integer(parts[1], "branch block")
            if parts[3] != "-":
                integer(parts[3], "branch hit count")
        elif key == "VER":
            continue
        else:
            raise ValueError(f"unsupported LCOV field {key} at line {number}")
    if source is not None:
        raise ValueError("unterminated LCOV source record")
    if not coverage:
        raise ValueError("LCOV report has no production executable lines")
    return coverage


def check(report: Path | None, policy: Path, root: Path, validate_only: bool = False) -> int:
    try:
        root = root.resolve(strict=True)
        overall, domains = load_policy(policy, root)
        if validate_only:
            print("coverage policy: all domains mapped to production Rust sources")
            return 0
        if report is None:
            raise ValueError("an LCOV report is required")
        coverage = load_lcov(report, root)
        evidence = json.loads(report.with_name("executable-sources.json").read_text(encoding="utf-8"))
        if (not isinstance(evidence, dict) or evidence.get("version") != 1
                or not isinstance(evidence.get("sources"), dict) or not evidence["sources"]):
            raise ValueError("missing executable-source evidence from the normal production build")
        executable_sources = set()
        for raw, digest in evidence["sources"].items():
            path = Path(raw)
            if (path.is_absolute() or ".." in path.parts
                    or production_path(root / path, root) != path
                    or hashlib.sha256((root / path).read_bytes()).hexdigest() != digest):
                raise ValueError(f"invalid or stale executable-source evidence: {raw}")
            executable_sources.add(path)
        checks = [("overall", overall, set(coverage) | executable_sources, set())]
        checks.extend((name, floor, files, exact_files)
                      for name, (floor, files, exact_files) in sorted(domains.items()))
        failed = False
        for name, floor, files, exact_files in checks:
            missing = (exact_files | (files & executable_sources)) - coverage.keys()
            if missing:
                raise ValueError(f"LCOV report omits {name} sources: " + ", ".join(map(str, sorted(missing))))
            files = files.intersection(coverage)
            if not files:
                raise ValueError(f"LCOV report has no executable coverage for domain: {name}")
            total = sum(len(coverage[file]) for file in files)
            covered = sum(hit > 0 for file in files for hit in coverage[file].values())
            actual = covered * 100.0 / total
            passed = actual >= floor
            failed |= not passed
            print(f"{name}: {actual:.2f}% line coverage (minimum {floor:.2f}%) "
                  f"{'OK' if passed else 'FAILED'}")
        return 1 if failed else 0
    except (OSError, UnicodeError, KeyError, TypeError, ValueError) as error:
        print(f"invalid coverage input: {error}", file=sys.stderr)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", nargs="?", type=Path, help="LCOV line coverage report")
    parser.add_argument("--policy", type=Path, default=Path("coverage-policy.json"))
    parser.add_argument("--source-root", type=Path, default=Path.cwd())
    parser.add_argument("--validate-policy", action="store_true", help="require complete domain mappings")
    arguments = parser.parse_args()
    return check(arguments.report, arguments.policy, arguments.source_root, arguments.validate_policy)


if __name__ == "__main__":
    raise SystemExit(main())
