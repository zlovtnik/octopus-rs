#!/usr/bin/env python3
"""Run native tests with the selected Rust compiler's LLVM coverage tools."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


class CoverageError(RuntimeError):
    pass


def function_regions(function: dict) -> tuple:
    """Identify compiler-mapped functions independently of test crate hashes."""
    files = tuple(str(Path(path).resolve()) for path in function["filenames"])
    regions = tuple(tuple(region[:4] + region[5:]) for region in function["regions"])
    return files, regions


def production_functions(normal: str, tests: str, root: Path) -> dict[str, str]:
    normal_data, test_data = json.loads(normal), json.loads(tests)
    signatures = {function_regions(function)
                  for data in normal_data["data"] for function in data["functions"]
                  if any(Path(path).resolve().is_relative_to(root / "src")
                         for path in function["filenames"])}
    return {function["name"]: str(Path(function["filenames"][0]).resolve())
            for data in test_data["data"] for function in data["functions"]
            if function_regions(function) in signatures}


def production_lcov(normal: str, shown: list[str], functions: dict[str, str], root: Path) -> tuple[str, str]:
    """Keep LLVM's normal-build executable lines and production-function hits."""
    sources: dict[str, dict[int, int]] = {}
    source = None
    for line in normal.splitlines():
        if line.startswith("SF:"):
            path = Path(line[3:])
            path = (path if path.is_absolute() else root / path).resolve()
            source = str(path) if path.is_relative_to(root / "src") else None
        elif line.startswith("DA:") and source is not None:
            number, hit = map(int, line[3:].split(",")[:2])
            sources.setdefault(source, {})[number] = hit
    seen = set()
    for output in shown:
        source = None
        for line in output.splitlines():
            if line.endswith(":") and line[:-1] in functions:
                seen.add(line[:-1])
                source = functions[line[:-1]]
                continue
            match = re.match(r"^\s*([0-9]+)\|\s*([0-9]+(?:\.[0-9]+)?[kMGTPE]?)\|", line)
            if match and source in sources and int(match[1]) in sources[source]:
                # Coverage thresholds need covered/uncovered, not abbreviated
                # pretty-printed execution counts from llvm-cov show.
                hit = int(float(match[2].rstrip("kMGTPE")) > 0)
                number = int(match[1])
                sources[source][number] = max(sources[source][number], hit)
    if seen != set(functions):
        raise CoverageError("LLVM did not render all selected production functions")
    result = ""
    for source, lines in sorted(sources.items()):
        relative = Path(source).relative_to(root).as_posix()
        result += f"SF:{relative}\n" + "".join(f"DA:{number},{hit}\n" for number, hit in sorted(lines.items())) + "end_of_record\n"
    total = sum(len(lines) for lines in sources.values())
    covered = sum(hit > 0 for lines in sources.values() for hit in lines.values())
    return result, f"Production coverage: {covered}/{total} executable lines covered\n"


def source_evidence(lcov: str, root: Path) -> dict:
    sources = {}
    source = None
    for line in lcov.splitlines():
        if line.startswith("SF:"):
            source = Path(line[3:])
            if not source.is_absolute():
                source = root / source
            source = source.resolve()
        elif line.startswith("DA:") and source is not None and source.is_relative_to(root / "src"):
            relative = source.relative_to(root).as_posix()
            sources[relative] = hashlib.sha256(source.read_bytes()).hexdigest()
    if not sources:
        raise CoverageError("normal build produced no executable production sources")
    return {"version": 1, "sources": sources}


def run(source_root: Path, environment: dict[str, str] | None = None) -> int:
    root = source_root.resolve()
    output = root / "artifacts/octopus-coverage"
    report = output / "lcov.info"
    summary = output / "summary.txt"
    evidence = output / "executable-sources.json"
    # Never leave a previous successful report available after a failed run.
    try:
        report.unlink(missing_ok=True)
        summary.unlink(missing_ok=True)
        evidence.unlink(missing_ok=True)
        for relative in ("Cargo.toml", "Cargo.lock", "src/main.rs"):
            path = root / relative
            if not path.is_file() or not path.stat().st_size:
                raise CoverageError(f"missing {relative}; native runtime is not implemented")
        env = dict(os.environ if environment is None else environment)
        for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET"):
            if env.get(key):
                raise CoverageError(f"unset {key}; coverage requires fixed host instrumentation")
        output.mkdir(parents=True, exist_ok=True)
        target = root / "target/coverage"
        target.mkdir(parents=True, exist_ok=True)
        with (output / "tests.log").open("w", encoding="utf-8") as log:
            def command(arguments: list[str], *, capture_stdout: bool = False) -> str:
                log.write("$ " + " ".join(arguments) + "\n")
                log.flush()
                result = subprocess.run(arguments, cwd=root, env=env, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                if not capture_stdout:
                    log.write(result.stdout)
                    print(result.stdout, end="")
                log.write(result.stderr)
                print(result.stderr, end="", file=sys.stderr)
                log.flush()
                if result.returncode:
                    if capture_stdout:
                        log.write(result.stdout)
                    raise subprocess.CalledProcessError(result.returncode, arguments)
                return result.stdout

            sysroot = Path(command(["rustc", "--print", "sysroot"]).strip())
            version = command(["rustc", "-vV"])
            host = next((line.removeprefix("host: ") for line in version.splitlines()
                         if line.startswith("host: ")), None)
            if not host:
                raise CoverageError("rustc did not report its host target")
            tools = sysroot / "lib/rustlib" / host / "bin"
            profdata = tools / "llvm-profdata"
            cov = tools / "llvm-cov"
            if not profdata.is_file() or not cov.is_file():
                raise CoverageError("selected Rust toolchain is missing llvm-tools-preview")
            env["CARGO_TARGET_DIR"] = str(target / "build")
            env["CARGO_ENCODED_RUSTFLAGS"] = "-Cinstrument-coverage"
            with tempfile.TemporaryDirectory(prefix="profiles-", dir=target) as directory:
                profiles = Path(directory)
                env["LLVM_PROFILE_FILE"] = str(profiles / "%p-%m.profraw")
                cargo = ["cargo", "test", "--locked", "--all-targets", "--target", host]
                messages = command(cargo + ["--no-run", "--message-format=json"], capture_stdout=True)
                objects: set[str] = set()
                has_tests = False
                for line in messages.splitlines():
                    try:
                        message = json.loads(line)
                    except json.JSONDecodeError as error:
                        raise CoverageError("invalid Cargo JSON output") from error
                    if not isinstance(message, dict):
                        raise CoverageError("invalid Cargo JSON message")
                    if message.get("reason") == "compiler-message":
                        rendered = message.get("message", {}).get("rendered") or ""
                        log.write(rendered)
                        print(rendered, end="", file=sys.stderr)
                    if message.get("reason") != "compiler-artifact" or not message.get("executable"):
                        continue
                    if "custom-build" in message.get("target", {}).get("kind", []):
                        continue
                    executable = Path(message["executable"])
                    if not executable.is_absolute():
                        executable = root / executable
                    if not executable.is_file():
                        raise CoverageError(f"Cargo executable does not exist: {executable}")
                    objects.add(str(executable))
                    has_tests |= message.get("profile", {}).get("test") is True
                if not has_tests:
                    raise CoverageError("Cargo produced no test executables")
                command(cargo)
                # Normal compilation supplies production-only function mappings;
                # test executables include inline test functions in src/*.rs.
                normal_messages = command(["cargo", "build", "--locked", "--bins", "--target", host,
                                           "--message-format=json"], capture_stdout=True)
                normal_objects: set[str] = set()
                for line in normal_messages.splitlines():
                    message = json.loads(line)
                    if message.get("reason") != "compiler-artifact":
                        continue
                    if message.get("profile", {}).get("test"):
                        continue
                    manifest = Path(message.get("manifest_path", root / "Cargo.toml")).resolve()
                    if not manifest.is_relative_to(root):
                        continue
                    candidates = [path for path in message.get("filenames", []) if path.endswith(".rlib")]
                    if message.get("executable"):
                        candidates.append(message["executable"])
                    for candidate in candidates:
                        path = Path(candidate)
                        if not path.is_absolute():
                            path = root / path
                        if not path.is_file():
                            raise CoverageError(f"normal Cargo object does not exist: {path}")
                        normal_objects.add(str(path))
                if not normal_objects:
                    raise CoverageError("Cargo produced no normal application objects")
                raw = sorted(profiles.glob("*.profraw"))
                if not raw:
                    raise CoverageError("native tests produced no coverage profiles")
                merged = profiles / "merged.profdata"
                command([str(profdata), "merge", "-sparse", *(str(path) for path in raw),
                         "-o", str(merged)])
                object_arguments = [argument for path in sorted(objects) for argument in ("-object", path)]
                common = [f"-instr-profile={merged}", *object_arguments]
                normal_common = [f"-instr-profile={merged}",
                                 *[arg for path in sorted(normal_objects) for arg in ("-object", path)]]
                normal_json = command([str(cov), "export", *normal_common], capture_stdout=True)
                test_json = command([str(cov), "export", *common], capture_stdout=True)
                names = production_functions(normal_json, test_json, root)
                if not names:
                    raise CoverageError("test objects have no matching production function mappings")
                # Profile symbol hashes differ between test and normal crates.
                # Export matching test functions to retain their production hits,
                # while normal records keep never-called production functions.
                normal_lcov = command([str(cov), "export", "-format=lcov", *normal_common], capture_stdout=True)
                shown = []
                # LLVM export ignores name filters. show applies them before
                # calculating each function's line counts. Bound argument size.
                batch = []
                size = 0
                for name in sorted(names):
                    escaped = re.escape(name)
                    if batch and size + len(escaped) > 16000:
                        selector = "^(" + "|".join(batch) + ")$"
                        shown.append(command([str(cov), "show", "-show-line-counts", "-use-color=false",
                                              f"-name-regex={selector}", *common], capture_stdout=True))
                        batch, size = [], 0
                    batch.append(escaped)
                    size += len(escaped) + 1
                selector = "^(" + "|".join(batch) + ")$"
                shown.append(command([str(cov), "show", "-show-line-counts", "-use-color=false",
                                      f"-name-regex={selector}", *common], capture_stdout=True))
                lcov, text_summary = production_lcov(normal_lcov, shown, names, root)
                if not lcov.strip() or "SF:" not in lcov or "DA:" not in lcov:
                    raise CoverageError("LLVM exported no line coverage")
                summary.write_text(text_summary, encoding="utf-8")
                temporary = output / "lcov.info.partial"
                try:
                    temporary.write_text(lcov, encoding="utf-8")
                    temporary.replace(report)
                    evidence.write_text(json.dumps(source_evidence(normal_lcov, root), sort_keys=True) + "\n",
                                        encoding="utf-8")
                finally:
                    temporary.unlink(missing_ok=True)
                print(f"Coverage report: {report}")
        return 0
    except subprocess.CalledProcessError as error:
        print(f"coverage command failed ({error.returncode}): {' '.join(error.cmd)}", file=sys.stderr)
        return error.returncode if error.returncode > 0 else 1
    except (CoverageError, OSError, KeyError, TypeError, ValueError) as error:
        report.unlink(missing_ok=True)
        evidence.unlink(missing_ok=True)
        print(f"coverage error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(run(Path.cwd()))
