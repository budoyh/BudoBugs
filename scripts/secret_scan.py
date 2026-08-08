"""Run the local Gitleaks CLI against a repository-contained path without printing secrets."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", default=".", help="repository-contained directory to scan")
    parser.add_argument("--config", default=".gitleaks.toml", help="repository-contained Gitleaks config")
    args = parser.parse_args()

    source = (ROOT / args.path).resolve()
    config = (ROOT / args.config).resolve()
    if ROOT not in source.parents and source != ROOT:
        parser.error("--path must stay inside this repository")
    if not source.is_dir():
        parser.error(f"--path is not a directory: {source}")
    if ROOT not in config.parents or not config.is_file():
        parser.error("--config must name a repository-contained file")

    executable = shutil.which("gitleaks")
    if executable is None:
        print("FAIL: gitleaks is required; secret scanning was not performed", file=sys.stderr)
        return 2

    result = subprocess.run(
        [executable, "detect", "--source", str(source), "--no-git", "--redact", "--config", str(config)],
        cwd=ROOT,
        check=False,
    )
    if result.returncode:
        print("FAIL: gitleaks detected secrets or could not complete", file=sys.stderr)
        return result.returncode
    print("PASS: gitleaks completed with redacted output")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
