"""Create a fail-closed OpenVEX assessment for the isolated fixture image."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RAW_REPORT = ROOT / "release" / "scans" / "grype-fixture-raw.json"
OUTPUT = ROOT / "release" / "scans" / "fixture.openvex.json"
REVIEW_OUTPUT = ROOT / "release" / "scans" / "fixture-vex-review.json"
FIXTURE_SOURCE = ROOT / "src" / "budobugs" / "labs" / "fixture_app.py"
SEVERE = {"HIGH", "CRITICAL"}

# Every entry is deliberately tied to one exact package/version/CVE tuple. A new
# scanner match cannot inherit an old decision: the set-equality gate below fails.
ASSESSMENTS: dict[tuple[str, str, str], dict[str, Any]] = {
    ("python", "3.12.13", "CVE-2026-11940"): {
        "justification": "vulnerable_code_not_in_execute_path",
        "impact": "The fixture has no archive upload or extraction path and never imports or calls tarfile.",
        "references": ["https://github.com/python/cpython/issues/151558"],
    },
    ("python", "3.12.13", "CVE-2026-11972"): {
        "justification": "vulnerable_code_not_in_execute_path",
        "impact": "The fixture never opens tar archives or invokes tarfile streaming mode.",
        "references": ["https://github.com/python/cpython/issues/151981"],
    },
    ("python", "3.12.13", "CVE-2026-15308"): {
        "justification": "vulnerable_code_not_in_execute_path",
        "impact": "The fixture uses html.escape only; it never instantiates HTMLParser or parses attacker HTML.",
        "references": ["https://github.com/python/cpython/issues/153030"],
    },
    ("python", "3.12.13", "CVE-2026-3298"): {
        "justification": "component_not_present",
        "impact": "The image is Linux/Alpine; the affected Windows-only Proactor event-loop implementation is absent.",
        "references": ["https://github.com/python/cpython/issues/148808"],
    },
    ("python", "3.12.13", "CVE-2026-3644"): {
        "justification": "vulnerable_code_not_in_execute_path",
        "impact": "The fixture never imports http.cookies or invokes Morsel update, pickle, or js_output paths.",
        "references": ["https://github.com/python/cpython/issues/145599"],
    },
    ("python", "3.12.13", "CVE-2026-4224"): {
        "justification": "vulnerable_code_not_in_execute_path",
        "impact": "The fixture has no XML or DTD parsing path and never registers an Expat ElementDeclHandler.",
        "references": ["https://github.com/python/cpython/issues/145986"],
    },
    ("python", "3.12.13", "CVE-2026-4786"): {
        "justification": "vulnerable_code_not_in_execute_path",
        "impact": "The fixture never imports webbrowser or forwards URLs to a browser command or shell.",
        "references": ["https://github.com/python/cpython/issues/148169"],
    },
    ("python", "3.12.13", "CVE-2026-6100"): {
        "justification": "vulnerable_code_not_in_execute_path",
        "impact": "The fixture performs no gzip, bz2, or lzma decompression and cannot reuse a failed decompressor.",
        "references": ["https://github.com/python/cpython/issues/148395"],
    },
    ("python", "3.12.13", "CVE-2026-7210"): {
        "justification": "vulnerable_code_not_in_execute_path",
        "impact": "The fixture accepts no XML documents and never invokes Expat or ElementTree parsing.",
        "references": ["https://github.com/python/cpython/issues/149018"],
    },
    ("python", "3.12.13", "CVE-2026-9669"): {
        "justification": "vulnerable_code_not_in_execute_path",
        "impact": "The fixture performs no bz2 decompression and cannot reuse a BZ2Decompressor after an error.",
        "references": ["https://github.com/python/cpython/issues/150599"],
    },
    ("sqlite-libs", "3.51.2-r0", "CVE-2026-11822"): {
        "justification": "vulnerable_code_not_in_execute_path",
        "impact": "The fixture is backed only by in-memory dictionaries; it accepts no database, SQL, or FTS5 input.",
        "references": [
            "https://sqlite.org/cves.html",
            "https://sqlite.org/releaselog/3_53_2.html",
        ],
    },
    ("sqlite-libs", "3.51.2-r0", "CVE-2026-11824"): {
        "justification": "vulnerable_code_not_in_execute_path",
        "impact": "The fixture is backed only by in-memory dictionaries; it accepts no database, SQL, or FTS5 input.",
        "references": [
            "https://sqlite.org/cves.html",
            "https://sqlite.org/releaselog/3_53_2.html",
        ],
    },
}

# These exact tokens cover every affected API named by the assessments. If the
# fixture later starts using one, release generation stops before producing VEX.
PROHIBITED_FIXTURE_TOKENS = {
    "tarfile": "archive parsing",
    "HTMLParser": "incremental HTML parsing",
    "http.cookies": "cookie serialization",
    "ElementDeclHandler": "Expat DTD declarations",
    "webbrowser": "browser command execution",
    "LZMADecompressor": "streaming decompression",
    "BZ2Decompressor": "streaming decompression",
    "xml.parsers": "XML parsing",
    "ElementTree": "XML parsing",
    "sqlite3": "SQLite access",
    "sqlalchemy": "SQLite access",
    "FTS5": "SQLite full-text search",
}


def write_json(path: Path, payload: dict[str, Any]) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent, delete=False) as handle:
        handle.write(text)
        temporary = Path(handle.name)
    os.replace(temporary, path)


def main() -> int:
    fixture_text = FIXTURE_SOURCE.read_text(encoding="utf-8")
    prohibited = sorted(token for token in PROHIBITED_FIXTURE_TOKENS if token in fixture_text)
    if prohibited:
        raise SystemExit(f"fixture source now reaches a VEX-prohibited API: {prohibited}")

    payload = json.loads(RAW_REPORT.read_text(encoding="utf-8"))
    manifest = payload.get("source", {}).get("target", {}).get("manifestDigest")
    if not isinstance(manifest, str) or not manifest.startswith("sha256:"):
        raise SystemExit("Grype raw report has no image manifest digest")
    distro = payload.get("distro", {})
    if distro.get("name") != "alpine" or not str(distro.get("version", "")).startswith("3.23"):
        raise SystemExit(f"fixture VEX is restricted to Alpine 3.23, observed={distro!r}")

    severe = [
        match
        for match in payload.get("matches", [])
        if str(match.get("vulnerability", {}).get("severity", "")).upper() in SEVERE
    ]
    observed = {
        (match["artifact"]["name"], match["artifact"]["version"], match["vulnerability"]["id"]): match
        for match in severe
    }
    expected = set(ASSESSMENTS)
    if set(observed) != expected or len(severe) != len(observed):
        unexpected = sorted(set(observed) - expected)
        missing = sorted(expected - set(observed))
        duplicate_count = len(severe) - len(observed)
        raise SystemExit(
            f"Grype severe-match set changed; unexpected={unexpected}; missing={missing}; duplicates={duplicate_count}"
        )

    # The archive preserves the local image tag but has no RepoDigests entry, so
    # Grype identifies this scan by the tag. The canonical OCI identifier is also
    # emitted for consumers scanning the same manifest after registry publication.
    tag_product = "budobugs/fixture:local"
    encoded_manifest = manifest.replace(":", "%3A", 1)
    digest_product = f"pkg:oci/fixture@{encoded_manifest}?repository_url=index.docker.io%2Fbudobugs"
    timestamp = datetime.now(UTC).isoformat()
    statements: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    for key in sorted(observed):
        package, version, cve = key
        match = observed[key]
        assessment = ASSESSMENTS[key]
        purl = match.get("artifact", {}).get("purl")
        if not isinstance(purl, str) or not purl.startswith("pkg:"):
            raise SystemExit(f"Grype match has no package URL: {key}")
        statements.append(
            {
                "vulnerability": {"name": cve},
                "products": [
                    {"@id": tag_product, "subcomponents": [{"@id": purl}]},
                    {"@id": digest_product, "subcomponents": [{"@id": purl}]},
                ],
                "status": "not_affected",
                "justification": assessment["justification"],
                "impact_statement": assessment["impact"],
                "timestamp": timestamp,
            }
        )
        decisions.append(
            {
                "artifact": package,
                "version": version,
                "purl": purl,
                "vulnerability": cve,
                "severity": match["vulnerability"]["severity"],
                "namespace": match["vulnerability"]["namespace"],
                "match_types": sorted(detail["type"] for detail in match.get("matchDetails", [])),
                "status": "not_affected",
                "justification": assessment["justification"],
                "impact_statement": assessment["impact"],
                "references": assessment["references"],
            }
        )

    document = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://github.com/budoyh/BudoBugs/vex/fixture/{manifest.removeprefix('sha256:')}",
        "author": "BudoBugs release process",
        "role": "Document Creator",
        "timestamp": timestamp,
        "version": 1,
        "statements": statements,
    }
    review = {
        "schema_version": 1,
        "image_manifest": manifest,
        "distro": distro,
        "fixture_source": FIXTURE_SOURCE.relative_to(ROOT).as_posix(),
        "fixture_source_sha256": hashlib.sha256(fixture_text.encode()).hexdigest(),
        "control": {
            "prohibited_tokens_absent": sorted(PROHIBITED_FIXTURE_TOKENS),
            "review_scope": "All High/Critical matches in the unfiltered Grype report",
        },
        "decisions": decisions,
    }
    write_json(OUTPUT, document)
    write_json(REVIEW_OUTPUT, review)
    print(f"generated {OUTPUT.relative_to(ROOT)} and {REVIEW_OUTPUT.relative_to(ROOT)} ({len(statements)} decisions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
