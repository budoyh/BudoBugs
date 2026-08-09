"""Build immutable, hash-addressed, redacted per-finding evidence packs."""

from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

import yaml

from budobugs.core.io import atomic_write_json, atomic_write_text, sha256_file
from budobugs.core.paths import PathBoundaryError, safe_join
from budobugs.core.redaction import contains_unredacted_secret
from budobugs.models import ControlExperiment, Critique, Finding, HttpExchange
from budobugs.models.base import utc_now


class EvidencePackError(ValueError):
    pass


class EvidencePackBuilder:
    def __init__(self, findings_root: Path) -> None:
        self.findings_root = findings_root.resolve()

    def build(
        self,
        finding: Finding,
        exchanges: list[HttpExchange],
        controls: list[ControlExperiment],
        *,
        critique: Critique | None = None,
        browser_artifacts: list[Path] | None = None,
    ) -> Path:
        pack = safe_join(self.findings_root, finding.finding_id)
        for name in (
            "requests",
            "responses",
            "screenshots",
            "browser-trace",
            "controls",
            "tool-output",
            "critique",
            "report",
        ):
            safe_join(pack, name).mkdir(parents=True, exist_ok=True)
        screenshot_sources = [Path(item) for item in finding.screenshots]
        screenshot_refs = self._copy_screenshots(pack, screenshot_sources)
        self._copy_browser_artifacts(pack, browser_artifacts or [])
        request_refs: list[str] = []
        response_refs: list[str] = []
        for index, exchange in enumerate(exchanges, start=1):
            request_relative = f"requests/{index:03d}-{exchange.exchange_id}.json"
            response_relative = f"responses/{index:03d}-{exchange.exchange_id}.json"
            atomic_write_json(
                pack / request_relative,
                {
                    "exchange_id": exchange.exchange_id,
                    "method": exchange.method,
                    "url": exchange.url,
                    "headers": exchange.request_headers,
                    "body": exchange.request_body,
                    "account_alias": exchange.account_alias,
                    "captured_at": exchange.captured_at.isoformat(),
                },
            )
            atomic_write_json(
                pack / response_relative,
                {
                    "exchange_id": exchange.exchange_id,
                    "status": exchange.response_status,
                    "headers": exchange.response_headers,
                    "body": exchange.response_body,
                    "response_hash": exchange.response_hash,
                },
            )
            request_refs.append(request_relative)
            response_refs.append(response_relative)
        for control in controls:
            atomic_write_json(
                pack / "controls" / f"{control.control_id}.json",
                json.loads(control.model_dump_json()),
            )
        if critique is not None:
            atomic_write_json(
                pack / "critique" / f"{critique.critique_id}.json",
                json.loads(critique.model_dump_json()),
            )
        finding.requests = request_refs
        finding.responses = response_refs
        finding.screenshots = screenshot_refs
        atomic_write_text(pack / "summary.md", self._summary(finding))
        atomic_write_text(pack / "cleanup.md", f"# Cleanup\n\n{finding.cleanup_status}\n")
        atomic_write_text(pack / "timeline.jsonl", self._timeline(finding, exchanges, controls, critique))
        finding_payload = finding.model_dump(mode="json", exclude_none=False)
        atomic_write_text(
            pack / "finding.yaml",
            yaml.safe_dump(finding_payload, allow_unicode=True, sort_keys=False),
        )
        # Mutable receipts and the manifest itself are excluded to avoid a self-hash cycle.
        finding.evidence_hashes = self._hash_artifacts(pack)
        atomic_write_text(
            pack / "finding.yaml",
            yaml.safe_dump(
                finding.model_dump(mode="json", exclude_none=False),
                allow_unicode=True,
                sort_keys=False,
            ),
        )
        atomic_write_json(pack / "hashes.json", finding.evidence_hashes)
        return pack

    @staticmethod
    def _copy_screenshots(pack: Path, sources: list[Path]) -> list[str]:
        references: list[str] = []
        for index, source_value in enumerate(sources, start=1):
            if not source_value.is_absolute():
                existing = pack / source_value
                if existing.is_file() and not existing.is_symlink():
                    references.append(source_value.as_posix())
                    continue
            source = source_value.resolve()
            if not source.is_file() or source.is_symlink() or source.stat().st_size > 25 * 1024 * 1024:
                raise EvidencePackError(f"invalid screenshot source: {source_value}")
            suffix = source.suffix.lower()
            if suffix not in {".png", ".jpg", ".jpeg", ".webp"}:
                raise EvidencePackError(f"unsupported screenshot format: {source}")
            relative = f"screenshots/{index:03d}-{source.stem[:60]}{suffix}"
            destination = pack / relative
            shutil.copy2(source, destination)
            atomic_write_json(
                destination.with_suffix(destination.suffix + ".metadata.json"),
                {
                    "captured_at": utc_now().isoformat(),
                    "step": source.stem,
                    "source_filename": source.name,
                },
            )
            references.append(relative)
        return references

    @staticmethod
    def _copy_browser_artifacts(pack: Path, sources: list[Path]) -> None:
        for index, source_value in enumerate(sources, start=1):
            source = source_value.resolve()
            if not source.is_file() or source.is_symlink() or source.stat().st_size > 200 * 1024 * 1024:
                raise EvidencePackError(f"invalid browser artifact: {source_value}")
            lowered_parts = {part.lower() for part in source.parts}
            if "profile" in lowered_parts or source.name.lower() == "storage-state.json":
                continue
            # HAR and Playwright traces are retained in the private run directory. They may
            # contain opaque cookies or tokens that a text secret scan cannot reliably detect.
            if source.suffix.lower() not in {".html", ".json", ".jsonl"}:
                continue
            destination = pack / "browser-trace" / f"{index:03d}-{source.name[:100]}"
            shutil.copy2(source, destination)

    @staticmethod
    def _hash_artifacts(pack: Path, *, exclude: set[str] | None = None) -> dict[str, str]:
        excluded = exclude or {"finding.yaml", "gate-receipt.json", "hashes.json"}
        hashes: dict[str, str] = {}
        for path in sorted(pack.rglob("*")):
            if path.is_file() and not path.is_symlink():
                relative = path.relative_to(pack).as_posix()
                if relative not in excluded and not relative.startswith("report/"):
                    hashes[relative] = sha256_file(path)
        return hashes

    @staticmethod
    def _summary(finding: Finding) -> str:
        return (
            f"# {finding.title}\n\n"
            f"- Finding: `{finding.finding_id}`\n"
            f"- Status: `{finding.status}`\n"
            f"- Capability delta: {finding.capability_delta}\n"
            f"- Conservative impact: {finding.impact}\n"
        )

    @staticmethod
    def _timeline(
        finding: Finding,
        exchanges: list[HttpExchange],
        controls: list[ControlExperiment],
        critique: Critique | None,
    ) -> str:
        rows: list[dict[str, object]] = [
            {
                "type": "finding-created",
                "finding_id": finding.finding_id,
                "timestamps": finding.timestamps,
            }
        ]
        rows.extend(
            {
                "type": "http-exchange",
                "exchange_id": item.exchange_id,
                "captured_at": item.captured_at.isoformat(),
            }
            for item in exchanges
        )
        rows.extend({"type": "control", "control_id": item.control_id} for item in controls)
        if critique is not None:
            rows.append(
                {
                    "type": "critique",
                    "critique_id": critique.critique_id,
                    "verdict": critique.verdict,
                }
            )
        return "".join(json.dumps(row, ensure_ascii=False, default=str) + "\n" for row in rows)


def pack_finding(pack: Path, destination: Path) -> Path:
    """Secret-scan and create a traversal-safe portable ZIP."""

    pack = pack.resolve()
    finding_path = pack / "finding.yaml"
    try:
        finding = Finding.model_validate(yaml.safe_load(finding_path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError, ValueError) as exc:
        raise EvidencePackError("finding.yaml is missing or invalid") from exc
    members: list[Path] = []
    violations: list[str] = []
    for path in sorted(pack.rglob("*")):
        if path.is_symlink():
            raise PathBoundaryError(f"symlink not allowed in evidence export: {path}")
        if path.is_file():
            relative = path.relative_to(pack)
            if ".." in relative.parts:
                raise PathBoundaryError(f"unsafe archive member: {relative}")
            if path.suffix.lower() in {".json", ".jsonl", ".md", ".yaml", ".yml", ".html", ".txt"}:
                violations.extend(
                    f"{relative}:{label}" for label in contains_unredacted_secret(path.read_text(encoding="utf-8"))
                )
            members.append(path)
    if violations:
        raise EvidencePackError(f"secret scan failed: {violations[:10]}")
    from budobugs.validation.gates import EvidenceGate

    gate = EvidenceGate().evaluate(finding, pack, require_critic=True)
    if not gate.passed:
        failures = [item.gate for item in gate.gates if not item.passed]
        raise EvidencePackError(f"live evidence gate failed: {failures}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in members:
            archive.write(path, arcname=path.relative_to(pack).as_posix())
    return destination
