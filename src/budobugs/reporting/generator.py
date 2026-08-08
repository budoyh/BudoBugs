"""Generate Chinese SRC reports only from critic-confirmed findings."""

from __future__ import annotations

import html
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json, atomic_write_text, sha256_file
from budobugs.core.redaction import contains_unredacted_secret
from budobugs.models import Finding, Report
from budobugs.validation.gates import EvidenceGate


class ReportGenerationError(ValueError):
    pass


class ReportGenerator:
    def __init__(self, template_root: Path) -> None:
        self.environment = Environment(
            loader=FileSystemLoader(template_root),
            undefined=StrictUndefined,
            autoescape=lambda name: bool(name and name.endswith((".html", ".html.j2", ".xml", ".xml.j2"))),
            trim_blocks=False,
            lstrip_blocks=True,
        )

    def generate(
        self,
        finding: Finding,
        pack: Path,
        *,
        vendor: str,
        engagement_platform: str,
        platform: str = "butian",
    ) -> Report:
        if not finding.is_submission_ready:
            raise ReportGenerationError("finding has not passed evidence gate and independent critic")
        gate_receipt = EvidenceGate().evaluate(finding, pack, require_critic=True)
        if not gate_receipt.passed:
            gate_failures = [item.gate for item in gate_receipt.gates if not item.passed]
            raise ReportGenerationError(f"live evidence gate failed: {gate_failures}")
        report_dir = pack / "report"
        report_dir.mkdir(parents=True, exist_ok=True)
        context = {
            "finding": finding.model_dump(mode="json"),
            "platform": platform,
            "vendor": vendor,
            "engagement_platform": engagement_platform,
            "request_evidence": _evidence_rows(pack, finding.requests),
            "response_evidence": _evidence_rows(pack, finding.responses),
            "screenshots": [item for item in finding.screenshots if (pack / item).is_file()],
            "gate_receipt": gate_receipt.model_dump(mode="json"),
        }
        markdown = self.environment.get_template("butian.md.j2").render(**context)
        html_body = self.environment.get_template("butian.html.j2").render(**context)
        markdown_path = report_dir / "report.md"
        html_path = report_dir / "report.html"
        finding_path = report_dir / "finding.json"
        checklist_path = report_dir / "human-review-checklist.md"
        atomic_write_text(markdown_path, markdown + "\n")
        atomic_write_text(html_path, html_body + "\n")
        atomic_write_json(finding_path, finding.model_dump(mode="json", exclude_none=False))
        atomic_write_text(checklist_path, _review_checklist(finding))
        scan_targets = (markdown_path, html_path, finding_path, checklist_path)
        violations = {path.name: contains_unredacted_secret(path.read_text(encoding="utf-8")) for path in scan_targets}
        scan_failures = {name: labels for name, labels in violations.items() if labels}
        if scan_failures:
            raise ReportGenerationError(f"report secret scan failed: {scan_failures}")
        manifest_path = report_dir / "evidence-manifest.json"
        manifest = {
            "finding_id": finding.finding_id,
            "artifacts": {
                path.name: {"sha256": sha256_file(path), "bytes": path.stat().st_size} for path in scan_targets
            },
            "source_evidence_hashes": finding.evidence_hashes,
        }
        atomic_write_json(manifest_path, manifest)
        return Report(
            report_id=new_id("report"),
            finding_id=finding.finding_id,
            platform=platform,
            markdown_path=str(markdown_path),
            html_path=str(html_path),
            manifest_path=str(manifest_path),
            human_review_checklist_path=str(checklist_path),
            redaction_scan_status="PASS",
            submission_ready=True,
        )


def _review_checklist(finding: Finding) -> str:
    title = html.escape(finding.title)
    return f"""# 人工复核清单：{title}

- [ ] 授权目标、厂商与测试时间准确
- [ ] 复现步骤可由人工按顺序执行
- [ ] 请求和响应中的账号、Cookie、Token 与个人数据已脱敏
- [ ] 正常对照和负对照与报告叙述一致
- [ ] 能力增量和影响未超出证据
- [ ] 数据暴露仅保留最小证明，清理状态已确认
- [ ] CVSS 向量与平台规则一致
- [ ] 重复风险说明准确
- [ ] 最终提交由人工完成
"""


def _evidence_rows(pack: Path, references: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for reference in references:
        path = pack / reference
        if not path.is_file() or path.is_symlink():
            raise ReportGenerationError(f"evidence artifact is missing: {reference}")
        text = path.read_text(encoding="utf-8")
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            rendered = text
        else:
            rendered = json.dumps(decoded, ensure_ascii=False, indent=2, sort_keys=True)
        rows.append({"reference": reference, "content": rendered})
    return rows
