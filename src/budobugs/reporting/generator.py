"""Generate Chinese SRC reports only from critic-confirmed findings."""

from __future__ import annotations

import html
import json
from pathlib import Path
from urllib.parse import urlsplit

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
            "remediation": _remediation(finding),
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
            rendered = _render_http_evidence(decoded)
        rows.append({"reference": reference, "content": rendered})
    return rows


def _render_http_evidence(value: object) -> str:
    """Render redacted evidence as a copyable minimal HTTP message when possible."""

    if not isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    headers = value.get("headers")
    header_rows = [f"{name}: {item}" for name, item in sorted(headers.items())] if isinstance(headers, dict) else []
    body = value.get("body")
    if body is None:
        body_text = ""
    elif isinstance(body, str):
        body_text = body
    else:
        body_text = json.dumps(body, ensure_ascii=False, indent=2, sort_keys=True)
    if isinstance(value.get("method"), str) and isinstance(value.get("url"), str):
        parsed = urlsplit(value["url"])
        target = parsed.path or "/"
        if parsed.query:
            target = f"{target}?{parsed.query}"
        lines = [f"{value['method'].upper()} {target} HTTP/1.1", *header_rows]
    elif isinstance(value.get("status"), int):
        lines = [f"HTTP/1.1 {value['status']}", *header_rows]
    else:
        return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    rendered = "\n".join(lines)
    return f"{rendered}\n\n{body_text}" if body_text else rendered


def _remediation(finding: Finding) -> list[str]:
    """Return root-cause-specific remediation and regression checks."""

    category = finding.vulnerability_class.casefold()
    enforcement = finding.enforcement_point
    if "cors" in category:
        return [
            "对允许携带凭据的跨域请求使用精确 Origin allowlist；禁止反射任意 Origin，也不要将通配符与凭据组合。",
            "在响应中正确设置 Vary: Origin，并让预检和实际请求经过同一授权策略。",
            "增加受信 Origin、非受信 Origin、null Origin 和凭据请求的回归测试。",
        ]
    if "csrf" in category:
        return [
            "为所有状态变更请求校验不可预测且绑定会话的 CSRF token，并结合 SameSite Cookie 与 Origin/Referer 校验。",
            "不要把自定义前端参数或隐藏按钮当作服务端 CSRF 防护。",
            "增加同站正常提交、跨站无 token、错误 token 和重复提交的回归测试。",
        ]
    if "websocket" in category:
        return [
            f"在 {enforcement} 同时校验握手身份、当前会话状态以及每条消息引用对象的权限。",
            "不要把握手成功视为整个连接生命周期的永久授权；角色、租户或撤销状态变化后重新评估能力。",
            "增加跨账号对象订阅、消息重放、会话撤销和安全频道拒绝的回归测试。",
        ]
    if any(marker in category for marker in ("xss", "client-side", "frontend", "client trust")):
        return [
            "按输出上下文使用安全 DOM API 或严格编码；需要富文本时采用经过审计的 allowlist sanitizer，"
            "避免把不可信值写入 innerHTML。",
            "CSP 只能作为纵深防御，不能替代 source-to-sink 修复。",
            "增加 inert marker、危险上下文和 textContent/安全渲染负对照的前端回归测试。",
        ]
    if any(marker in category for marker in ("session", "jwt", "oauth", "authentication")):
        return [
            f"在 {enforcement} 对每次受保护操作校验当前会话、token 撤销、过期和最新角色状态。",
            "退出、撤权和密码/角色变更后立即失效旧能力；轮换 refresh token，并严格绑定 OAuth state、"
            "redirect URI 与 PKCE。",
            "增加旧/新会话、撤销后重复、JWT 过期/受众以及 OAuth 回调的回归测试。",
        ]
    if any(marker in category for marker in ("business", "workflow", "logic", "state")):
        return [
            f"在 {enforcement} 实现服务端状态机，原子校验前置状态、允许的转换、幂等键和一次性约束。",
            "不要依赖页面顺序、客户端按钮状态或单次请求假设维持流程完整性。",
            "增加跳步、乱序、重复、并发、撤销和过期后的回归测试。",
        ]
    if any(marker in category for marker in ("authorization", "tenant", "file", "share", "access control")):
        return [
            f"在 {enforcement} 基于当前认证主体、角色、租户、对象所有权和对象状态执行服务端授权。",
            "让读取、修改、下载、预览、分享、邀请和撤销入口复用同一策略，而不是依赖前端隐藏或不可猜测标识符。",
            "增加跨账号、跨角色、跨租户、撤销/过期以及同根因其他入口的回归测试。",
        ]
    return [
        f"在 {enforcement} 直接恢复报告中声明的安全不变量：{finding.security_invariant}",
        "围绕正常对照、负对照、重复复现和最强正常解释增加服务端回归测试。",
    ]
