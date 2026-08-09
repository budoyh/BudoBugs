"""`budo` command surface."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console

from budobugs import __version__
from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json
from budobugs.core.paths import WorkspacePaths
from budobugs.core.policy import target_allowed, websocket_target_allowed
from budobugs.evidence.pack import pack_finding
from budobugs.knowledge.vendor import VendorKnowledgeBase, vendor_key
from budobugs.labs import LabManager
from budobugs.models import (
    AuthorizationStatus,
    Engagement,
    EngagementMode,
    OutcomeStatus,
    PhaseName,
    PlatformOutcome,
    SafeWebSocketExperimentTemplate,
    SelfOwnedObjectRecipe,
    Target,
    parse_program_experiment_template,
    program_experiment_actions,
)
from budobugs.orchestration import HuntEngine, RepositoryService
from budobugs.reporting.generator import ReportGenerator
from budobugs.storage.secrets import SecretStore
from budobugs.tools.doctor import doctor
from budobugs.tools.installer import ToolInstaller
from budobugs.tools.registry import ToolRegistry
from budobugs.traffic.importer import import_har
from budobugs.validation.gates import EvidenceGate

app = typer.Typer(help="BudoBugs：已授权、证据驱动、可恢复的漏洞研究操作系统。", no_args_is_help=True)
tools_app = typer.Typer(help="固定版本工具的安装、健康检查和清理。")
lab_app = typer.Typer(help="仅限 localhost / Docker 内网的 TEST FIXTURE 靶场。")
engagement_app = typer.Typer(help="授权任务声明与审批。")
traffic_app = typer.Typer(help="受控流量导入和确定性建模。")
findings_app = typer.Typer(help="候选与证据门禁。")
report_app = typer.Typer(help="只从 critic-confirmed finding 生成报告。")
proxy_app = typer.Typer(help="Caido、Burp、ZAP、HAR 和 direct backend 诊断。")
mcp_app = typer.Typer(help="BudoBugs 本地 MCP 诊断。")
outcome_app = typer.Typer(help="记录平台反馈并更新厂商长期记忆与优先级。")
app.add_typer(tools_app, name="tools")
app.add_typer(lab_app, name="lab")
app.add_typer(engagement_app, name="engagement")
app.add_typer(traffic_app, name="traffic")
app.add_typer(findings_app, name="findings")
app.add_typer(report_app, name="report")
app.add_typer(proxy_app, name="proxy")
app.add_typer(mcp_app, name="mcp")
app.add_typer(outcome_app, name="outcome")
console = Console()


def _paths() -> WorkspacePaths:
    return WorkspacePaths.discover()


def _service() -> RepositoryService:
    return RepositoryService(_paths())


def _emit(value: Any, json_output: bool) -> None:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    if json_output:
        sys.stdout.write(json.dumps(value, ensure_ascii=True, indent=2, default=str) + "\n")
    elif isinstance(value, (dict, list)):
        console.print_json(data=value)
    else:
        console.print(value)


@app.command()
def version(
    json_output: Annotated[bool, typer.Option("--json", help="输出 JSON。")] = False,
) -> None:
    """显示 BudoBugs 版本。"""

    _emit({"name": "budobugs", "version": __version__}, json_output)


@app.command()
def bootstrap(json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    """幂等安装 core profile，并立即执行真实健康检查。"""

    installer = ToolInstaller(_paths().root)
    receipts = installer.install("core")
    _emit({"receipts": [asdict(item) for item in receipts]}, json_output)


@app.command("doctor")
def doctor_command(
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """检查 OS、运行时、Docker、WSL、资源和所有注册工具。"""

    _emit(asyncio.run(doctor(_paths().root)), json_output)


@tools_app.command("list")
def tools_list(
    profile: Annotated[str | None, typer.Option(help="core、extended 或 lab-ai。")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    registry = ToolRegistry.load(_paths().root / "tools" / "registry")
    _emit([item.model_dump(mode="json") for item in registry.list(profile)], json_output)


@tools_app.command("install")
def tools_install(
    profile: Annotated[str, typer.Option(help="core、extended 或 lab-ai。")],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    receipts = ToolInstaller(_paths().root).install(profile)
    _emit({"profile": profile, "receipts": [asdict(item) for item in receipts]}, json_output)


@tools_app.command("update")
def tools_update(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="只比较锁文件，不安装。")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    if not dry_run:
        raise typer.BadParameter("版本更新必须先使用 --dry-run 审核")
    lock = _paths().root / "tools" / "lock" / "tool-lock.yaml"
    _emit(
        {"status": "NO_CHANGE_APPLIED", "lock_file": str(lock), "review_required": True},
        json_output,
    )


@tools_app.command("health")
def tools_health(
    profile: Annotated[str | None, typer.Option()] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    _emit(asyncio.run(doctor(_paths().root, profile=profile)), json_output)


@tools_app.command("clean")
def tools_clean(
    yes: Annotated[bool, typer.Option("--yes", help="确认仅删除 BudoBugs 用户工具目录。")] = False,
) -> None:
    if not yes:
        raise typer.BadParameter("清理是破坏性操作；请显式传入 --yes")
    removed = ToolInstaller(_paths().root).clean()
    console.print(f"已删除 BudoBugs 专用工具目录：{removed}")


def _lab_manager() -> LabManager:
    paths = _paths()
    return LabManager(paths.root, paths.runtime_home)


@lab_app.command("up")
def lab_up(
    native_only: Annotated[bool, typer.Option("--native-only", help="只启动仓库自带 TEST FIXTURE。")] = False,
    extended: Annotated[bool, typer.Option("--extended", help="同时启动 ZAP daemon/API。")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    if native_only and extended:
        raise typer.BadParameter("--native-only and --extended cannot be combined")
    _emit(asdict(_lab_manager().up(native_only=native_only, extended=extended)), json_output)


@lab_app.command("down")
def lab_down(json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    _emit(asdict(_lab_manager().down()), json_output)


@lab_app.command("status")
def lab_status(json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    _emit(asdict(_lab_manager().status()), json_output)


@lab_app.command("zap-scan")
def lab_zap_scan(json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    """在 Docker 内网中对自建 TEST FIXTURE 执行固定 ZAP Automation 作业。"""

    _emit(_lab_manager().zap_scan(), json_output)


@lab_app.command("clean")
def lab_clean(
    yes: Annotated[bool, typer.Option("--yes", help="确认停止并删除本项目 Docker lab volumes。")] = False,
) -> None:
    if not yes:
        raise typer.BadParameter("清理 lab volumes 需要显式 --yes")
    _emit(asdict(_lab_manager().clean()), False)


@engagement_app.command("new")
def engagement_new(
    engagement_id: Annotated[str, typer.Option("--id")],
    mode: Annotated[EngagementMode, typer.Option()],
    target: Annotated[list[str], typer.Option("--target")],
    vendor: Annotated[str, typer.Option()],
    attestation: Annotated[str, typer.Option(help="用户的明确授权声明，至少 20 字符。")],
    platform: Annotated[str, typer.Option()] = "local-or-src",
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    engagement = Engagement(
        engagement_id=engagement_id,
        platform=platform,
        vendor=vendor,
        user_authorization_attestation=attestation,
        root_targets=[
            Target(
                uri=item,
                label=f"target-{index}",
                kind="source" if mode is EngagementMode.SOURCE else "web",
            )
            for index, item in enumerate(target, start=1)
        ],
        selected_mode=mode,
    )
    path = _service().save_engagement(engagement)
    _emit({"engagement": engagement.model_dump(mode="json"), "path": str(path)}, json_output)


@engagement_app.command("validate")
def engagement_validate(
    engagement_id: str,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    engagement = _service().load_engagement(engagement_id)
    decisions = [target_allowed(engagement, item.uri) for item in engagement.root_targets]
    _emit(
        {
            "valid": all(item.allowed for item in decisions),
            "authorization_status": engagement.authorization_status.value,
            "decisions": [asdict(item) for item in decisions],
        },
        json_output,
    )


@engagement_app.command("show")
def engagement_show(engagement_id: str, json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    _emit(_service().load_engagement(engagement_id), json_output)


@engagement_app.command("authorize")
def engagement_authorize(engagement_id: str, json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    engagement = _service().authorize_engagement(engagement_id)
    _emit(engagement, json_output)


@engagement_app.command("account-set")
def engagement_account_set(
    engagement_id: str,
    alias: Annotated[str, typer.Option(help="自有测试账号别名，如 alice/bob。")],
    headers_env: Annotated[
        str,
        typer.Option(
            help=(
                '包含 {"headers": {...}, "login_url": "...", "self_owned_object_recipe": {...}} '
                "JSON 的环境变量名。recipe 是授权前登记的可逆自有对象生命周期。"
            ),
        ),
    ],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """将账号请求头从环境变量写入系统 keyring，并仅在 engagement 中保存引用。"""

    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{1,31}", alias):
        raise typer.BadParameter("alias must contain 2-32 safe characters")
    raw = os.environ.get(headers_env)
    if not raw:
        raise typer.BadParameter(f"environment variable {headers_env} is empty")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter("account header environment value must be JSON") from exc
    headers = payload.get("headers", {}) if isinstance(payload, dict) else None
    login_url = payload.get("login_url") if isinstance(payload, dict) else None
    if not isinstance(headers, dict) or not all(
        isinstance(name, str) and isinstance(value, str) for name, value in headers.items()
    ):
        raise typer.BadParameter("account JSON headers must be a string mapping")
    if login_url is not None and not isinstance(login_url, str):
        raise typer.BadParameter("account JSON login_url must be a string")
    if not headers and not login_url:
        raise typer.BadParameter("account JSON must contain headers or login_url")
    service = _service()
    engagement = service.load_engagement(engagement_id)
    if engagement.authorization_status is not AuthorizationStatus.DRAFT:
        raise typer.BadParameter("testing accounts must be configured before the one-time authorization")
    recipe_payload = payload.get("self_owned_object_recipe") if isinstance(payload, dict) else None
    if recipe_payload is not None:
        try:
            recipe = SelfOwnedObjectRecipe.model_validate(recipe_payload)
        except ValueError as exc:
            raise typer.BadParameter(f"self_owned_object_recipe is invalid: {exc}") from exc
        if recipe.account_alias != alias:
            raise typer.BadParameter("self_owned_object_recipe account_alias must exactly match --alias")
        for action in (recipe.create, recipe.verification, recipe.cleanup, recipe.cleanup_verification):
            decision = target_allowed(engagement, action.target_url)
            if not decision.allowed:
                raise typer.BadParameter(f"self_owned_object_recipe action {action.action_id} is out of scope")
    store = SecretStore(service.paths.runtime_home / "secrets" / "fallback.json")
    reference = store.set(f"engagement:{engagement_id}", f"account:{alias}", raw)
    references = dict(engagement.testing_accounts_secret_refs)
    references[alias] = reference
    updated = engagement.model_copy(update={"testing_accounts_secret_refs": references})
    service.save_engagement(updated, actor="account-secret-helper")
    _emit(
        {
            "status": "PASS",
            "alias": alias,
            "secret_ref": reference,
            "self_owned_object_recipe": "configured" if recipe_payload is not None else "not-configured",
        },
        json_output,
    )


@engagement_app.command("experiment-set")
def engagement_experiment_set(
    engagement_id: str,
    spec_env: Annotated[
        str,
        typer.Option(
            help=(
                "包含 SafeExperimentTemplate 或 SafeWorkflowExperimentTemplate JSON 的环境变量名；"
                "模板只引用自有账号、精确 URL、正常/重复/负对照和清理动作。"
            )
        ),
    ],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """一次性登记正式 engagement 可执行的自有数据写操作实验。"""

    raw = os.environ.get(spec_env)
    if not raw:
        raise typer.BadParameter(f"environment variable {spec_env} is empty")
    try:
        template = parse_program_experiment_template(raw)
    except ValueError as exc:
        raise typer.BadParameter(f"safe experiment template is invalid: {exc}") from exc
    service = _service()
    engagement = service.load_engagement(engagement_id)
    if engagement.selected_mode is not EngagementMode.PROGRAM:
        raise typer.BadParameter("safe HTTP experiments are available only in program mode")
    if engagement.authorization_status is not AuthorizationStatus.DRAFT:
        raise typer.BadParameter("safe experiments must be configured before the one-time authorization")
    actions = program_experiment_actions(template)
    unknown_accounts = {
        item.account_alias
        for item in actions
        if item.account_alias != "anonymous" and item.account_alias not in engagement.testing_accounts_secret_refs
    }
    if unknown_accounts:
        raise typer.BadParameter(f"template references undeclared self-owned accounts: {sorted(unknown_accounts)}")
    for action in actions:
        decision = target_allowed(engagement, action.target_url)
        if not decision.allowed:
            raise typer.BadParameter(f"template action {action.action_id} is out of scope: {decision.reason}")
    store = SecretStore(service.paths.runtime_home / "secrets" / "fallback.json")
    reference = store.set(
        f"engagement:{engagement_id}",
        f"experiment:{template.template_id}",
        template.model_dump_json(),
    )
    references = dict(engagement.safe_experiment_secret_refs)
    references[template.template_id] = reference
    updated = engagement.model_copy(update={"safe_experiment_secret_refs": references})
    service.save_engagement(updated, actor="safe-experiment-helper")
    _emit(
        {
            "status": "PASS",
            "template_id": template.template_id,
            "specialist_role": template.specialist_role,
            "secret_ref": reference,
        },
        json_output,
    )


@engagement_app.command("websocket-experiment-set")
def engagement_websocket_experiment_set(
    engagement_id: str,
    spec_env: Annotated[
        str,
        typer.Option(
            help=(
                "包含 SafeWebSocketExperimentTemplate JSON 的环境变量名；仅允许已声明账号、"
                "精确同源 WS/WSS URL、正常/重复/拒绝对照。"
            )
        ),
    ],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """一次性登记正式 engagement 可执行的只读 WebSocket 对照实验。"""

    raw = os.environ.get(spec_env)
    if not raw:
        raise typer.BadParameter(f"environment variable {spec_env} is empty")
    try:
        template = SafeWebSocketExperimentTemplate.model_validate_json(raw)
    except ValueError as exc:
        raise typer.BadParameter(f"safe WebSocket experiment template is invalid: {exc}") from exc
    service = _service()
    engagement = service.load_engagement(engagement_id)
    if engagement.selected_mode is not EngagementMode.PROGRAM:
        raise typer.BadParameter("safe WebSocket experiments are available only in program mode")
    if engagement.authorization_status is not AuthorizationStatus.DRAFT:
        raise typer.BadParameter("safe WebSocket experiments must be configured before the one-time authorization")
    if template.template_id in engagement.safe_experiment_secret_refs:
        raise typer.BadParameter("safe WebSocket experiment ID conflicts with an HTTP safe experiment")
    actions = (template.normal_control, template.experiment, template.negative_control)
    unknown_accounts = {
        item.account_alias for item in actions if item.account_alias not in engagement.testing_accounts_secret_refs
    }
    if unknown_accounts:
        raise typer.BadParameter(f"template references undeclared self-owned accounts: {sorted(unknown_accounts)}")
    for action in actions:
        decision = websocket_target_allowed(engagement, action.target_url)
        if not decision.allowed:
            raise typer.BadParameter(f"template action {action.action_id} is out of scope: {decision.reason}")
    store = SecretStore(service.paths.runtime_home / "secrets" / "fallback.json")
    reference = store.set(
        f"engagement:{engagement_id}",
        f"websocket-experiment:{template.template_id}",
        template.model_dump_json(),
    )
    references = dict(engagement.websocket_experiment_secret_refs)
    references[template.template_id] = reference
    updated = engagement.model_copy(update={"websocket_experiment_secret_refs": references})
    service.save_engagement(updated, actor="safe-websocket-experiment-helper")
    _emit(
        {
            "status": "PASS",
            "template_id": template.template_id,
            "specialist_role": template.specialist_role,
            "secret_ref": reference,
            "raw_frames_persisted": False,
        },
        json_output,
    )


@app.command("hunt")
def hunt(
    engagement_id: str,
    resume: Annotated[bool, typer.Option("--resume")] = False,
    phase: Annotated[str | None, typer.Option(help="保留用于编排器阶段选择；lab fixture 会完成闭环。")] = None,
    agent_mode: Annotated[
        str | None,
        typer.Option("--agent-mode", help="Agent Loop 提案模式：disabled 或 codex。"),
    ] = None,
    proxy: Annotated[
        str,
        typer.Option("--proxy", help="auto、direct、har、caido、burp 或 zap。"),
    ] = "auto",
    har: Annotated[Path | None, typer.Option("--har", help="选择 HAR backend 时的授权流量文件。")] = None,
    interactive_login: Annotated[
        bool,
        typer.Option("--interactive-login", help="遇到登录/MFA/验证码时暂停一次并持久化恢复。"),
    ] = False,
    headed: Annotated[bool, typer.Option("--headed", help="显示 Playwright 浏览器。")] = False,
    agent_stop_after_turns: Annotated[
        int | None,
        typer.Option("--agent-stop-after-turns", hidden=True),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="只输出阶段、请求与模型预算上界，不执行 hunt。"),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    if phase not in {None, "recon", "all"}:
        raise typer.BadParameter("phase must be recon or all")
    if agent_mode is not None and agent_mode.lower() not in {"disabled", "codex"}:
        raise typer.BadParameter("agent-mode must be disabled or codex")
    if proxy.lower() not in {"auto", "direct", "har", "caido", "burp", "zap"}:
        raise typer.BadParameter("proxy must be auto, direct, har, caido, burp, or zap")
    if proxy.lower() == "har" and har is None:
        raise typer.BadParameter("--proxy har requires --har")
    if interactive_login and not headed:
        raise typer.BadParameter("--interactive-login requires --headed")
    if dry_run and resume:
        raise typer.BadParameter("--dry-run cannot be combined with --resume")
    service = _service()
    engine = HuntEngine(
        service,
        agent_mode=agent_mode,
        proxy_backend=proxy,
        har_path=har,
        interactive_login=interactive_login,
        headless=not headed,
        agent_stop_after_turns=agent_stop_after_turns,
    )
    engagement = service.load_engagement(engagement_id)
    if dry_run:
        _emit(engine.estimate(engagement), json_output)
        return
    stop_after = PhaseName.PASSIVE_RECON if phase == "recon" else None
    result = asyncio.run(
        engine.run(
            engagement,
            resume=resume,
            stop_after=stop_after,
        )
    )
    _emit(
        {
            "run_id": result.run.run_id,
            "status": result.run.status,
            "confirmed_finding_id": result.confirmed_finding_id,
            "killed_finding_id": result.killed_finding_id,
            "report_markdown": result.report_markdown,
            "report_html": result.report_html,
            "confirmed_finding_ids": list(result.confirmed_finding_ids),
            "killed_finding_ids": list(result.killed_finding_ids),
            "report_markdowns": list(result.report_markdowns),
            "report_htmls": list(result.report_htmls),
            "agent_loop_receipt": result.agent_loop_receipt,
        },
        json_output,
    )


@outcome_app.command("record")
def outcome_record(
    finding_id: str,
    status: Annotated[OutcomeStatus, typer.Option("--status")],
    reward: Annotated[float, typer.Option("--reward", min=0)] = 0,
    reason: Annotated[str, typer.Option("--reason")] = "platform feedback recorded",
    root_cause_key: Annotated[str | None, typer.Option("--root-cause-key")] = None,
    exploitation_method: Annotated[str | None, typer.Option("--exploitation-method")] = None,
    previously_fixed: Annotated[bool, typer.Option("--previously-fixed")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Persist platform disposition and feed it into future bounty ranking and false-positive rules."""

    service = _service()
    finding = service.load_finding(finding_id)
    engagement = service.load_engagement(finding.engagement_id)
    outcome = PlatformOutcome(
        outcome_id=new_id("platform-outcome"),
        finding_id=finding_id,
        vendor_key=vendor_key(engagement.platform, engagement.vendor),
        status=status,
        reward=reward,
        reason=reason,
        vulnerability_class=finding.vulnerability_class,
        root_cause_key=root_cause_key,
        feature_key=finding.affected_feature,
        endpoint_family=finding.endpoint_family,
        exploitation_method=exploitation_method,
        previously_fixed=previously_fixed,
    )
    knowledge = VendorKnowledgeBase(service.store).record_outcome(engagement, outcome)
    service.audit(
        "platform-outcome.recorded",
        "human-feedback-command",
        engagement_id=engagement.engagement_id,
        details={
            "finding_id": finding_id,
            "status": status.value,
            "reward": reward,
            "outcome_id": outcome.outcome_id,
        },
    )
    _emit(
        {
            "outcome": outcome.model_dump(mode="json"),
            "updated_priors": {
                "acceptance": knowledge.acceptance_prior,
                "duplicate_risk": knowledge.duplicate_risk_prior,
                "impact_multiplier": knowledge.impact_multiplier,
            },
        },
        json_output,
    )


@app.command("status")
def status(engagement_id: str, json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    run = _service().latest_run(engagement_id)
    _emit(
        {"engagement_id": engagement_id, "run": run.model_dump(mode="json") if run else None},
        json_output,
    )


@app.command("timeline")
def timeline(engagement_id: str, json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    _emit(_service().timeline(engagement_id), json_output)


@traffic_app.command("import")
def traffic_import(
    file: Path,
    engagement_id: Annotated[str, typer.Option("--engagement")],
    account: Annotated[str | None, typer.Option(help="将该 HAR 关联到自有测试账号别名。")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    service = _service()
    engagement = service.load_engagement(engagement_id)
    exchanges = import_har(file, engagement)
    if account is not None:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{1,31}", account):
            raise typer.BadParameter("account alias must contain 2-32 safe characters")
        exchanges = [item.model_copy(update={"account_alias": account}) for item in exchanges]
    suffix = f"-{account}" if account else ""
    destination = service.paths.runtime_home / "imports" / engagement_id / f"{file.stem}{suffix}.json"
    atomic_write_json(destination, [item.model_dump(mode="json") for item in exchanges])
    _emit({"count": len(exchanges), "artifact": str(destination)}, json_output)


@traffic_app.command("summarize")
def traffic_summarize(engagement_id: str, json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    run = _service().latest_run(engagement_id)
    if run is None:
        raise typer.BadParameter("engagement has no run")
    artifact = _service().paths.runs / run.run_id / "artifacts" / "traffic_model.json"
    if not artifact.is_file():
        raise typer.BadParameter("traffic model artifact is not available")
    _emit(json.loads(artifact.read_text(encoding="utf-8")), json_output)


@findings_app.command("list")
def findings_list(engagement_id: str, json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    _emit(
        [item.model_dump(mode="json") for item in _service().list_findings(engagement_id)],
        json_output,
    )


@findings_app.command("show")
def findings_show(finding_id: str, json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    _emit(_service().load_finding(finding_id), json_output)


@findings_app.command("validate")
def findings_validate(finding_id: str, json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    service = _service()
    finding = service.load_finding(finding_id)
    pack = service.paths.findings / finding_id
    receipt = EvidenceGate().evaluate(finding, pack, require_critic=True)
    _emit(receipt, json_output)


@report_app.command("generate")
def report_generate(
    finding_id: str,
    platform: Annotated[str, typer.Option()] = "butian",
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    service = _service()
    finding = service.load_finding(finding_id)
    templates = Path(__file__).parents[1] / "reporting" / "templates"
    engagement = service.load_engagement(finding.engagement_id)
    report = ReportGenerator(templates).generate(
        finding,
        service.paths.findings / finding_id,
        vendor=engagement.vendor,
        engagement_platform=engagement.platform,
        platform=platform,
    )
    _emit(report, json_output)


@report_app.command("pack")
def report_pack(finding_id: str, json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    service = _service()
    pack = service.paths.findings / finding_id
    destination = service.paths.runtime_home / "exports" / f"{finding_id}.zip"
    result = pack_finding(pack, destination)
    _emit({"archive": str(result), "bytes": result.stat().st_size}, json_output)


@proxy_app.command("doctor")
def proxy_doctor(json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    from budobugs.proxy.burp import BurpMcpAdapter
    from budobugs.proxy.caido import CaidoClient
    from budobugs.proxy.direct import DirectProxyBackend
    from budobugs.proxy.zap import ZapClient

    async def checks() -> dict[str, object]:
        caido_config = _paths().runtime_home / "proxy" / "caido.json"
        caido_health: tuple[bool, str] = (False, "NEEDS_CREDENTIAL: run `budo proxy caido-configure`")
        if caido_config.is_file():
            try:
                config = json.loads(caido_config.read_text(encoding="utf-8"))
                reference = str(config["pat_reference"])
                pat = SecretStore(_paths().runtime_home / "secrets" / "fallback.json").get(reference)
                if pat:
                    caido_health = await CaidoClient(str(config["url"]), pat).health()
            except (KeyError, ValueError, OSError, RuntimeError, json.JSONDecodeError) as exc:
                caido_health = (False, f"Caido configuration error: {exc}")
        direct, burp, zap = await asyncio.gather(
            DirectProxyBackend().health(),
            BurpMcpAdapter(os.environ.get("BUDOBUGS_BURP_MCP_URL", "http://127.0.0.1:9876/mcp")).health(),
            ZapClient("http://127.0.0.1:8090").health(),
        )
        return {
            "direct": {"ready": direct[0], "detail": direct[1]},
            "burp-mcp": {"ready": burp[0], "detail": burp[1]},
            "zap": {"ready": zap[0], "detail": zap[1]},
            "caido": {"ready": caido_health[0], "detail": caido_health[1]},
            "har": {"ready": True, "detail": "available when an authorized HAR is supplied"},
        }

    _emit(asyncio.run(checks()), json_output)


@proxy_app.command("caido-configure")
def proxy_caido_configure(
    url: Annotated[str, typer.Option(help="Caido instance URL；默认仅允许 loopback。")],
    pat_env: Annotated[str, typer.Option(help="包含 PAT 的环境变量名，值不会写入日志。")] = "CAIDO_PAT",
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """从环境变量读取 PAT，写入系统 keyring，并保存非敏感连接配置。"""

    from budobugs.proxy.base import require_local_control_plane

    instance_url = require_local_control_plane(url)
    pat = os.environ.get(pat_env)
    if not pat:
        raise typer.BadParameter(f"environment variable {pat_env} is empty")
    paths = _paths()
    store = SecretStore(paths.runtime_home / "secrets" / "fallback.json")
    reference = store.set("caido", "pat", pat)
    config_path = paths.runtime_home / "proxy" / "caido.json"
    atomic_write_json(config_path, {"url": instance_url, "pat_reference": reference})
    _emit({"status": "PASS", "url": instance_url, "pat_reference": reference}, json_output)


@mcp_app.command("doctor")
def mcp_doctor(json_output: Annotated[bool, typer.Option("--json")] = False) -> None:
    from budobugs.mcp.doctor import probe_stdio

    paths = _paths()
    _emit(asyncio.run(probe_stdio(paths.root, paths.runtime_home)), json_output)


@app.command("tui")
def tui() -> None:
    """启动只读运行状态 TUI。"""

    from budobugs.tui import BudoBugsTui

    BudoBugsTui().run()


@app.command("uninstall")
def uninstall(
    keep_data: Annotated[bool, typer.Option("--keep-data", help="保留 engagement、run 和 finding。")] = False,
    yes: Annotated[bool, typer.Option("--yes")] = False,
) -> None:
    if not keep_data:
        raise typer.BadParameter("安全卸载只支持 --keep-data；研究数据必须由用户另行明确处理")
    if not yes:
        raise typer.BadParameter("请使用 --yes 确认删除 BudoBugs 专用工具目录")
    removed = ToolInstaller(_paths().root).clean()
    console.print(f"已移除专用工具目录 {removed}；研究数据保持不变。")


if __name__ == "__main__":
    app()
