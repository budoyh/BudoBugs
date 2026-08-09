"""Artifact-producing validators for safe differential and stateful experiments."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit

from budobugs.browser.session import BrowserSessionManager
from budobugs.core.identifiers import new_id
from budobugs.models import (
    CandidateDecision,
    CandidateStatus,
    ControlExperiment,
    Engagement,
    EngagementMode,
    Finding,
    HttpExchange,
    Severity,
    ValidationOutcome,
)
from budobugs.proxy.direct import DirectProxyBackend


@dataclass(slots=True)
class ValidatorResult:
    outcome: ValidationOutcome
    finding: Finding
    controls: list[ControlExperiment]
    exchanges: list[HttpExchange]
    artifact_refs: list[str]


class ValidatorRegistry:
    """Execute validators with repeat, normal/negative control, refutation, and cleanup."""

    FIXTURE_VALIDATORS = {
        "fixture-horizontal-rest",
        "fixture-horizontal-graphql",
        "fixture-vertical-role",
        "fixture-cross-tenant",
        "fixture-file-share",
        "fixture-business-workflow",
        "fixture-session-revocation",
        "fixture-client-xss",
        "fixture-false-public",
        "fixture-false-secure-object",
        "fixture-false-safe-client",
        "fixture-false-control-suite",
    }

    def __init__(self, artifact_root: Path) -> None:
        self.artifact_root = artifact_root.resolve()
        self.artifact_root.mkdir(parents=True, exist_ok=True)

    async def run(self, validator_id: str, engagement: Engagement) -> list[ValidatorResult]:
        if validator_id not in self.FIXTURE_VALIDATORS:
            raise ValueError(f"unknown validator: {validator_id}")
        self._require_fixture(engagement)
        backend = DirectProxyBackend(timeout=10)
        if validator_id == "fixture-false-control-suite":
            results: list[ValidatorResult] = []
            for item in (
                "fixture-false-public",
                "fixture-false-secure-object",
                "fixture-false-safe-client",
            ):
                results.extend(await self.run(item, engagement))
            return results
        dispatch = {
            "fixture-horizontal-rest": self._horizontal_rest,
            "fixture-horizontal-graphql": self._horizontal_graphql,
            "fixture-vertical-role": self._vertical_role,
            "fixture-cross-tenant": self._cross_tenant,
            "fixture-file-share": self._file_share,
            "fixture-business-workflow": self._business_workflow,
            "fixture-session-revocation": self._session_revocation,
            "fixture-client-xss": self._client_xss,
            "fixture-false-public": self._false_public,
            "fixture-false-secure-object": self._false_secure_object,
            "fixture-false-safe-client": self._false_safe_client,
        }
        return [await dispatch[validator_id](engagement, backend)]

    @staticmethod
    def _require_fixture(engagement: Engagement) -> None:
        if engagement.selected_mode is not EngagementMode.LAB:
            raise PermissionError("fixture validators can run only in lab mode")
        hosts = {urlsplit(item.uri).hostname for item in engagement.root_targets}
        if not hosts or not hosts.issubset({"localhost", "127.0.0.1", "::1"}):
            raise PermissionError("fixture validators require loopback targets")

    @staticmethod
    def _base(engagement: Engagement) -> str:
        return engagement.root_targets[0].uri.rstrip("/")

    @staticmethod
    def _auth(alias: str) -> dict[str, str]:
        return {"Authorization": f"Fixture {alias}"}

    async def _reset(self, engagement: Engagement, backend: DirectProxyBackend) -> HttpExchange:
        return await backend.send(
            engagement,
            "POST",
            f"{self._base(engagement)}/__fixture__/reset",
            headers={"X-Budo-Fixture": "reset-local-test-state"},
            account_alias="fixture-controller",
            source="fixture",
        )

    @staticmethod
    def _json(exchange: HttpExchange) -> dict[str, object]:
        try:
            value = json.loads(exchange.response_body or "")
        except json.JSONDecodeError:
            return {}
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _control(
        kind: str,
        description: str,
        exchanges: list[HttpExchange],
        observed: str,
        supports: bool,
        artifacts: list[str] | None = None,
    ) -> ControlExperiment:
        return ControlExperiment(
            control_id=new_id("control"),
            kind=kind,  # type: ignore[arg-type]
            description=description,
            request_exchange_ids=[item.exchange_id for item in exchanges],
            observed_result=observed,
            supports_finding=supports,
            artifact_refs=artifacts or [],
        )

    @staticmethod
    def _finding(
        engagement: Engagement,
        *,
        title: str,
        vulnerability_class: str,
        feature: str,
        endpoint: str,
        invariant: str,
        protected_asset: str,
        trust_boundary: str,
        enforcement: str,
        observed: str,
        expected: str,
        before: str,
        after: str,
        delta: str,
        normal: str,
        negative: str,
        benign: str,
        refutations: list[str],
        steps: list[str],
        exposure: str,
        mutation: str,
        cleanup: str,
        impact: str,
        severity: Severity,
        confidence: float,
        duplicate: str,
        decision: CandidateDecision,
    ) -> Finding:
        return Finding(
            finding_id=new_id("finding"),
            engagement_id=engagement.engagement_id,
            title=title,
            vulnerability_class=vulnerability_class,
            affected_asset=ValidatorRegistry._base(engagement),
            affected_feature=feature,
            endpoint_family=endpoint,
            attacker_prerequisites=["本地夹具自有测试账号", "仅使用仓库内无害测试对象"],
            victim_conditions=["另一个夹具账号或同一夹具对象处于受保护状态"],
            security_invariant=invariant,
            protected_asset=protected_asset,
            trust_boundary=trust_boundary,
            enforcement_point=enforcement,
            observed_behavior=observed,
            expected_behavior=expected,
            capability_before=before,
            capability_after=after,
            capability_delta=delta,
            normal_control=normal,
            negative_control=negative,
            strongest_benign_explanation=benign,
            refutation_attempts=refutations,
            reproduction_steps=steps,
            requests=[],
            responses=[],
            data_exposure_scope=exposure,
            mutation_scope=mutation,
            cleanup_status=cleanup,
            impact=impact,
            severity=severity,
            confidence=confidence,
            duplicate_risk=duplicate,
            status=CandidateStatus.VALIDATING if decision is CandidateDecision.CONFIRMED else CandidateStatus.KILL,
        )

    @staticmethod
    def _result(
        validator_id: str,
        finding: Finding,
        controls: list[ControlExperiment],
        exchanges: list[HttpExchange],
        *,
        decision: CandidateDecision,
        root_cause: str,
        repair_boundary: str,
        repeated: bool,
        normal: bool,
        negative: bool,
        cleanup: bool,
        closed: bool,
        confidence: float,
        artifacts: list[str] | None = None,
    ) -> ValidatorResult:
        outcome = ValidationOutcome(
            outcome_id=new_id("validation"),
            validator_id=validator_id,
            candidate_id=new_id("candidate"),
            decision=decision,
            vulnerability_class=finding.vulnerability_class,
            title=finding.title,
            root_cause_key=root_cause,
            repair_boundary=repair_boundary,
            finding_id=finding.finding_id,
            control_ids=[item.control_id for item in controls],
            exchange_ids=[item.exchange_id for item in exchanges],
            capability_delta=finding.capability_delta,
            strongest_benign_explanation=finding.strongest_benign_explanation,
            repeated=repeated,
            normal_control_passed=normal,
            negative_control_passed=negative,
            cleanup_completed=cleanup,
            evidence_closed=closed,
            confidence=confidence,
        )
        return ValidatorResult(outcome, finding, controls, exchanges, artifacts or [])

    async def _horizontal_rest(self, engagement: Engagement, backend: DirectProxyBackend) -> ValidatorResult:
        await self._reset(engagement, backend)
        base = self._base(engagement)
        own = await backend.send(
            engagement, "GET", f"{base}/api/objects/2", headers=self._auth("bob"), account_alias="bob", source="fixture"
        )
        cross_first = await backend.send(
            engagement, "GET", f"{base}/api/objects/1", headers=self._auth("bob"), account_alias="bob", source="fixture"
        )
        cross_second = await backend.send(
            engagement, "GET", f"{base}/api/objects/1", headers=self._auth("bob"), account_alias="bob", source="fixture"
        )
        anonymous = await backend.send(
            engagement, "GET", f"{base}/api/objects/1", account_alias="anonymous", source="fixture"
        )
        secure = await backend.send(
            engagement,
            "GET",
            f"{base}/api/secure-objects/1",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        repeated = cross_first.response_body == cross_second.response_body and cross_first.response_status == 200
        controls = [
            self._control(
                "normal", "Bob reads Bob's own fixture object.", [own], f"status={own.response_status}", True
            ),
            self._control(
                "negative",
                "Anonymous and owner-enforcing equivalents deny Alice's object.",
                [anonymous, secure],
                f"anonymous={anonymous.response_status}; secure={secure.response_status}",
                True,
            ),
        ]
        finding = self._finding(
            engagement,
            title="本地夹具共享对象解析器缺少水平授权",
            vulnerability_class="horizontal-authorization",
            feature="REST object retrieval",
            endpoint="GET /api/objects/{id}",
            invariant="账号只能读取明确授权给自己的私有对象。",
            protected_asset="alice 的一个本地私有测试对象",
            trust_boundary="alice 与 bob 两个自有夹具账号",
            enforcement="shared object resolver owner/tenant policy",
            observed="bob 仅替换对象 ID 后，两次获得 alice 对象的相同私有内容。",
            expected="服务端拒绝非所有者，或返回不泄露对象存在性的等价响应。",
            before="bob 只能正常读取对象 2。",
            after="bob 能读取 alice 的对象 1。",
            delta="跨越一个账号边界读取一个自有私有对象",
            normal=f"bob 自有对象返回 {own.response_status}。",
            negative=f"匿名返回 {anonymous.response_status}，安全等价端点返回 {secure.response_status}。",
            benign="对象可能公开或共享；匿名拒绝和安全等价端点的所有权拒绝排除了该解释。",
            refutations=["匿名访问", "安全等价端点", "精确重复", "自有对象基线"],
            steps=["bob 读取自有对象 2。", "仅把路径 ID 改为 1。", "重复请求。", "执行匿名和安全端点对照。"],
            exposure="仅 alice 的一个仓库夹具对象；没有第三方数据。",
            mutation="GET-only；只改变一个路径标识符。",
            cleanup="只读，无需清理；夹具状态已重置。",
            impact="低权限账号可越过对象所有权边界读取私有对象。",
            severity=Severity.MEDIUM,
            confidence=0.99,
            duplicate="按 shared object resolver 的同一修复边界聚类。",
            decision=CandidateDecision.CONFIRMED,
        )
        return self._result(
            "fixture-horizontal-rest",
            finding,
            controls,
            [own, cross_first, cross_second, anonymous, secure],
            decision=CandidateDecision.CONFIRMED,
            root_cause="object-resolver-policy-omitted",
            repair_boundary="enforce owner and tenant policy inside shared object resolver",
            repeated=repeated,
            normal=own.response_status == 200,
            negative=anonymous.response_status == 401 and secure.response_status == 403,
            cleanup=True,
            closed=repeated,
            confidence=0.99,
        )

    async def _horizontal_graphql(self, engagement: Engagement, backend: DirectProxyBackend) -> ValidatorResult:
        await self._reset(engagement, backend)
        base = self._base(engagement)

        async def query(alias: str, object_id: int) -> HttpExchange:
            body = {
                "operationName": "GetObject",
                "query": "query GetObject($objectId:Int!){object(id:$objectId){id owner tenant secret}}",
                "variables": {"objectId": object_id},
            }
            return await backend.send(
                engagement,
                "POST",
                f"{base}/graphql",
                headers={**self._auth(alias), "Content-Type": "application/json"},
                content=json.dumps(body),
                account_alias=alias,
                source="fixture",
            )

        own = await query("bob", 2)
        cross_first = await query("bob", 1)
        cross_second = await query("bob", 1)
        anonymous = await backend.send(
            engagement,
            "POST",
            f"{base}/graphql",
            headers={"Content-Type": "application/json"},
            content=json.dumps(
                {"query": "query($objectId:Int!){object(id:$objectId){id}}", "variables": {"objectId": 1}}
            ),
            account_alias="anonymous",
            source="fixture",
        )
        controls = [
            self._control(
                "normal", "Bob queries Bob's own object through GraphQL.", [own], f"status={own.response_status}", True
            ),
            self._control(
                "negative",
                "Anonymous GraphQL query is denied.",
                [anonymous],
                f"status={anonymous.response_status}",
                True,
            ),
        ]
        repeated = cross_first.response_body == cross_second.response_body and cross_first.response_status == 200
        finding = self._finding(
            engagement,
            title="GraphQL 对象入口复用缺少授权的共享解析器",
            vulnerability_class="horizontal-authorization",
            feature="GraphQL object query",
            endpoint="POST /graphql variables.objectId",
            invariant="GraphQL 对象解析必须执行与 REST 相同的对象所有权策略。",
            protected_asset="alice 的一个本地私有测试对象",
            trust_boundary="alice 与 bob 两个自有账号",
            enforcement="shared object resolver owner/tenant policy",
            observed="bob 只改变 GraphQL variables.objectId 后两次取得 alice 对象。",
            expected="解析器应拒绝非所有者。",
            before="bob 只能查询自己的对象 2。",
            after="bob 可查询 alice 对象 1。",
            delta="通过 GraphQL 跨账号读取一个私有对象",
            normal=f"自有对象查询返回 {own.response_status}。",
            negative=f"匿名 GraphQL 查询返回 {anonymous.response_status}。",
            benign="可能是独立 GraphQL 缺陷；响应中的同一 root_cause 标记和共享解析器行为表明同一修复可解决。",
            refutations=["匿名查询", "精确重复", "自有对象变量基线", "与 REST 根因比较"],
            steps=["bob 查询对象 2。", "只把 variables.objectId 改为 1。", "重复。", "执行匿名对照。"],
            exposure="仅仓库夹具中的一个 alice 对象。",
            mutation="POST GraphQL 只读 query；只改变一个变量。",
            cleanup="只读，无需清理。",
            impact="GraphQL 客户端可复用同一缺失授权解析器跨账号读取。",
            severity=Severity.MEDIUM,
            confidence=0.99,
            duplicate="与 REST 入口由同一 shared object resolver 修复，必须合并。",
            decision=CandidateDecision.CONFIRMED,
        )
        return self._result(
            "fixture-horizontal-graphql",
            finding,
            controls,
            [own, cross_first, cross_second, anonymous],
            decision=CandidateDecision.CONFIRMED,
            root_cause="object-resolver-policy-omitted",
            repair_boundary="enforce owner and tenant policy inside shared object resolver",
            repeated=repeated,
            normal=own.response_status == 200,
            negative=anonymous.response_status == 401,
            cleanup=True,
            closed=repeated,
            confidence=0.99,
        )

    async def _vertical_role(self, engagement: Engagement, backend: DirectProxyBackend) -> ValidatorResult:
        base = self._base(engagement)
        admin = await backend.send(
            engagement,
            "GET",
            f"{base}/api/admin/audit",
            headers=self._auth("admin"),
            account_alias="admin",
            source="fixture",
        )
        low_first = await backend.send(
            engagement,
            "GET",
            f"{base}/api/admin/audit",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        low_second = await backend.send(
            engagement,
            "GET",
            f"{base}/api/admin/audit",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        secure = await backend.send(
            engagement,
            "GET",
            f"{base}/api/secure-admin/audit",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        controls = [
            self._control(
                "normal",
                "Admin invokes the administrative audit export.",
                [admin],
                f"status={admin.response_status}",
                True,
            ),
            self._control(
                "negative", "Role-enforcing equivalent denies Bob.", [secure], f"status={secure.response_status}", True
            ),
        ]
        finding = self._finding(
            engagement,
            title="本地夹具管理功能缺少垂直角色授权",
            vulnerability_class="vertical-authorization",
            feature="administrative audit export",
            endpoint="GET /api/admin/audit",
            invariant="只有 admin 角色可以调用管理审计导出。",
            protected_asset="管理级审计导出能力",
            trust_boundary="普通用户到管理员角色边界",
            enforcement="admin function role policy",
            observed="普通账号 bob 两次获得与 admin 相同的 audit-export 能力。",
            expected="普通账号应被拒绝。",
            before="bob 无管理权限。",
            after="bob 可调用管理审计导出。",
            delta="从普通用户提升到一个管理功能",
            normal=f"admin 正常调用返回 {admin.response_status}。",
            negative=f"安全等价端点对 bob 返回 {secure.response_status}。",
            benign="功能名称可能仅为展示；返回明确 admin_capability 且安全等价端点执行角色拒绝，排除了该解释。",
            refutations=["admin 正常基线", "安全等价端点", "普通账号重复"],
            steps=["admin 调用管理功能。", "保持请求不变切换为 bob。", "重复。", "调用安全等价端点。"],
            exposure="仅本地夹具审计字符串，无真实管理数据。",
            mutation="GET-only。",
            cleanup="只读，无需清理。",
            impact="普通账号获得管理级功能能力。",
            severity=Severity.HIGH,
            confidence=0.99,
            duplicate="按 admin function role policy 修复边界去重。",
            decision=CandidateDecision.CONFIRMED,
        )
        return self._result(
            "fixture-vertical-role",
            finding,
            controls,
            [admin, low_first, low_second, secure],
            decision=CandidateDecision.CONFIRMED,
            root_cause="admin-function-role-check-omitted",
            repair_boundary="enforce administrative role at audit function handler",
            repeated=low_first.response_status == low_second.response_status == 200,
            normal=admin.response_status == 200,
            negative=secure.response_status == 403,
            cleanup=True,
            closed=True,
            confidence=0.99,
        )

    async def _cross_tenant(self, engagement: Engagement, backend: DirectProxyBackend) -> ValidatorResult:
        base = self._base(engagement)
        own = await backend.send(
            engagement,
            "GET",
            f"{base}/api/tenant/blue/settings",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        cross_first = await backend.send(
            engagement,
            "GET",
            f"{base}/api/tenant/red/settings",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        cross_second = await backend.send(
            engagement,
            "GET",
            f"{base}/api/tenant/red/settings",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        anonymous = await backend.send(
            engagement, "GET", f"{base}/api/tenant/red/settings", account_alias="anonymous", source="fixture"
        )
        controls = [
            self._control("normal", "Bob reads blue tenant settings.", [own], f"status={own.response_status}", True),
            self._control(
                "negative",
                "Anonymous tenant access is denied.",
                [anonymous],
                f"status={anonymous.response_status}",
                True,
            ),
        ]
        finding = self._finding(
            engagement,
            title="本地夹具租户设置缺少上下文隔离",
            vulnerability_class="cross-tenant-authorization",
            feature="tenant settings",
            endpoint="GET /api/tenant/{tenant}/settings",
            invariant="账号只能访问其所属租户设置。",
            protected_asset="red 租户的一个本地设置值",
            trust_boundary="blue 与 red 两个夹具租户",
            enforcement="tenant context policy",
            observed="blue 租户账号 bob 只改变租户路径后两次获得 red 私有设置。",
            expected="服务端应按会话租户拒绝跨租户路径。",
            before="bob 只能访问 blue 租户。",
            after="bob 可访问 red 租户设置。",
            delta="跨越一个自控租户边界读取设置",
            normal=f"blue 设置返回 {own.response_status}。",
            negative=f"匿名 red 设置返回 {anonymous.response_status}。",
            benign="设置可能公开；匿名拒绝且响应明确 private_setting，排除公开解释。",
            refutations=["本租户基线", "匿名对照", "精确重复"],
            steps=["bob 读取 blue 设置。", "只把 tenant 改为 red。", "重复。", "匿名请求 red。"],
            exposure="仅两个本地夹具租户。",
            mutation="GET-only；只改变租户路径。",
            cleanup="只读。",
            impact="租户隔离失效导致跨租户配置读取。",
            severity=Severity.HIGH,
            confidence=0.99,
            duplicate="按 tenant context policy 去重。",
            decision=CandidateDecision.CONFIRMED,
        )
        return self._result(
            "fixture-cross-tenant",
            finding,
            controls,
            [own, cross_first, cross_second, anonymous],
            decision=CandidateDecision.CONFIRMED,
            root_cause="tenant-context-policy-omitted",
            repair_boundary="bind tenant settings lookup to authenticated tenant",
            repeated=cross_first.response_body == cross_second.response_body,
            normal=own.response_status == 200,
            negative=anonymous.response_status == 401,
            cleanup=True,
            closed=True,
            confidence=0.99,
        )

    async def _file_share(self, engagement: Engagement, backend: DirectProxyBackend) -> ValidatorResult:
        await self._reset(engagement, backend)
        base = self._base(engagement)
        own = await backend.send(
            engagement, "GET", f"{base}/api/files/2", headers=self._auth("bob"), account_alias="bob", source="fixture"
        )
        cross_first = await backend.send(
            engagement, "GET", f"{base}/api/files/1", headers=self._auth("bob"), account_alias="bob", source="fixture"
        )
        cross_second = await backend.send(
            engagement, "GET", f"{base}/api/files/1", headers=self._auth("bob"), account_alias="bob", source="fixture"
        )
        secure = await backend.send(
            engagement,
            "GET",
            f"{base}/api/secure-files/1",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        revoked = await backend.send(
            engagement,
            "GET",
            f"{base}/api/shares/revoked-share",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        revoked_secure = await backend.send(
            engagement,
            "GET",
            f"{base}/api/secure-shares/revoked-share",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        controls = [
            self._control(
                "normal", "Bob downloads Bob's own harmless text file.", [own], f"status={own.response_status}", True
            ),
            self._control(
                "negative",
                "Owner-enforcing file and revoked-share equivalents deny Bob.",
                [secure, revoked_secure],
                f"secure-file={secure.response_status}; secure-share={revoked_secure.response_status}",
                True,
            ),
        ]
        finding = self._finding(
            engagement,
            title="文件下载与撤销分享入口未统一执行授权",
            vulnerability_class="file-share-authorization",
            feature="file download and revoked share consumption",
            endpoint="GET /api/files/{id}; GET /api/shares/{token}",
            invariant="私有文件及撤销分享必须在每次消费时执行所有者和分享状态授权。",
            protected_asset="alice 的一个无害文本夹具文件",
            trust_boundary="文件所有者、接收者和 revoked 状态",
            enforcement="file/share consumption policy",
            observed="bob 两次直接下载 alice 文件，并且可消费已撤销分享。",
            expected="非所有者文件请求与 revoked 分享均应拒绝。",
            before="bob 只能下载自有文件或有效分享。",
            after="bob 可下载 alice 私有文件并消费 revoked 分享。",
            delta="跨文件所有权和撤销状态读取一个测试文件",
            normal=f"自有文件返回 {own.response_status}。",
            negative=f"安全文件返回 {secure.response_status}，安全 revoked 分享返回 {revoked_secure.response_status}。",
            benign="文件可能已分享；直接文件端点无分享上下文，且 revoked 安全端点明确拒绝，排除该解释。",
            refutations=["自有文件基线", "安全文件端点", "revoked 分享", "重复下载"],
            steps=["bob 下载自有文件 2。", "仅把文件 ID 改为 1 并重复。", "读取 revoked-share。", "执行安全端点对照。"],
            exposure="仅仓库夹具中的两个无害文本文件。",
            mutation="GET-only；分享状态由 fixture reset 建立。",
            cleanup="夹具 reset 已恢复分享状态。",
            impact="文件所有权与撤销状态不能阻止私有文件读取。",
            severity=Severity.HIGH,
            confidence=0.99,
            duplicate="下载和分享入口按 file/share consumption policy 的同一修复边界评估。",
            decision=CandidateDecision.CONFIRMED,
        )
        return self._result(
            "fixture-file-share",
            finding,
            controls,
            [own, cross_first, cross_second, secure, revoked, revoked_secure],
            decision=CandidateDecision.CONFIRMED,
            root_cause="file-share-consumption-policy-divergence",
            repair_boundary="enforce owner and active-share policy at file consumption service",
            repeated=cross_first.response_body == cross_second.response_body,
            normal=own.response_status == 200,
            negative=secure.response_status == 403 and revoked_secure.response_status == 403,
            cleanup=True,
            closed=revoked.response_status == 200,
            confidence=0.99,
        )

    async def _business_workflow(self, engagement: Engagement, backend: DirectProxyBackend) -> ValidatorResult:
        reset_before = await self._reset(engagement, backend)
        base = self._base(engagement)
        state = await backend.send(
            engagement, "GET", f"{base}/api/orders/2", headers=self._auth("bob"), account_alias="bob", source="fixture"
        )
        skip = await backend.send(
            engagement,
            "POST",
            f"{base}/api/orders/2/confirm",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        replay = await backend.send(
            engagement,
            "POST",
            f"{base}/api/orders/2/confirm",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        reset_control = await self._reset(engagement, backend)
        secure = await backend.send(
            engagement,
            "POST",
            f"{base}/api/secure-orders/2/confirm",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        preview = await backend.send(
            engagement,
            "POST",
            f"{base}/api/orders/2/preview",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        normal = await backend.send(
            engagement,
            "POST",
            f"{base}/api/secure-orders/2/confirm",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        cleanup = await self._reset(engagement, backend)
        controls = [
            self._control(
                "normal",
                "Preview then secure confirm performs the documented sequence once.",
                [preview, normal],
                f"preview={preview.response_status}; confirm={normal.response_status}",
                True,
            ),
            self._control(
                "negative",
                "Secure confirm rejects a draft order when preview is skipped.",
                [secure],
                f"status={secure.response_status}",
                True,
            ),
        ]
        skip_payload = self._json(skip)
        replay_payload = self._json(replay)
        finding = self._finding(
            engagement,
            title="多步骤订单流程允许跳过前置步骤并重复一次性确认",
            vulnerability_class="business-logic-workflow",
            feature="order preview/confirm workflow",
            endpoint="POST /api/orders/{id}/confirm",
            invariant="订单必须从 reviewed 状态确认，且一次性确认不得重复产生效果。",
            protected_asset="bob 的一个可恢复本地测试订单",
            trust_boundary="draft、reviewed、confirmed 状态机",
            enforcement="order transition and idempotency policy",
            observed=(
                f"draft 订单直接确认成功，随后重复确认使 confirm_count 从 "
                f"{skip_payload.get('confirm_count')} 增至 {replay_payload.get('confirm_count')}。"
            ),
            expected="跳过 preview 或重复 confirm 应返回冲突且不改变状态。",
            before="bob 只有 draft 测试订单。",
            after="bob 可跳跃到 confirmed 并重复一次性效果。",
            delta="绕过一个业务前置步骤并重复一次性状态变更",
            normal=f"preview 后安全确认返回 {normal.response_status}。",
            negative=f"draft 上安全确认返回 {secure.response_status}。",
            benign="confirm 可能设计为幂等；递增 confirm_count 证明重复产生了新的效果。",
            refutations=["读取初始状态", "安全状态机对照", "重复提交", "正常顺序", "reset 清理"],
            steps=[
                "reset 后读取 draft。",
                "跳过 preview 直接 confirm。",
                "重复 confirm。",
                "reset 后执行安全负对照和正常顺序。",
            ],
            exposure="仅 bob 的一个本地可恢复测试订单。",
            mutation="POST；仅自有夹具对象；每组实验前后 reset。",
            cleanup=f"最终 reset 返回 {cleanup.response_status}，状态已恢复。",
            impact="攻击者可绕过业务顺序并重复一次性效果。",
            severity=Severity.HIGH,
            confidence=0.99,
            duplicate="按 order transition and idempotency policy 去重。",
            decision=CandidateDecision.CONFIRMED,
        )
        return self._result(
            "fixture-business-workflow",
            finding,
            controls,
            [reset_before, state, skip, replay, reset_control, secure, preview, normal, cleanup],
            decision=CandidateDecision.CONFIRMED,
            root_cause="order-transition-and-idempotency-policy-omitted",
            repair_boundary="enforce state prerequisite and idempotency in order confirmation service",
            repeated=replay_payload.get("confirm_count") == 2,
            normal=normal.response_status == 200,
            negative=secure.response_status == 409,
            cleanup=cleanup.response_status == 200,
            closed=skip_payload.get("previous") == "draft",
            confidence=0.99,
        )

    async def _session_revocation(self, engagement: Engagement, backend: DirectProxyBackend) -> ValidatorResult:
        reset = await self._reset(engagement, backend)
        base = self._base(engagement)
        started = await backend.send(
            engagement,
            "POST",
            f"{base}/api/session/start",
            headers=self._auth("alice"),
            account_alias="alice",
            source="fixture",
        )
        token = self._json(started).get("session")
        if not isinstance(token, str):
            raise RuntimeError("fixture session start did not return a token")
        session_header = {"X-Fixture-Api-Session": token}
        before = await backend.send(
            engagement, "GET", f"{base}/api/session/me", headers=session_header, account_alias="alice", source="fixture"
        )
        revoked = await backend.send(
            engagement,
            "POST",
            f"{base}/api/session/revoke",
            headers=session_header,
            account_alias="alice",
            source="fixture",
        )
        after_first = await backend.send(
            engagement, "GET", f"{base}/api/session/me", headers=session_header, account_alias="alice", source="fixture"
        )
        after_second = await backend.send(
            engagement, "GET", f"{base}/api/session/me", headers=session_header, account_alias="alice", source="fixture"
        )
        secure = await backend.send(
            engagement,
            "GET",
            f"{base}/api/secure-session/me",
            headers=session_header,
            account_alias="alice",
            source="fixture",
        )
        cleanup = await self._reset(engagement, backend)
        controls = [
            self._control(
                "normal",
                "Fresh session accesses its own session profile.",
                [before],
                f"status={before.response_status}",
                True,
            ),
            self._control(
                "negative",
                "Revocation-aware session consumer rejects the same old session.",
                [secure],
                f"status={secure.response_status}",
                True,
            ),
        ]
        finding = self._finding(
            engagement,
            title="会话撤销后旧会话仍保留认证能力",
            vulnerability_class="authentication-session",
            feature="session revocation lifecycle",
            endpoint="POST /api/session/revoke; GET /api/session/me",
            invariant="明确撤销后，旧会话必须立即失去所有认证能力。",
            protected_asset="alice 的一个本地一次性 API 会话",
            trust_boundary="authenticated 到 revoked 状态",
            enforcement="session consumer revocation check",
            observed="撤销返回成功后，同一旧会话仍连续两次访问受保护 profile。",
            expected="旧会话应返回 401；新会话才能恢复访问。",
            before="新会话可访问自身 profile。",
            after="已撤销会话仍保留相同认证能力。",
            delta="跨越 revoked 状态继续使用旧认证会话",
            normal=f"撤销前返回 {before.response_status}。",
            negative=f"revocation-aware 等价端点返回 {secure.response_status}。",
            benign="撤销可能异步；连续重复和安全等价消费者的立即拒绝排除了传播延迟。",
            refutations=["撤销前基线", "两次撤销后重复", "安全消费者", "reset 清理"],
            steps=["启动本地会话。", "访问 profile。", "撤销。", "用同一会话访问两次。", "调用安全等价端点。"],
            exposure="仅 alice 的本地夹具会话。",
            mutation="POST revoke；仅自有 fixture session；最终 reset。",
            cleanup=f"reset 返回 {cleanup.response_status}，会话表已清空。",
            impact="退出或权限撤销后旧会话仍可继续认证访问。",
            severity=Severity.HIGH,
            confidence=0.99,
            duplicate="按 session consumer revocation check 去重。",
            decision=CandidateDecision.CONFIRMED,
        )
        return self._result(
            "fixture-session-revocation",
            finding,
            controls,
            [reset, started, before, revoked, after_first, after_second, secure, cleanup],
            decision=CandidateDecision.CONFIRMED,
            root_cause="session-consumer-revocation-check-omitted",
            repair_boundary="enforce revocation in common authenticated session middleware",
            repeated=after_first.response_status == after_second.response_status == 200,
            normal=before.response_status == 200 and revoked.response_status == 200,
            negative=secure.response_status == 401,
            cleanup=cleanup.response_status == 200,
            closed=True,
            confidence=0.99,
        )

    async def _client_xss(self, engagement: Engagement, backend: DirectProxyBackend) -> ValidatorResult:
        base = self._base(engagement)
        marker = "<span id='budo-inert-marker'>BUDO_INERT</span>"
        vulnerable_url = f"{base}/preview?value={quote(marker, safe='')}"
        safe_url = f"{base}/safe-preview?value={quote(marker, safe='')}"
        browser_root = self.artifact_root / "client-xss"
        browser = BrowserSessionManager(browser_root, engagement)
        artifacts: list[str] = []
        try:
            page = await browser.open("client-test", vulnerable_url)
            first = await page.locator("#budo-inert-marker").count() == 1
            first_shot = await browser.screenshot("client-test", page, "vulnerable-first")
            artifacts.append(str(first_shot))
            await page.reload(wait_until="domcontentloaded")
            repeated = await page.locator("#budo-inert-marker").count() == 1
            second_shot = await browser.screenshot("client-test", page, "vulnerable-repeat")
            artifacts.append(str(second_shot))
            await page.close()
            safe_page = await browser.open("client-control", safe_url)
            safe_absent = await safe_page.locator("#budo-inert-marker").count() == 0
            safe_text = "BUDO_INERT" in await safe_page.locator("#sink").inner_text()
            safe_shot = await browser.screenshot("client-control", safe_page, "safe-control")
            artifacts.append(str(safe_shot))
            await safe_page.close()
        finally:
            await browser.stop()
        for path in browser_root.rglob("*"):
            if path.is_file():
                artifacts.append(str(path))
        vulnerable = await backend.send(
            engagement, "GET", vulnerable_url, account_alias="client-test", source="fixture"
        )
        safe = await backend.send(engagement, "GET", safe_url, account_alias="client-control", source="fixture")
        controls = [
            self._control(
                "normal",
                "Vulnerable DOM flow creates an inert marker twice.",
                [vulnerable],
                f"marker-first={first}; marker-repeat={repeated}",
                True,
                artifacts[:2],
            ),
            self._control(
                "negative",
                "textContent-based equivalent renders text without creating a node.",
                [safe],
                f"marker-absent={safe_absent}; text-preserved={safe_text}",
                True,
                [str(safe_shot)],
            ),
        ]
        finding = self._finding(
            engagement,
            title="客户端参数流入 innerHTML 形成可验证 DOM XSS sink",
            vulnerability_class="client-side-xss",
            feature="client preview renderer",
            endpoint="GET /preview?value=...",
            invariant="URL 参数不得流入可执行 DOM sink。",
            protected_asset="隔离 Playwright 页面 DOM 与同源会话上下文",
            trust_boundary="URL 参数到 innerHTML",
            enforcement="client preview rendering sink",
            observed="无害 span marker 在两次浏览器加载中均成为真实 DOM 节点。",
            expected="参数仅作为文本呈现，不创建由输入控制的 DOM。",
            before="输入只能作为文本。",
            after="输入可控制 innerHTML sink。",
            delta="从文本输入获得同源 DOM 注入能力（仅用 inert marker 证明）",
            normal="vulnerable flow 两次创建 inert marker。",
            negative="safe textContent flow 保留文本但不创建 marker 节点。",
            benign="可能只是服务端反射；源 HTML 不包含 payload，运行后 DOM 才出现节点，排除了纯反射解释。",
            refutations=["重复浏览器加载", "textContent 安全对照", "DOM 节点检查", "无 alert/外联 payload"],
            steps=[
                "打开带 inert marker 的 preview。",
                "检查 DOM 节点并截图。",
                "刷新重复。",
                "打开 safe-preview 对照。",
            ],
            exposure="仅 localhost fixture 与无害 DOM marker。",
            mutation="GET-only；不执行脚本、不外联。",
            cleanup="关闭并删除运行期浏览器上下文即可；无服务端状态。",
            impact="攻击者可把输入送入同源可执行 DOM sink；报告影响保持保守。",
            severity=Severity.MEDIUM,
            confidence=0.98,
            duplicate="按 client preview innerHTML sink 修复边界去重。",
            decision=CandidateDecision.CONFIRMED,
        )
        return self._result(
            "fixture-client-xss",
            finding,
            controls,
            [vulnerable, safe],
            decision=CandidateDecision.CONFIRMED,
            root_cause="client-preview-innerhtml-trust",
            repair_boundary="replace preview innerHTML assignment with safe text or sanitizer",
            repeated=first and repeated,
            normal=first,
            negative=safe_absent and safe_text,
            cleanup=True,
            closed=True,
            confidence=0.98,
            artifacts=list(dict.fromkeys(artifacts)),
        )

    async def _false_public(self, engagement: Engagement, backend: DirectProxyBackend) -> ValidatorResult:
        base = self._base(engagement)
        anonymous = await backend.send(
            engagement, "GET", f"{base}/api/public/101", account_alias="anonymous", source="fixture"
        )
        authenticated = await backend.send(
            engagement,
            "GET",
            f"{base}/api/public/101",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        controls = [
            self._control(
                "refutation",
                "Anonymous and authenticated responses both declare visibility=public.",
                [anonymous, authenticated],
                "intentional public design",
                False,
            )
        ]
        finding = self._finding(
            engagement,
            title="伪候选：明确公开对象允许匿名读取",
            vulnerability_class="horizontal-authorization",
            feature="documented public object",
            endpoint="GET /api/public/{id}",
            invariant="公开对象允许匿名读取。",
            protected_asset="公开 fixture 文档",
            trust_boundary="无私有边界",
            enforcement="public visibility policy",
            observed="匿名与认证请求都返回 visibility=public。",
            expected="公开对象允许匿名读取。",
            before="匿名可读公开对象。",
            after="能力未增加。",
            delta="none",
            normal="匿名按设计返回 200。",
            negative="认证身份未扩大字段或范围。",
            benign="CONTROL_RESULT: INTENTIONALLY_PUBLIC。",
            refutations=["比较匿名与认证响应", "检查 visibility"],
            steps=["匿名读取 101。", "以 bob 读取 101 并比较。"],
            exposure="公开夹具对象。",
            mutation="GET-only。",
            cleanup="无需清理。",
            impact="无安全影响。",
            severity=Severity.INFO,
            confidence=0.99,
            duplicate="不应形成报告。",
            decision=CandidateDecision.KILL,
        )
        return self._result(
            "fixture-false-public",
            finding,
            controls,
            [anonymous, authenticated],
            decision=CandidateDecision.KILL,
            root_cause="intentional-public-design",
            repair_boundary="no fix",
            repeated=True,
            normal=True,
            negative=True,
            cleanup=True,
            closed=True,
            confidence=0.99,
        )

    async def _false_secure_object(self, engagement: Engagement, backend: DirectProxyBackend) -> ValidatorResult:
        base = self._base(engagement)
        own = await backend.send(
            engagement,
            "GET",
            f"{base}/api/secure-objects/2",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        cross_first = await backend.send(
            engagement,
            "GET",
            f"{base}/api/secure-objects/1",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        cross_second = await backend.send(
            engagement,
            "GET",
            f"{base}/api/secure-objects/1",
            headers=self._auth("bob"),
            account_alias="bob",
            source="fixture",
        )
        controls = [
            self._control(
                "normal", "Bob reads Bob's own secure object.", [own], f"status={own.response_status}", False
            ),
            self._control(
                "refutation",
                "Cross-account requests are consistently denied.",
                [cross_first, cross_second],
                f"statuses={cross_first.response_status},{cross_second.response_status}",
                False,
            ),
        ]
        finding = self._finding(
            engagement,
            title="伪候选：安全对象端点正确拒绝跨账号访问",
            vulnerability_class="horizontal-authorization",
            feature="secure object retrieval",
            endpoint="GET /api/secure-objects/{id}",
            invariant="账号只能读取自己的对象。",
            protected_asset="alice 私有对象",
            trust_boundary="alice/bob",
            enforcement="owner check",
            observed="bob 自有对象成功，alice 对象连续两次返回 403。",
            expected="该行为符合预期。",
            before="bob 只能访问自己的对象。",
            after="能力未增加。",
            delta="none",
            normal=f"自有对象 {own.response_status}。",
            negative=f"跨账号两次 {cross_first.response_status}/{cross_second.response_status}。",
            benign="CONTROL_RESULT: OWNER_CHECK_ENFORCED。",
            refutations=["自有基线", "跨账号重复"],
            steps=["读取对象 2。", "改为对象 1 并重复。"],
            exposure="无跨账号内容。",
            mutation="GET-only。",
            cleanup="无需清理。",
            impact="无。",
            severity=Severity.INFO,
            confidence=0.99,
            duplicate="不报告。",
            decision=CandidateDecision.KILL,
        )
        return self._result(
            "fixture-false-secure-object",
            finding,
            controls,
            [own, cross_first, cross_second],
            decision=CandidateDecision.KILL,
            root_cause="owner-check-enforced-control",
            repair_boundary="no fix",
            repeated=cross_first.response_status == cross_second.response_status == 403,
            normal=own.response_status == 200,
            negative=True,
            cleanup=True,
            closed=True,
            confidence=0.99,
        )

    async def _false_safe_client(self, engagement: Engagement, backend: DirectProxyBackend) -> ValidatorResult:
        base = self._base(engagement)
        marker = "<span id='budo-safe-control'>SAFE</span>"
        url = f"{base}/safe-preview?value={quote(marker, safe='')}"
        browser_root = self.artifact_root / "safe-client-control"
        browser = BrowserSessionManager(browser_root, engagement)
        try:
            page = await browser.open("safe-client", url)
            absent_first = await page.locator("#budo-safe-control").count() == 0
            text_first = "SAFE" in await page.locator("#sink").inner_text()
            await page.reload(wait_until="domcontentloaded")
            absent_second = await page.locator("#budo-safe-control").count() == 0
            shot = await browser.screenshot("safe-client", page, "safe-repeat")
            await page.close()
        finally:
            await browser.stop()
        exchange = await backend.send(engagement, "GET", url, account_alias="safe-client", source="fixture")
        controls = [
            self._control(
                "refutation",
                "textContent rendering preserves text but creates no marker node on repeat.",
                [exchange],
                f"absent={absent_first and absent_second}; text={text_first}",
                False,
                [str(shot)],
            )
        ]
        finding = self._finding(
            engagement,
            title="伪候选：安全预览仅按文本渲染输入",
            vulnerability_class="client-side-xss",
            feature="safe preview renderer",
            endpoint="GET /safe-preview?value=...",
            invariant="不可信输入只按文本渲染。",
            protected_asset="浏览器 DOM",
            trust_boundary="URL 参数到 textContent",
            enforcement="textContent sink",
            observed="输入文字可见，但两次均未创建输入控制的 DOM 节点。",
            expected="符合预期。",
            before="文本可显示。",
            after="无可执行能力。",
            delta="none",
            normal="文字 SAFE 可见。",
            negative="marker 节点两次均不存在。",
            benign="CONTROL_RESULT: TEXTCONTENT_ESCAPED。",
            refutations=["DOM 节点检查", "刷新重复", "截图"],
            steps=["打开 safe-preview。", "检查节点与文本。", "刷新重复。"],
            exposure="仅无害 marker。",
            mutation="GET-only。",
            cleanup="关闭浏览器上下文。",
            impact="无。",
            severity=Severity.INFO,
            confidence=0.99,
            duplicate="不报告。",
            decision=CandidateDecision.KILL,
        )
        return self._result(
            "fixture-false-safe-client",
            finding,
            controls,
            [exchange],
            decision=CandidateDecision.KILL,
            root_cause="safe-textcontent-control",
            repair_boundary="no fix",
            repeated=absent_first and absent_second,
            normal=text_first,
            negative=True,
            cleanup=True,
            closed=True,
            confidence=0.99,
            artifacts=[str(shot)],
        )
