"""Repository-facing engagement, run, finding, and audit services."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from budobugs.core.config import load_yaml_model, write_yaml_model
from budobugs.core.identifiers import new_id
from budobugs.core.io import atomic_write_json
from budobugs.core.paths import WorkspacePaths, safe_join
from budobugs.models import (
    AuditEvent,
    AuthorizationStatus,
    CostRecord,
    Engagement,
    Finding,
    Run,
)
from budobugs.storage.eventlog import EventLog
from budobugs.storage.state import StateStore


class RepositoryService:
    """Single boundary for state changes and their append-only audit trail."""

    def __init__(self, paths: WorkspacePaths | None = None) -> None:
        self.paths = paths or WorkspacePaths.discover()
        self.paths.initialize()
        self.store = StateStore(self.paths.state / "budobugs.sqlite3")
        self.events = EventLog(self.paths.events / "audit.jsonl")

    def engagement_path(self, engagement_id: str) -> Path:
        return safe_join(self.paths.engagements, engagement_id, "engagement.yaml")

    def save_engagement(self, engagement: Engagement, *, actor: str = "cli") -> Path:
        path = self.engagement_path(engagement.engagement_id)
        write_yaml_model(path, engagement)
        self.store.save("engagement", engagement.engagement_id, engagement)
        self.audit(
            "engagement.saved",
            actor,
            engagement_id=engagement.engagement_id,
            details={"authorization_status": engagement.authorization_status.value},
        )
        return path

    def load_engagement(self, engagement_id: str) -> Engagement:
        path = self.engagement_path(engagement_id)
        if not path.is_file():
            raise FileNotFoundError(f"engagement not found: {engagement_id}")
        return load_yaml_model(path, Engagement)

    def authorize_engagement(self, engagement_id: str) -> Engagement:
        engagement = self.load_engagement(engagement_id)
        if engagement.authorization_status is AuthorizationStatus.REVOKED:
            raise ValueError("revoked engagement cannot be authorized")
        if engagement.authorization_status is not AuthorizationStatus.AUTHORIZED:
            payload = engagement.model_dump(mode="python")
            payload.update(
                authorization_status=AuthorizationStatus.AUTHORIZED,
                authorized_at=datetime.now(UTC),
            )
            engagement = Engagement.model_validate(payload)
            self.save_engagement(engagement, actor="human-authorization-command")
        return engagement

    def save_run(self, run: Run) -> Path:
        directory = safe_join(self.paths.runs, run.run_id)
        path = directory / "run.json"
        atomic_write_json(path, run.model_dump(mode="json", exclude_none=False))
        self.store.save("run", run.run_id, run)
        return path

    def load_run(self, run_id: str) -> Run:
        value = self.store.load("run", run_id, Run)
        if value is None:
            raise FileNotFoundError(f"run not found: {run_id}")
        return value

    def latest_run(self, engagement_id: str) -> Run | None:
        runs = [item for item in self.store.list("run", Run) if item.engagement_id == engagement_id]
        return max(runs, key=lambda item: item.updated_at) if runs else None

    def save_finding(self, finding: Finding) -> None:
        self.store.save("finding", finding.finding_id, finding)

    def save_cost(self, cost: CostRecord) -> None:
        self.store.save("cost", cost.cost_id, cost)

    def list_costs(self, run_id: str | None = None, candidate_id: str | None = None) -> list[CostRecord]:
        values = self.store.list("cost", CostRecord)
        if run_id is not None:
            values = [item for item in values if item.run_id == run_id]
        if candidate_id is not None:
            values = [item for item in values if item.candidate_id == candidate_id]
        return values

    def load_finding(self, finding_id: str) -> Finding:
        value = self.store.load("finding", finding_id, Finding)
        if value is None:
            raise FileNotFoundError(f"finding not found: {finding_id}")
        return value

    def list_findings(self, engagement_id: str | None = None) -> list[Finding]:
        values = self.store.list("finding", Finding)
        return values if engagement_id is None else [item for item in values if item.engagement_id == engagement_id]

    def audit(
        self,
        event_type: str,
        actor: str,
        *,
        engagement_id: str | None = None,
        run_id: str | None = None,
        message: str | None = None,
        details: dict[str, object] | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=new_id("event"),
            event_type=event_type,
            engagement_id=engagement_id,
            run_id=run_id,
            actor=actor,
            message=message or event_type,
            details=json.loads(json.dumps(details or {}, default=str)),
        )
        self.events.append(event)
        self.store.record_event(event.event_id, event.event_type, event.model_dump_json())
        return event

    def timeline(self, engagement_id: str) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for envelope in self.events.replay(verify=True):
            event = envelope["event"]
            if event.get("engagement_id") == engagement_id:
                rows.append(event)
        return rows
