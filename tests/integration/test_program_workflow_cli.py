from __future__ import annotations

from tests.unit.test_program_workflow_experiments import _session_template
from typer.testing import CliRunner

from budobugs.cli.app import app
from budobugs.models import EngagementMode, SafeWorkflowExperimentTemplate
from budobugs.orchestration.engine import HuntEngine


def test_workflow_experiment_cli_stores_only_reference_and_engine_loads_union(
    service,
    lab_engagement,
    monkeypatch,
) -> None:
    program = lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {"alice": "keyring://fixture/alice"},
        }
    )
    service.save_engagement(program)
    template = _session_template(program.root_targets[0].uri)
    raw = template.model_dump_json()
    reference = "keyring://fixture/session-workflow"
    monkeypatch.setattr("budobugs.cli.app._service", lambda: service)
    monkeypatch.setattr("budobugs.cli.app.SecretStore.set", lambda *_args: reference)
    monkeypatch.setenv("BUDO_WORKFLOW_TEMPLATE", raw)

    result = CliRunner().invoke(
        app,
        [
            "engagement",
            "experiment-set",
            program.engagement_id,
            "--spec-env",
            "BUDO_WORKFLOW_TEMPLATE",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    updated = service.load_engagement(program.engagement_id)
    assert updated.safe_experiment_secret_refs == {template.template_id: reference}
    assert raw not in updated.model_dump_json()

    monkeypatch.setattr(
        "budobugs.orchestration.engine.SecretStore.get",
        lambda _self, requested: raw if requested == reference else None,
    )
    loaded = HuntEngine(service)._safe_experiment_templates(updated)
    assert len(loaded) == 1
    assert isinstance(loaded[0], SafeWorkflowExperimentTemplate)
    assert loaded[0].template_id == template.template_id

    service.authorize_engagement(program.engagement_id)
    denied = CliRunner().invoke(
        app,
        [
            "engagement",
            "experiment-set",
            program.engagement_id,
            "--spec-env",
            "BUDO_WORKFLOW_TEMPLATE",
            "--json",
        ],
    )
    assert denied.exit_code != 0
    assert service.load_engagement(program.engagement_id).safe_experiment_secret_refs == {
        template.template_id: reference
    }


def test_workflow_cli_rejects_undeclared_accounts(service, lab_engagement, monkeypatch) -> None:
    program = lab_engagement.model_copy(
        update={
            "selected_mode": EngagementMode.PROGRAM,
            "testing_accounts_secret_refs": {"alice": "keyring://fixture/alice"},
        }
    )
    service.save_engagement(program)
    template = _session_template(program.root_targets[0].uri)
    payload = template.model_dump(mode="python")
    payload["negative_steps"][0]["action"]["account_alias"] = "bob"
    raw = SafeWorkflowExperimentTemplate.model_validate(payload).model_dump_json()
    monkeypatch.setattr("budobugs.cli.app._service", lambda: service)
    monkeypatch.setenv("BUDO_WORKFLOW_TEMPLATE", raw)

    result = CliRunner().invoke(
        app,
        [
            "engagement",
            "experiment-set",
            program.engagement_id,
            "--spec-env",
            "BUDO_WORKFLOW_TEMPLATE",
            "--json",
        ],
    )
    assert result.exit_code != 0
    assert "undeclared self-owned accounts" in result.output
