"""Recoverable phase DAG and candidate transition rules."""

from __future__ import annotations

from datetime import UTC, datetime

from budobugs.models import CandidateStatus, PhaseName, PhaseRecord, Run

PHASE_ORDER: tuple[PhaseName, ...] = tuple(PhaseName)

_CANDIDATE_TRANSITIONS: dict[CandidateStatus, set[CandidateStatus]] = {
    CandidateStatus.SIGNAL: {
        CandidateStatus.HYPOTHESIS,
        CandidateStatus.KILL,
        CandidateStatus.OUT_OF_TASK,
    },
    CandidateStatus.HYPOTHESIS: {
        CandidateStatus.TEST_PLANNED,
        CandidateStatus.THEORETICAL,
        CandidateStatus.KILL,
        CandidateStatus.OUT_OF_TASK,
    },
    CandidateStatus.TEST_PLANNED: {
        CandidateStatus.VALIDATING,
        CandidateStatus.HOLD,
        CandidateStatus.KILL,
    },
    CandidateStatus.VALIDATING: {
        CandidateStatus.CONFIRMED,
        CandidateStatus.REFUTED,
        CandidateStatus.HOLD,
        CandidateStatus.KILL,
    },
    CandidateStatus.THEORETICAL: {
        CandidateStatus.TEST_PLANNED,
        CandidateStatus.HOLD,
        CandidateStatus.KILL,
    },
    CandidateStatus.CONFIRMED: {
        CandidateStatus.READY_FOR_HUMAN_REVIEW,
        CandidateStatus.HOLD,
        CandidateStatus.KILL,
    },
    CandidateStatus.REFUTED: {CandidateStatus.ARCHIVED},
    CandidateStatus.HOLD: {
        CandidateStatus.TEST_PLANNED,
        CandidateStatus.VALIDATING,
        CandidateStatus.KILL,
    },
    CandidateStatus.KILL: {CandidateStatus.ARCHIVED},
    CandidateStatus.OUT_OF_TASK: {CandidateStatus.ARCHIVED},
    CandidateStatus.READY_FOR_HUMAN_REVIEW: {CandidateStatus.ARCHIVED},
    CandidateStatus.ARCHIVED: set(),
}


class InvalidTransition(ValueError):
    """Raised when code attempts to bypass a lifecycle gate."""


def transition_candidate(current: CandidateStatus, desired: CandidateStatus) -> CandidateStatus:
    if desired not in _CANDIDATE_TRANSITIONS[current]:
        raise InvalidTransition(f"candidate transition {current} -> {desired} is not allowed")
    return desired


def initialize_phases() -> list[PhaseRecord]:
    return [PhaseRecord(name=name) for name in PHASE_ORDER]


def start_phase(run: Run, phase: PhaseName) -> Run:
    index = PHASE_ORDER.index(phase)
    if index > 0:
        previous = next(item for item in run.phases if item.name is PHASE_ORDER[index - 1])
        if previous.status != "completed":
            raise InvalidTransition(f"previous phase {previous.name} is not complete")
    record = next(item for item in run.phases if item.name is phase)
    if record.status == "completed":
        return run
    record.status = "running"
    record.attempt += 1
    record.started_at = datetime.now(UTC)
    record.error = None
    run.current_phase = phase
    run.status = "running"
    run.updated_at = datetime.now(UTC)
    return run


def complete_phase(run: Run, phase: PhaseName, artifacts: list[str], receipt_id: str) -> Run:
    record = next(item for item in run.phases if item.name is phase)
    if record.status != "running":
        raise InvalidTransition(f"phase {phase} is not running")
    record.status = "completed"
    record.completed_at = datetime.now(UTC)
    record.output_artifacts = artifacts
    record.receipt_id = receipt_id
    if phase is PHASE_ORDER[-1]:
        run.status = "completed"
    run.updated_at = datetime.now(UTC)
    return run


def block_phase(run: Run, phase: PhaseName, reason: str) -> Run:
    record = next(item for item in run.phases if item.name is phase)
    record.status = "blocked"
    record.error = reason
    record.completed_at = datetime.now(UTC)
    run.status = "blocked"
    run.updated_at = datetime.now(UTC)
    return run
