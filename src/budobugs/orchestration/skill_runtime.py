"""Load project Skills as enforced planning contracts in the hunt loop."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from budobugs.models import ActionKind, ActionProposal, AgentRole


@dataclass(frozen=True, slots=True)
class SkillContract:
    name: str
    instruction: str
    workflow: str
    path: str


class SkillRuntime:
    """Bind roles to reviewed Skills and reject actions outside each Skill's capability."""

    ROLE_SKILLS: dict[AgentRole, tuple[str, ...]] = {
        AgentRole.COORDINATOR: ("budobugs-controller", "engagement-intake"),
        AgentRole.BROWSER_EXPLORER: ("web-attack-surface", "client-file-workflows"),
        AgentRole.TRAFFIC_MODELER: ("traffic-object-model",),
        AgentRole.AUTHORIZATION_SPECIALIST: ("authz-business-logic", "hypothesis-and-validation"),
        AgentRole.BUSINESS_LOGIC_SPECIALIST: ("authz-business-logic", "hypothesis-and-validation"),
        AgentRole.API_AUTH_SPECIALIST: ("api-auth-session", "hypothesis-and-validation"),
        AgentRole.WEB_CLIENT_SPECIALIST: ("client-file-workflows", "hypothesis-and-validation"),
        AgentRole.EVIDENCE_VALIDATOR: ("evidence-critic", "hypothesis-and-validation", "lab-evaluation"),
        AgentRole.ADVERSARIAL_CRITIC: ("evidence-critic",),
        AgentRole.RECON_RESEARCHER: ("passive-recon", "tool-operator"),
        AgentRole.SOURCE_REVIEWER: ("source-secret-supply-chain", "tool-operator"),
        AgentRole.REPORT_WRITER: ("butian-report",),
    }
    SKILL_ACTIONS: dict[str, set[ActionKind]] = {
        "budobugs-controller": {ActionKind.PROXY_SEARCH, ActionKind.EVIDENCE_REVIEW, ActionKind.FINISH},
        "engagement-intake": {ActionKind.EVIDENCE_REVIEW},
        "web-attack-surface": {
            ActionKind.BROWSER_EXPLORE,
            ActionKind.BROWSER_NAVIGATE,
            ActionKind.BROWSER_FORM,
            ActionKind.PROXY_SEARCH,
        },
        "client-file-workflows": {
            ActionKind.BROWSER_EXPLORE,
            ActionKind.BROWSER_NAVIGATE,
            ActionKind.BROWSER_FORM,
            ActionKind.HTTP_REQUEST,
            ActionKind.PROXY_REPLAY,
            ActionKind.VALIDATOR_RUN,
            ActionKind.EVIDENCE_REVIEW,
        },
        "traffic-object-model": {ActionKind.PROXY_SEARCH, ActionKind.TRAFFIC_MODEL},
        "authz-business-logic": {
            ActionKind.HTTP_REQUEST,
            ActionKind.PROXY_REPLAY,
            ActionKind.VALIDATOR_RUN,
            ActionKind.EVIDENCE_REVIEW,
        },
        "hypothesis-and-validation": {
            ActionKind.HTTP_REQUEST,
            ActionKind.PROXY_REPLAY,
            ActionKind.VALIDATOR_RUN,
            ActionKind.EVIDENCE_REVIEW,
        },
        "api-auth-session": {
            ActionKind.HTTP_REQUEST,
            ActionKind.PROXY_REPLAY,
            ActionKind.VALIDATOR_RUN,
            ActionKind.EVIDENCE_REVIEW,
        },
        "evidence-critic": {ActionKind.EVIDENCE_REVIEW, ActionKind.VALIDATOR_RUN, ActionKind.FINISH},
        "passive-recon": {ActionKind.PROXY_SEARCH, ActionKind.TOOL_TASK},
        "source-secret-supply-chain": {ActionKind.TOOL_TASK, ActionKind.EVIDENCE_REVIEW},
        "tool-operator": {ActionKind.TOOL_TASK},
        "lab-evaluation": {ActionKind.VALIDATOR_RUN},
        "butian-report": {ActionKind.EVIDENCE_REVIEW, ActionKind.FINISH},
    }

    def __init__(self, root: Path) -> None:
        self.root = (root / ".agents" / "skills").resolve()
        self._cache: dict[str, SkillContract] = {}

    def load(self, name: str) -> SkillContract:
        if name in self._cache:
            return self._cache[name]
        path = (self.root / name / "SKILL.md").resolve()
        if not path.is_relative_to(self.root) or not path.is_file() or path.is_symlink():
            raise FileNotFoundError(f"Skill is unavailable: {name}")
        instruction = path.read_text(encoding="utf-8")
        match = re.search(r"(?m)^name:\s*([^\r\n]+)$", instruction)
        if match is None or match.group(1).strip() != name:
            raise ValueError(f"Skill identity mismatch: {name}")
        workflow_path = path.parent / "references" / "workflow.md"
        workflow = workflow_path.read_text(encoding="utf-8") if workflow_path.is_file() else ""
        contract = SkillContract(name=name, instruction=instruction, workflow=workflow, path=str(path))
        self._cache[name] = contract
        return contract

    def default_for(self, role: AgentRole) -> str:
        return self.ROLE_SKILLS[role][0]

    def validate(self, proposal: ActionProposal) -> SkillContract:
        allowed_skills = self.ROLE_SKILLS.get(proposal.agent_role, ())
        if proposal.skill_name not in allowed_skills:
            raise PermissionError(f"role {proposal.agent_role.value} cannot invoke Skill {proposal.skill_name}")
        allowed_actions = self.SKILL_ACTIONS.get(proposal.skill_name, set())
        if proposal.kind not in allowed_actions:
            raise PermissionError(f"Skill {proposal.skill_name} cannot propose {proposal.kind.value}")
        return self.load(proposal.skill_name)
