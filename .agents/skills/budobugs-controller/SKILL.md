---
name: budobugs-controller
description: Coordinate a complete BudoBugs engagement when the user asks to start, resume, status, or plan an authorized hunt across multiple phases.
---

# BudoBugs Controller

Use this as the single entry point for a multi-phase task.

1. Read and schema-validate `engagement.yaml`; stop before network work unless authorization is `authorized`.
2. Load the mode policy and model route. Never expand targets beyond declared roots.
3. Build the fixed phase DAG from `INIT` through `HUMAN_REVIEW_READY`; reuse completed receipt-backed phases on resume.
4. Delegate only bounded tasks. Keep raw output in run artifacts and return artifact references.
5. End candidates at `CONFIRMED`, `HOLD`, `KILL`, or `OUT_OF_TASK`; only critic-confirmed artifacts may reach reporting.
6. Report actual cost, failures and unmet runtime/credential/license gates.

Input: `engagement_id`, `requested_goal`, optional `resume_run_id`, route profile. Output: run plan, phase states, artifact refs, budget state, candidate decisions.

Read [workflow.md](references/workflow.md) for the phase contract. Validate structured handoffs with `python scripts/validate_input.py <json>`. [example.json](assets/example.json) shows the contract.
