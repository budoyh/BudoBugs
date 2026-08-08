---
name: authz-business-logic
description: Investigate IDOR/BOLA, BFLA, cross-role, cross-tenant, file, sharing, invitation, and workflow-invariant candidates with two self-owned accounts.
---

# Authorization and Business Logic

1. State the protected asset, trust boundary, enforcement point and invariant.
2. Establish the normal owner flow first. Change one account, role, tenant, object ID or state transition at a time.
3. Use only self-owned accounts and minimum proof data. Concurrency is lab-only unless explicitly allowed.
4. Record repeat reproduction, denial/public controls, cleanup and conservative capability delta.
5. Route unresolved ownership, inherited sharing or public-design ambiguity to `HOLD`, never to a report.

Read category and control patterns in [workflow.md](references/workflow.md). Validate plans with `python scripts/validate_input.py <json>` and compare [example.json](assets/example.json).
