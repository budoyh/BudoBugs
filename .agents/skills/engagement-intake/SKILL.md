---
name: engagement-intake
description: Create or validate engagement.yaml when a user supplies an authorized SRC, lab, or source-review task and its target scope.
---

# Engagement Intake

1. Classify the task as `lab`, `program`, or `source`.
2. Record platform, vendor, human authorization attestation, exact roots, optional subdomains, exclusions, account secret references, rate profile and notes.
3. Store only aliases and secret references; use keyring for secret values.
4. Validate URLs/paths and mode boundaries. Do not infer affiliated domains.
5. Leave status `draft`; require the separate human `authorize` command.

Input and output are defined in [workflow.md](references/workflow.md). Run `python scripts/validate_input.py <json>` before emitting a new engagement. Use [example.json](assets/example.json) as a safe local fixture example.
