---
name: butian-report
description: Generate a Chinese Butian/SRC-style Markdown and HTML draft from a submission-ready, critic-confirmed structured finding.
---

# Butian Report

1. Refuse input unless status is `READY_FOR_HUMAN_REVIEW`, reportability is `submission-ready`, and critic verdict is `CONFIRMED`.
2. Use only finding fields and cited artifacts; never invent requests, impact, screenshots, CVSS or affected scope.
3. Explain target, prerequisites, invariant, steps, requests/responses, controls, capability delta, conservative impact, cleanup, severity, duplicate risk and remediation.
4. Run a second secret/PII scan and emit an evidence manifest plus human review checklist.
5. Leave submission to the user.

Report mapping is in [workflow.md](references/workflow.md). Validate input with `python scripts/validate_input.py <json>`; [example.json](assets/example.json) is a redacted report stub.
