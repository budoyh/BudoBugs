---
name: web-attack-surface
description: Map authorized web and API routes, forms, business flows, parameters, schemas, and state transitions from captured normal traffic.
---

# Web Attack Surface

1. Use redacted HAR/proxy/Playwright exchanges from normal user flows.
2. Cluster method, host and path templates; identify parameters, content types, schemas, forms and client routes.
3. Mark dynamic IDs, state-changing endpoints and third-party calls; retain source exchange IDs.
4. Record gaps and uncertainty. Do not infer reachability or authorization failures from route names alone.
5. Return endpoint families and workflow edges for object and invariant modeling.

Load [workflow.md](references/workflow.md) for schema rules. Use `python scripts/validate_input.py <json>` and [example.json](assets/example.json).
