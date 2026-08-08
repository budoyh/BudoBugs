---
name: source-secret-supply-chain
description: Review an authorized local source root for reachable security flaws, secrets, dependencies, CI/CD, containers, and deployment configuration.
---

# Source, Secret and Supply Chain

1. Enforce the declared source root and never follow paths outside it.
2. Use registered Semgrep, Gitleaks, Trivy, OSV, Syft or Grype wrappers; preserve receipts and exact file references.
3. Redact secret values immediately; report type, location and reachability, not the value.
4. Trace source to sink, authorization enforcement and deployment reachability. Static matches remain signals until validated.
5. Separate vulnerable dependency presence from a reachable vulnerable execution path.

Read [workflow.md](references/workflow.md) for evidence tiers. Validate the request with `python scripts/validate_input.py <json>`; [example.json](assets/example.json) contains no secret.
