---
name: lab-evaluation
description: Run and assess the localhost/Docker BudoBugs lab E2E, including one confirmed fixture issue, one killed false candidate, evidence, report, resume, and cleanup.
---

# Lab Evaluation

1. Prove all targets are loopback, private or Docker-internal and labeled TEST FIXTURE.
2. Start the pinned lab and record actual service health; native fallback is partial and must not be called full Docker PASS.
3. Create and authorize a lab engagement, capture normal traffic, build object/invariant models, validate one known issue and refute one public-design candidate.
4. Verify evidence hashes, report redaction, interruption/resume and teardown.
5. Return per-check PASS/FAIL/BLOCKED with logs; never contact an external target.

The 14-point E2E receipt is in [workflow.md](references/workflow.md). Validate inputs with `python scripts/validate_input.py <json>`; [example.json](assets/example.json) uses `127.0.0.1` only.
