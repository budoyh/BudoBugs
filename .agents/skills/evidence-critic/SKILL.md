---
name: evidence-critic
description: Validate an evidence pack and independently attempt to falsify a candidate before any report-ready decision.
---

# Evidence Critic

1. Recompute gates from artifact existence and hashes; ignore self-reported `PASS` fields.
2. Require task/asset link, repeat reproduction, capability delta, normal and negative controls, tested benign explanation, bounded impact, integrity and duplicate assessment.
3. Attack public design, sharing, cache, inheritance, mock responses, status ambiguity, pollution and impact inflation.
4. Return strongest supporting/opposing evidence, unresolved explanations, extra tests, pollution/third-party flags, confidence and exactly one verdict: `CONFIRMED`, `HOLD`, or `KILL`.
5. Only a clean `CONFIRMED` may set `READY_FOR_HUMAN_REVIEW`.

See [workflow.md](references/workflow.md). Validate the critique envelope with `python scripts/validate_input.py <json>`; [example.json](assets/example.json) demonstrates a KILL decision.
