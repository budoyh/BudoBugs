---
name: hypothesis-and-validation
description: Turn observed signals into security-invariant hypotheses and execute safe single-variable validation with repeat, negative, and refutation controls.
---

# Hypothesis and Validation

1. Express one invariant, asset, trust boundary, enforcement point and falsifiable violation signal.
2. Build a mode-allowed plan with exact target, account alias, mutation, expected control and cleanup.
3. Establish baseline, change one variable, repeat the result, run negative/normal controls and test the strongest benign explanation.
4. Record failed tests as evidence. Do not interpret HTTP 200, reflection or scanner labels as proof by themselves.
5. Emit a structured candidate state and capability delta for mechanical gates.

The A-H precritic contract is in [workflow.md](references/workflow.md). Run `python scripts/validate_input.py <json>`; [example.json](assets/example.json) shows a two-account plan.
