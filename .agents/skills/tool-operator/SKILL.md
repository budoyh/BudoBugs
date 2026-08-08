---
name: tool-operator
description: Select, health-check, and run a registered BudoBugs tool when an authorized task needs deterministic external tooling.
---

# Tool Operator

1. Resolve the tool only from `tools/registry`; never compose an arbitrary shell command.
2. Check installed version, health, mode, mutation/resource risk, target scope, required secrets and concurrency.
3. Let the wrapper inject the engagement target and use a no-shell argument vector.
4. Capture raw private stdout/stderr, redacted public output, normalized JSON, exit/timeout/retry state and execution receipt.
5. Report `NEEDS_RUNTIME`, `NEEDS_CREDENTIAL`, `NEEDS_LICENSE`, `UNSUPPORTED` or failure honestly.

See [workflow.md](references/workflow.md) for the request/receipt schema. Validate requests with `python scripts/validate_input.py <json>` and [example.json](assets/example.json).
