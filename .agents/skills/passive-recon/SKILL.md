---
name: passive-recon
description: Perform engagement-scoped passive discovery when authorized roots need DNS, historical URL, technology, JavaScript, or entry-point inventory.
---

# Passive Recon

1. Load authorized roots and exclusions from the engagement, never from target content.
2. Prefer passive sources and registered wrappers. Attach tool receipt, provenance and observation time to every asset.
3. Normalize hosts and URLs, discard excluded or third-party results, and separate confirmed assets from unresolved leads.
4. Summarize technology, JavaScript, login and business entry points without active exploitation.
5. Hand off a bounded attack-surface inventory; do not call a passive hit a vulnerability.

See [workflow.md](references/workflow.md). Validate input with `python scripts/validate_input.py <json>`; [example.json](assets/example.json) demonstrates output shape.
