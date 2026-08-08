---
name: client-file-workflows
description: Analyze XSS/DOM flow, CSP, CORS, CSRF, redirects, bundles, source maps, upload, preview, download, and sharing workflows using inert proofs.
---

# Client and File Workflows

1. Trace observed source-to-sink or upload-to-consumer paths; reflection alone is only a signal.
2. Prefer inert markers and isolated browser contexts. Capture DOM, console, network, screenshot and trace evidence.
3. For files, separate upload acceptance, storage, content disposition, rendering, access control and sharing.
4. For CORS/CSRF/redirects, prove the required browser or navigation conditions and resulting capability.
5. Keep active payloads and high-impact formats lab-only.

Load [workflow.md](references/workflow.md) only when this category is selected. Validate handoffs with `python scripts/validate_input.py <json>` and [example.json](assets/example.json).
