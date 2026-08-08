# Security Policy

## Supported state

The `main` source tree carries third-party notices, a CycloneDX SBOM, production license inventories,
manifest-digest checks, raw security scans, a source-bound fixture VEX review, provenance, and CI release gates.
No long-term support window or response-time SLA is implied until a tagged release explicitly states one. When
reporting a defect, identify the exact commit rather than assuming every checkout has identical evidence.

## Reporting a vulnerability

Do not publish an undisclosed BudoBugs vulnerability, secret, private traffic capture, or lab escape in a public issue. Report it privately to the repository owner through the repository's security-advisory channel when available; otherwise use the contact method published by the repository owner. Include affected revision, minimal reproduction, impact, and whether credentials or third-party data were exposed.

Do not use BudoBugs to test third-party systems while reporting a BudoBugs defect. A report that includes live credentials must be revoked/rotated before sharing whenever possible.

## Incident classes

- Secret, token, raw traffic, or unpublished-finding exposure: revoke access first, preserve only sanitized evidence, then report.
- Supply-chain or image concern: report the artifact URL, tag/digest, source, and verification result; do not replace it with an unpinned image.
- Container escape, Docker socket exposure, or unintended external request: stop the lab, retain minimal local logs, and report as high priority.

No response-time commitment is made by this document. Users remain responsible for target authorization and for their own disclosure obligations.
