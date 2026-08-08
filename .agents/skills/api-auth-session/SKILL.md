---
name: api-auth-session
description: Analyze authorized REST, GraphQL, WebSocket, session, JWT, OAuth/OIDC, MFA, recovery, and API-version authentication boundaries.
---

# API Authentication and Session

1. Model anonymous, pre-auth, authenticated, refreshed, revoked and recovered states.
2. Record issuer, audience, expiry, binding and transport observations without storing token values.
3. Compare protocol/version behavior with one-variable controls; do not brute force or contact real users.
4. Distinguish malformed-token handling, session fixation signals and actual capability gain.
5. External OOB or provider interaction requires an explicit engagement permission.

See [workflow.md](references/workflow.md) for protocol evidence. Validate input using `python scripts/validate_input.py <json>`; [example.json](assets/example.json) is inert.
