# BudoBugs

**Budo Autonomous Bug Bounty OS**

BudoBugs is a local-first, authorization-bound vulnerability-research system for approved SRC programs,
white-box source review, and isolated labs. One explicit engagement authorization defines the targets,
accounts, exclusions, mode, and rate profile. The system then runs a resumable workflow for surface modeling,
low-impact validation, negative controls, independent criticism, evidence packaging, and report drafting. It
never submits a report automatically.

The primary executable documentation is the [Chinese README](README.md). Key commands are:

```bash
./scripts/bootstrap.sh
uv run playwright install chromium
uv run budo tools install --profile core --json
uv run budo doctor --json
uv run budo lab up --native-only --json
uv run budo engagement new --id first-lab --mode lab --target http://127.0.0.1:8765 --vendor local-fixture --attestation "I own and authorize this isolated local fixture."
uv run budo engagement validate first-lab --json
uv run budo engagement authorize first-lab --json
uv run budo hunt first-lab --json
uv run budo lab down --json
```

The three enforced modes are `lab`, `program`, and `source`. Program mode blocks high-mutation,
high-resource, and autonomous lab-ai execution; lab mode rejects public network targets; source mode cannot
escape its declared local roots. Exact-origin scope checks, typed no-shell wrappers, redaction, immutable event
logs, evidence gates, and an independent critic apply before a report can become ready for human review.

Docker Compose includes the BudoBugs two-account fixture, Juice Shop, WebGoat, crAPI, and ZAP. External images
are pinned by manifest digest, host ports bind only to loopback, and the lab network is internal. Caido uses the
pinned official SDK bridge; Burp uses the user-installed official MCP BApp; ZAP 2.17.0 supports daemon history,
replay, export, and a fixed Automation Framework job. Missing GUI credentials or commercial licenses are
reported explicitly and do not become false PASS results.

Hunts are deterministic by default (`agent_mode=disabled`). Run
`budo hunt <id> --agent-mode codex --dry-run --json` to inspect request and token ceilings before enabling Codex
advisory. An advisory may provide an exact candidate permutation or veto a deterministic confirmation; it cannot
promote a candidate that failed the local evidence gates. Per-phase and model cost receipts remain queryable from
local state, while provider billing is never guessed. Task-specific JSON Schemas constrain Codex output, and an
identical successful advisory within one run is served from an input-bound cache without another model charge.

Release evidence under `release/` includes a CycloneDX source SBOM, raw scanner output, a source-bound OpenVEX
review for the fixture image, production Python and Node license inventories, and provenance. CI runs lint,
type checking, unit/integration/security tests, at least 85% branch coverage over the defined core, native E2E,
Docker/ZAP integration, secret/SAST/dependency/container scans, Skill validation, and clean-wheel smoke tests.

Before any non-fixture use, read [Responsible Use](docs/operations/RESPONSIBLE_USE.md),
[Data Handling](docs/operations/DATA_HANDLING.md), [Threat Model](docs/architecture/THREAT_MODEL.md),
[Manual Setup](docs/MANUAL_ONCE.md), and [Third-Party Notices](THIRD_PARTY_NOTICES.md). A human remains
responsible for target authorization, provider terms and cost, final evidence review, disclosure, and submission.
