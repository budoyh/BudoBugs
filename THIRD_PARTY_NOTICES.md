# Third-Party Notices and Distribution Boundary

Release-evidence snapshot: 2026-08-09. This document records engineering and distribution boundaries; it is
not legal advice and does not replace an upstream license. BudoBugs source is Apache-2.0. Third-party packages,
tools, browsers, commercial applications, vulnerability databases, and lab images keep their own licenses and
terms.

## Packaged production dependencies

Python dependencies are transitively locked by `uv.lock`; Node dependencies are locked by `pnpm-lock.yaml`.
Machine-readable production inventories are committed at:

- `release/licenses/python-production.json`: 57 package identities, 0 unresolved licenses.
- `release/licenses/node-production.json`: 16 package identities, 0 unresolved licenses; the complete
  cross-platform `@openai/codex` optional package family is included.
- `release/licenses/summary.json`: counts and the boundary statement checked by the release verifier.
- `release/sbom/source.cdx.json`: CycloneDX source SBOM generated from the release tree.

The release verifier independently reconstructs both production dependency closures from the lockfiles and
rejects missing, extra, version-mismatched, duplicate, or unresolved license records. The generated inventory
also records installed notice/license file locations where Python package metadata exposes them.

Important direct boundaries are:

| Family | Upstream license boundary | BudoBugs handling |
|---|---|---|
| FastAPI, Pydantic, httpx, Jinja2, keyring, MCP SDK, Rich, SQLAlchemy, Textual, Typer, Uvicorn | Individually recorded in the Python production inventory | Locked runtime packages; retain the applicable upstream notices when redistributing. |
| Playwright | Apache-2.0 | Locked Python dependency; its downloaded browser is separate. |
| Chromium | Multi-license | Downloaded and managed by Playwright in user-local storage; not repackaged in the BudoBugs wheel/source bundle. Review Chromium notices before redistributing a browser artifact. |
| `@caido/sdk-client` | MIT | Locked optional localhost integration; Caido product/service terms remain separate. |
| `@openai/codex-sdk` and `@openai/codex` platform packages | Apache-2.0 | Locked Node integration; provider/API terms remain separate from the package license. |

## External tools and applications

Registry entries and installers do not bundle external tools into the BudoBugs source or wheel. Fixed versions,
upstream URLs, commits, licenses, checksums, profiles, health checks, and execution boundaries are recorded in
`tools/registry/`, `tools/lock/tool-lock.yaml`, and the
[license matrix](docs/research/LICENSE_MATRIX.md). User-local binaries must retain their upstream notices.

Key process boundaries:

- Arjun is AGPL-3.0 and runs from an isolated `uv tool` environment.
- Semgrep CE is LGPL-2.1 and runs as an independent CLI/WSL tool.
- Burp MCP is GPL-3.0 and runs inside a user-installed Burp application; BudoBugs only uses its localhost MCP
  protocol and does not copy or redistribute it.
- Shannon is AGPL-3.0 and remains an optional external lab-only process.
- Caido is connected through its official MIT SDK; the community MCP implementation is research input only.
- Components whose upstream license is `NOASSERTION` or audit-required are disabled from automatic install and
  are not copied.

## Runtime lab images

Every external Compose image is pinned as `tag@sha256` in `docker/compose.yaml`; the release verifier rejects an
unpinned external image. Host publishing is loopback-only, the `lab` network is internal, containers receive no
Docker socket or home-directory mount, and capabilities are dropped unless a documented minimal exception is
needed.

These images are pulled at runtime for isolated training and are not embedded in the BudoBugs wheel or source
archive:

| Image family | Upstream/root project boundary | Distribution note |
|---|---|---|
| OWASP Juice Shop 20.1.1 | MIT project source; layers/dependencies separate | Runtime lab only; retain image and dependency notices if independently redistributed. |
| OWASP WebGoat 2025.3 | GPL-2.0-or-later project source; layers separate | Runtime lab only; independent redistribution must satisfy GPL/source obligations. |
| OWASP crAPI 1.1.6 components | Apache-2.0 root project; MailHog/layers separate | Runtime lab only; exact component digests are in Compose. |
| Alpine, PostgreSQL, MongoDB, Chroma | Multi-component / PostgreSQL License / SSPL-1.0 server / Apache-2.0 | Supporting runtime images; independent redistribution requires per-layer review. |
| OWASP ZAP 2.17.0 | Apache-2.0 project/add-ons; layers separate | Fixed-digest runtime tool; BudoBugs does not relicense ZAP or its add-ons. |

`budobugs/fixture:local` and `budobugs/loopback-proxy:local` are built from this Apache-2.0 repository. The
fixture uses a fixed-digest Python/Alpine base and an exact hashed Python requirements lock. Trivy found zero
high/critical vulnerabilities, secrets, or high/critical misconfigurations in the release fixture image. Raw
Grype reported 12 high/critical package records; every record is preserved in
`release/scans/grype-fixture-raw.json` and matched one-for-one to the source-bound reachability review and
OpenVEX `not_affected` statements. The final report contains no unexplained blocking severe record. This VEX
decision applies only to the exact fixture manifest and reviewed `fixture_app.py`; any image/source drift
invalidates it.

## Lab-AI references

PentestGPT, Strix, Shannon, CAI, HexStrike AI, VulneraMCP, and Kali MCP are optional lab-only external processes,
not BudoBugs release contents. Missing credentials, runtime, or licenses remain explicit non-PASS states.

HexStrike AI is the one locally executed lab-ai integration in this release evidence. The adapter checks out the
reviewed MIT commit `d689933ff579d839c676c82b231f8e98326c5f04`, synchronizes an exact dependency lock,
patches the control plane to `127.0.0.1`, rejects non-loopback validation targets, and calls only the bounded
`intelligence/analyze-target` endpoint. The real localhost validation receipt is preserved at
`release/validation/hexstrike-localhost.json`; it records that the arbitrary-command endpoint was not used.

## Databases, rules, services, and user data

Scanner vulnerability databases, Semgrep/nuclei rules, model APIs, OOB services, proxy traffic, SRC accounts,
and target content are separate data/service inputs. A package license does not grant target authorization or
waive provider terms, data-residency requirements, disclosure rules, or commercial licenses. Real secrets,
traffic, findings, and reports are excluded from Git and must not be included in a public distribution.
