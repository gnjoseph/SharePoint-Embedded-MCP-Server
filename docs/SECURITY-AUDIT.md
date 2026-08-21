# Weekly repository security audit

This repository runs a scheduled security audit
([`.github/workflows/security-audit.yml`](../.github/workflows/security-audit.yml)) every Monday,
plus on demand via **Actions → Weekly security audit → Run workflow**.

The audit has two layers:

| Layer | Jobs | Gating |
| --- | --- | --- |
| **Deterministic** | CodeQL, dependency audit, secret scan, action pinning | Failures fail the run |
| **Model-assisted** | `model-audit` (real) / `model-audit-dry-run` (synthetic) | Advisory only, never gating |

> [!IMPORTANT]
> The model-assisted layer ships **disabled**. Until an administrator completes the
> [activation checklist](#activating-the-model-assisted-layer), the run summary reports
> `AI NOT_CONFIGURED`. It never reports a pass it did not perform.

## What runs

### Deterministic jobs

| Job | What it does | Notes |
| --- | --- | --- |
| `validate-inputs` | Normalizes and validates the manual inputs | Target must be a 40-hex SHA reachable from `main`; scope and model come from allowlists |
| `codeql` | CodeQL `security-extended` for JavaScript/TypeScript | Uploads SARIF to code scanning (`security-events: write`) |
| `dependency-audit` | `npm audit --audit-level=high` | The raw JSON is reduced to sanitized counts + advisory URLs before it ever leaves the runner |
| `secret-scan` | Gitleaks **CLI**, downloaded at a pinned version and SHA256-verified | Report is reduced to file/rule/line — never the matched secret |
| `action-pins` | Fails if any workflow uses a mutable action ref | Enforces 40-hex commit pinning across `.github/workflows` |
| `summary` | Aggregates results into the job summary | Fails the run if any deterministic job did not succeed |

Dependency installation in the audit path uses `npm ci --ignore-scripts`, so no repository
lifecycle script executes while untrusted content is being collected.

### Model-assisted job

`model-audit` sends a **bounded, allowlisted corpus** to a model and validates every finding
before anything is retained:

- Corpus caps: 40 files, 96 KiB per file, 512 KiB total (`scripts/security-audit/lib/constants.mjs`).
- Every file is wrapped in explicit untrusted-content delimiters; the system prompt states the
  file bodies are data, never instructions.
- The job is tool-less: no MCP servers, no shell, no repository write. `copilot-allow-tools`
  is deliberately left unset (empty means no tools).
- Model output is **never** interpolated into a shell command — only file paths are passed
  through `env:`.
- Findings are rejected outright if they carry tokens, GUIDs, absolute paths, or weaponized
  payloads; e-mail addresses, query strings, and long hex blobs are redacted.
- Findings must anchor to a corpus file and a line inside that file, and must cite a control
  from [`SECURITY-CONTROLS.md`](SECURITY-CONTROLS.md) (or the literal `UNMAPPED`).

Nothing from the model layer is published: no issues, no comments, no raw-finding artifacts.
Sanitized results go to code scanning under the restricted `security-events: write` permission.

## Running it locally

No credentials and no runtime dependencies are needed for the offline path.

```bash
# End-to-end synthetic run: corpus → validation → redaction → SARIF
npm run security:audit:dry-run

# The script test suite (schema, redaction, injection, workflow invariants)
npm run security:audit:test

# Fail if any workflow action is not pinned to a commit SHA
npm run security:audit:pins
```

`security:audit:dry-run` writes to `.security-audit/dry-run/` (git-ignored):

| File | Contents |
| --- | --- |
| `corpus-manifest.json` | Files collected, byte/line counts, skipped files |
| `model-report.json` | Accepted findings, rejected findings with reasons, redaction count |
| `model-report.sarif` | SARIF 2.1.0, flagged `synthetic` |

Individual stages can be run directly — see
[`scripts/security-audit/README.md`](../scripts/security-audit/README.md).

## Triaging results

1. **Deterministic findings are authoritative.** CodeQL and dependency findings appear in the
   **Security** tab. Secret-scan hits are reported as file + rule + line; open the file at that
   line to confirm, then rotate the credential *before* removing it from the source.
2. **Model findings are leads, not verdicts.** Each accepted finding carries a confidence and a
   control anchor. Confirm the code path by hand before filing anything.
3. **Check the rejected list.** A high rejection count usually means the model drifted off the
   corpus or attempted to smuggle content — treat it as a signal about the run, not about the code.
4. **Report real vulnerabilities privately** per [`SECURITY.md`](../SECURITY.md). Never open a
   public issue for an unfixed vulnerability.

## Activating the model-assisted layer

These steps require repository-administrator rights and are deliberately **not** automated.

1. Create the `security-audit-ai` environment and protect it: required reviewers, and a
   deployment-branch rule limited to `main`.
2. Add a least-scope `COPILOT_PAT` **environment** secret (Copilot Requests only — no `repo`,
   no `workflow`, no `write:*`), or wire an approved Foundry OIDC configuration instead.
3. Set the repository variable `SECURITY_AUDIT_AI_ENABLED` to `true`. The job stays skipped
   until this exists, so the protected environment is never implicitly created.
4. Validate that the configured model id is accepted by the provider before the first real run;
   the default (`claude-opus-5`) is an allowlist entry that has not been exercised end to end.

Related administrative follow-ups (independent of the model layer):

- Enable **native secret scanning** and **push protection** on the repository.
- Add the deterministic jobs as **required status checks** in the organization ruleset.
  Do **not** make the model job a required check — it is advisory and non-deterministic.

## Design constraints

- The workflow has **no** `pull_request` or `pull_request_target` trigger, so untrusted forks
  can never reach the audit path or its secrets.
- Workflow-level permissions are `{}` (deny-all); each job re-grants only what it needs.
- Every action is pinned to a 40-hex commit SHA with the version in a trailing comment, and
  `action-pins` fails the run if that ever regresses.
- Checkouts use `persist-credentials: false`.
- Every `continue-on-error: true` step is paired with an explicit failure gate that re-raises
  the failure after the raw report has been sanitized — a test enforces this invariant.
