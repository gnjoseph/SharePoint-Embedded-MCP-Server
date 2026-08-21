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
| `validate-inputs` | Normalizes and validates the manual inputs | Target must be a 40-hex SHA reachable from `main`; scope and model come from allowlists. Scheduled runs supply no ref, so the current `origin/main` tip is resolved to a full SHA and then validated by the same rules |
| `codeql` | CodeQL `security-extended` for JavaScript/TypeScript | Uploads SARIF to code scanning (`security-events: write`) |
| `dependency-audit` | `npm audit --audit-level=high` | The raw JSON is reduced to sanitized counts + advisory URLs before it ever leaves the runner |
| `secret-scan` | Gitleaks **CLI**, downloaded at a pinned version and SHA256-verified | Report is reduced to file/rule/line — never the matched secret |
| `action-pins` | Fails if any workflow uses a mutable action ref | Enforces 40-hex commit pinning recursively across `.github/workflows` **and** every composite `action.yml`/`action.yaml` in the repository |
| `summary` | Aggregates results into the job summary | Fails the run if any deterministic job did not succeed |

Dependency installation in the audit path uses `npm ci --ignore-scripts`, so no repository
lifecycle script executes while untrusted content is being collected.

### Model-assisted job

`model-audit` sends a **bounded, allowlisted corpus** to a model and validates every finding
before anything is retained:

- Corpus caps: 40 files, 96 KiB per file, 512 KiB total (`scripts/security-audit/lib/constants.mjs`).
- Instruction surfaces (`AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md`, `.github/instructions/`,
  `.github/agents/`, `.copilot/`, `Skills/*/SKILL.md`, …) are denied from the corpus outright, so
  agent-directed text can never be re-presented to the auditing model as repository content.
- Every file is wrapped in **per-run nonce delimiters** — see
  [Prompt-injection containment](#prompt-injection-containment) below.
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

### Prompt-injection containment

The corpus is untrusted by construction: it is repository source, and anyone who can land a
commit can write text into it. Containment is layered, and only the last layer is trusted.

1. **Per-run nonce fences.** `collect-corpus.mjs` generates a 24-byte random nonce for every run
   and wraps each file in `<<<SPE_AUDIT_UNTRUSTED_FILE_BEGIN:<nonce>>>>` /
   `…_END:<nonce>>>>`. A static delimiter is forgeable — the literal sentinel already appears in
   this repository's own `constants.mjs` — so any occurrence of the sentinel inside a file body
   is rewritten to a neutral marker before fencing, and a body that somehow contains the live
   nonce aborts the run. After emission the collector re-counts fences and fails unless the
   begin/end counts both equal the file count, so a corpus that can close its own fence never
   reaches the model.
2. **Nonce conveyance.** The nonce is recorded in `corpus-manifest.json`, and `build-prompt.mjs`
   renders it into both prompt files. The model is told the exact fence to expect, so a forged
   fence carrying a different (or no) nonce is visibly not the real boundary.
3. **Trusted suffix, not a privileged role.** `actions/ai-inference` concatenates the system
   prompt and the prompt, so `system-prompt-file` is *not* a separate privileged channel — text
   later in the payload is not inherently less authoritative. The output contract is therefore
   re-asserted **after** the corpus, from `prompt-suffix.md`, as the last thing the model reads.
4. **`validate-response.mjs` is the enforceable boundary.** Everything above is defence in depth
   and none of it is a security control on its own: prompt text cannot be enforced. The schema
   validator is the control. It re-derives the allowlists from `constants.mjs`, requires every
   finding to anchor to a real corpus file and a line that exists in it, rejects secrets/GUIDs/
   absolute paths/weaponized payloads, redacts the rest, and **exits non-zero if anything was
   rejected** (fail-closed). If the model ignores every instruction it was given, the run fails;
   it does not silently emit attacker-shaped output.

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
| `corpus-manifest.json` | Files collected, byte/line counts, skipped files, the run nonce |
| `system.txt` | Rendered auditor preamble (vocabulary injected from `constants.mjs`) |
| `prompt.txt` | Nonce-fenced corpus followed by the trusted output-contract suffix |
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

### Assumption: audited commits are reachable from `main`

`validate-target.mjs` requires the target SHA to be an ancestor of `refs/remotes/origin/main`.
That is the point of the check — it stops a dispatch from pointing the audit at an arbitrary
unreviewed commit — but it interacts with the repository's merge settings.

At the time of writing the repository allows **all three** merge methods (merge commit, squash,
rebase). Squash and rebase merges rewrite commits, so a pull request's original head SHA is
**not** reachable from `main` after the merge, and passing it here is rejected by design. Audit
the resulting commit on `main` instead — that is the code that actually ships. Administrators who
want dispatch-by-PR-head to work must standardize on merge commits; the audit intentionally does
not relax the reachability rule to accommodate rewritten history.

Scheduled runs are unaffected: they supply no ref, so the current `origin/main` tip is resolved
and validated by the same rules.

## Design constraints

- The workflow has **no** `pull_request` or `pull_request_target` trigger, so untrusted forks
  can never reach the audit path or its secrets.
- Workflow-level permissions are `{}` (deny-all); each job re-grants only what it needs.
- Every action is pinned to a 40-hex commit SHA with the version in a trailing comment, and
  `action-pins` fails the run if that ever regresses.
- Checkouts use `persist-credentials: false`.
- Every `continue-on-error: true` step is paired with an explicit failure gate that re-raises
  the failure after the raw report has been sanitized — a test enforces this invariant.
