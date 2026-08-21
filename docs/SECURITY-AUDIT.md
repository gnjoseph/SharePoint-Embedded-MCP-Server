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

### Trusted controller vs audited target

Any commit reachable from `main` can be audited, including commits from before this workflow
existed. The audit therefore never runs code from the commit it is auditing:

- **Controller** — checked out at the workspace root with **no `ref:` override**. Because the
  workflow only triggers on `schedule` and `workflow_dispatch` against the default branch, the
  event SHA is the protected `main` tip. This is where `scripts/security-audit/**`, `package.json`
  and the workflow itself come from.
- **Target** — checked out into `target/` at the validated SHA. It is **data**, never an
  executable surface.

Every helper is invoked from the controller checkout and pointed at the target explicitly
(`collect-corpus.mjs --repo-root target`, `check-action-pins.mjs --dir target/.github/workflows
--root target`, `npm ci`/`npm audit` under `working-directory: target`, `gitleaks git target`,
CodeQL `source-root: target`). Tests assert that no `node scripts/security-audit/...` invocation
ever resolves out of `target/`.

> **Ordering constraint.** `actions/checkout` runs `git clean -ffdx` in its destination, so a
> root checkout performed *after* a `target/` checkout would delete the target. The controller
> checkout must always come **first**; a test enforces the ordering.

Auditing an ancestor such as `819431d` — a commit with no `scripts/security-audit/` directory at
all — is a supported case and is covered by a regression test.

### Result attribution

SARIF uploaded from an audit describes the *target* commit, not the workflow event SHA, so both
uploads pass explicit attribution:

| Input | Value | Why |
| --- | --- | --- |
| `checkout_path` | `${{ github.workspace }}/target` | Relativizes SARIF paths against the target checkout, so results do not surface as `target/src/...` |
| `ref` | `refs/heads/main` | The ref results are recorded against |
| `sha` | The validated target SHA | The commit results are recorded against |

Code scanning defines `sha` as *the head of the supplied ref*, so a historical ancestor cannot be
described truthfully. Runs whose target is **not** the current `main` tip therefore do not upload:

- `codeql` sets `upload: never` and the analysis is discarded.
- `model-audit` skips the upload step and a dedicated step logs why and **fails the job**.

That is deliberate fail-closed behaviour. On a public repository the alternative — publishing raw
findings as a downloadable artifact — would disclose unfixed vulnerabilities, so it is not offered.
Historical audits are for local/manual triage; schedule-driven runs always target the tip and
always upload.

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

Both `security:audit:dry-run` and `collect-corpus.mjs` accept `--repo-root <dir>`, which is how
the workflow points the controller's helpers at the `target/` checkout. It defaults to `.`, so
local runs audit the working tree and need no extra flag. Manifest keys stay repository-relative
regardless of the root, so a finding reported against `src/server.ts` reads the same locally and
in CI.

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
   **Security** tab.
2. **Secret-scan hits publish counts only.** The job summary and the `secret-scan-summary`
   artifact are world-readable on a public repository, so they carry `total`, `ruleCount` and
   `fileCount` — never rule identifiers and never file paths. A rule id paired with a path
   states which file holds which class of credential, which is exactly the pre-rotation
   disclosure an attacker wants. To locate a hit, open the **`Scan for committed secrets`**
   step log of the failing run (visible to collaborators with read access to Actions logs);
   the scanner runs with `--redact`, so the log shows location without the secret value.
   The raw Gitleaks report is deleted inside the job and is never uploaded. Rotate the
   credential *before* removing it from source, then re-run the workflow to confirm.
3. **Model findings are leads, not verdicts.** Each accepted finding carries a confidence and a
   control anchor. Confirm the code path by hand before filing anything.
4. **Check the rejected list.** A high rejection count usually means the model drifted off the
   corpus or attempted to smuggle content — treat it as a signal about the run, not about the code.
5. **Report real vulnerabilities privately** per [`SECURITY.md`](../SECURITY.md). Never open a
   public issue for an unfixed vulnerability.

## Activating the model-assisted layer

The model layer ships **disabled**. Nothing in this repository stores, references or reuses a
credential, and the deterministic jobs are fully functional without one. Activation requires
repository-administrator rights and is deliberately **not** automated.

**Approval gate.** The model layer sends repository source to a third-party inference provider.
Obtain **CELA and Privacy sign-off before setting `SECURITY_AUDIT_AI_ENABLED`**. Enabling the
variable is the act that authorizes egress; every other step below is inert without it.

Steps, in order:

1. **Generate and commit the Copilot CLI lockfile.** The install step fails closed when
   `tools/copilot-cli/package-lock.json` is absent. Generate it on a network with direct access
   to `registry.npmjs.org` and verify the `resolved` and `integrity` fields before committing —
   see [`tools/copilot-cli/README.md`](../tools/copilot-cli/README.md).
2. **Create and protect the `security-audit-ai` environment**: required reviewers, plus a
   deployment-branch rule limited to `main`.
3. **Provision a team-owned managed service account, then add a least-scope `COPILOT_PAT`
   environment secret** (Copilot Requests only — no `repo`, no `workflow`, no `write:*`).
   GitHub has no "team alias" credential: a personal access token is always bound to a GitHub
   *account*, so the token must be issued from a **managed service (machine) account owned by the
   team**, never from an individual maintainer's account. This is the only supported credential
   path; see the governance requirements below.
4. **Set the repository variable `SECURITY_AUDIT_AI_ENABLED` to `true`.** The job stays skipped
   until this variable exists, so the protected environment is never implicitly created.
5. **Validate the model id** is accepted by the provider before the first real run. The default
   (`claude-opus-5`) is an allowlist entry that has not been exercised end to end.

### `COPILOT_PAT` governance requirements

These are prerequisites for step 3, not suggestions. If any cannot be met, leave the layer
disabled — the deterministic jobs are unaffected.

| Requirement | Obligation |
| --- | --- |
| Account | The token must be issued from a **team-owned managed service (machine) GitHub account**, provisioned through the organization's standard process and recorded in the team's asset inventory. A token issued from an individual maintainer's account is disqualifying: it silently inherits that person's entitlements and dies with their offboarding. |
| Seat | The service account must hold a **Copilot Business or Copilot Enterprise** seat. **Individual/Pro seats are disallowed pending CELA review** — their terms, retention and training posture differ from the business/enterprise agreements. |
| Named owners | Record **at least two named human owners** (primary and backup) for the service account and the token, alongside the environment. A machine account with no named owner is unmaintainable. |
| Scope | Copilot Requests only. Any `repo`, `workflow`, `write:*` or `admin:*` scope is disqualifying. |
| Expiry | Set an **explicit expiry**. Tokens configured with "no expiration" are disqualifying. |
| Rotation | Rotate on a fixed cadence no longer than the organization's standard for CI credentials, and immediately on any suspected exposure. |
| Offboarding | Add the token to the team's **offboarding checklist**. Revoke and reissue whenever a named owner changes role or leaves, and whenever the service account changes hands. |
| Cost centre | Copilot premium requests are metered and billed against the service account's entitlement. Record the **cost centre** that absorbs them before enabling; a weekly run over the full corpus is not free. |
| Debug logs | Do **not** enable `ACTIONS_STEP_DEBUG` or `ACTIONS_RUNNER_DEBUG` on runs of this workflow. Debug logging can surface prompt and response content into world-readable logs, defeating the redaction boundary. |

There is **no** alternative credential mechanism implemented. If a different provider or an
OIDC-based flow is adopted later, it must be implemented and reviewed on its own merits — do not
assume it is available.

### Activation determinations (to be completed by CELA/Privacy)

Nothing in this table is answered, agreed or approved. These are **open questions** that CELA and
Privacy must determine and record before `SECURITY_AUDIT_AI_ENABLED` is set. This repository makes
no claim about any of them; the rows exist so that activation cannot proceed on assumption.

| Determination | Question to be answered | Status |
| --- | --- | --- |
| Prompt/completion retention | How long does the provider retain the prompt (repository source) and the completion, and where is that retention documented? | ☐ Not determined |
| Data residency | In which regions are prompts processed and stored, and is that acceptable for this repository's content? | ☐ Not determined |
| Provider terms and AUP | Do the applicable terms of service and acceptable-use policy permit automated source analysis of this repository under the seat type in use? | ☐ Not determined |
| Model training/improvement | Are prompts or completions used for model training, fine-tuning or product improvement, and can that be disabled? | ☐ Not determined |
| Telemetry and provider-side logging | What request metadata and content is logged provider-side, who can access it, and for how long? | ☐ Not determined |
| Contributor disclosure sufficiency | Is the disclosure in [`../CONTRIBUTING.md`](../CONTRIBUTING.md) sufficient notice to external contributors? | ☐ Not determined |
| Export/third-party review | Are there export-control or third-party-review obligations triggered by sending this source to the provider? | ☐ Not determined |

If any row is unresolved, leave the layer disabled. The deterministic jobs are unaffected and
continue to run on schedule.

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

Reachability does **not** imply the commit contains this workflow. Older ancestors are audited
using the controller/target split described above, and code-scanning upload is suppressed for any
target that is not the current tip — see [Result attribution](#result-attribution).

## Design constraints

- The workflow has **no** `pull_request` or `pull_request_target` trigger, so untrusted forks
  can never reach the audit path or its secrets.
- Workflow-level permissions are `{}` (deny-all); each job re-grants only what it needs.
- Every action is pinned to a 40-hex commit SHA with the version in a trailing comment, and
  `action-pins` fails the run if that ever regresses.
- Checkouts use `persist-credentials: false`.
- Audit logic always executes from the protected `main` controller checkout; the audited commit is
  mounted at `target/` and treated as data.
- Findings are attributed to the target commit explicitly, and suppressed rather than misattributed
  when the target is not the current `main` tip.
- Every `continue-on-error: true` step is paired with an explicit failure gate that re-raises
  the failure after the raw report has been sanitized — a test enforces this invariant.
