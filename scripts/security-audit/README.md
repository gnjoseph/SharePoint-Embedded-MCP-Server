# `scripts/security-audit`

Zero-dependency Node ESM helpers behind
[`.github/workflows/security-audit.yml`](../../.github/workflows/security-audit.yml).
They use only the Node standard library, so they run with `node` alone — no `npm ci` required.

Operator-facing documentation lives in [`docs/SECURITY-AUDIT.md`](../../docs/SECURITY-AUDIT.md).

## Scripts

| Script | Purpose | Exit codes |
| --- | --- | --- |
| `validate-target.mjs` | Validates the manual inputs: 40-hex SHA reachable from `main`, allowlisted scope/model, boolean dry-run. An empty/absent ref (scheduled runs) resolves to the `origin/main` tip and is then held to the same rules | `0` ok, `1` rejected |
| `collect-corpus.mjs` | Collects the allowlisted, capped corpus, wraps each file in per-run nonce fences, and writes a manifest | `0` ok, `1` error |
| `build-prompt.mjs` | Renders `system.txt` (preamble) and `prompt.txt` (corpus + trusted suffix) from the manifest nonce | `0` ok, `1` error |
| `validate-response.mjs` | Parses, schema-checks, rejects, and redacts the model response | `0` ok, `1` malformed, `3` unsafe (fail closed) |
| `to-sarif.mjs` | Converts an accepted report to SARIF 2.1.0 | `0` ok, `1` error |
| `sanitize-findings.mjs` | Strips secret material from `npm audit` / gitleaks reports | `0` ok, `1` error |
| `check-action-pins.mjs` | Fails if any workflow **or composite action** uses an action that is not pinned to a 40-hex SHA | `0` clean, `1` violations |
| `summarize.mjs` | Builds the run summary and decides pass/fail | `0` pass, `1` a deterministic job failed |
| `dry-run.mjs` | Offline end-to-end run against a synthetic response | `0` ok, non-zero on failure |

## Prompt assembly

`actions/ai-inference` **concatenates** the system prompt and the prompt, so `system-prompt-file`
is not a privileged channel. The payload is therefore assembled deliberately:

1. `collect-corpus.mjs` generates a 24-byte run nonce, rewrites any occurrence of the static
   delimiter sentinel inside a file body to a neutral marker, fences every file with
   `<<<SPE_AUDIT_UNTRUSTED_FILE_BEGIN:<nonce>>>>` / `…_END:<nonce>>>>`, then re-counts the fences
   and fails unless both counts equal the file count. It records the nonce in
   `corpus-manifest.json`.
2. `build-prompt.mjs` reads that manifest, re-verifies the nonce shape and fence integrity, and
   renders two templates — injecting the nonce, the fences, and the category/severity/confidence
   vocabularies straight from `lib/constants.mjs`, so the prompt can never drift from the
   validator. Unresolved `{{TOKEN}}` placeholders are a hard error.
3. `prompt.txt` = fenced corpus + `prompt-suffix.md`. The output contract is re-asserted **after**
   the untrusted content, as the last thing the model reads.

None of this is a security control on its own. `validate-response.mjs` is the enforceable
boundary: it re-derives the allowlists from `constants.mjs`, requires each finding to anchor to a
real corpus file and line, rejects credentials/GUIDs/absolute paths/weaponized payloads, and exits
non-zero if anything was rejected.

`prompt.md` and `prompt-suffix.md` are templates, not literal payloads — read the rendered
`system.txt` / `prompt.txt` from a dry run to see what is actually sent.

## Layout

```
lib/constants.mjs    single source of truth: caps, allowlists, nonce API, statuses
lib/mini-yaml.mjs    fail-closed YAML-subset parser used by the tests
lib/controls.mjs     parses docs/SECURITY-CONTROLS.md into a code set
lib/redaction.mjs    reject/redact pattern sets
prompt.md            auditor preamble template  -> rendered to system.txt
prompt-suffix.md     trusted output contract    -> appended after the corpus
fixtures/            synthetic, malformed, unsafe, injection and delimiter fixtures
tests/               node:test suites (no vitest, no coverage thresholds)
```

## Common invocations

```bash
node scripts/security-audit/validate-target.mjs --ref <40-hex-sha> --scope server-core
node scripts/security-audit/validate-target.mjs --scope server-core   # empty ref -> origin/main tip
node scripts/security-audit/collect-corpus.mjs  --scope server-core --out .security-audit
node scripts/security-audit/build-prompt.mjs    --corpus .security-audit --out .security-audit
node scripts/security-audit/validate-response.mjs \
  --response .security-audit/response.txt \
  --manifest .security-audit/corpus-manifest.json \
  --out      .security-audit/model-report.json
node scripts/security-audit/to-sarif.mjs --report .security-audit/model-report.json \
  --out .security-audit/model-report.sarif
node scripts/security-audit/check-action-pins.mjs
```

`validate-target.mjs` needs `refs/remotes/origin/main` to exist locally (the workflow checks out
with `fetch-depth: 0`). `SECURITY_AUDIT_TEST_MODE=1` skips only the reachability check and is used
by the test suite; no workflow sets it, and a test asserts that.

Or via npm: `security:audit:dry-run`, `security:audit:test`, `security:audit:pins`.

## Tests

```bash
npm run security:audit:test
```

- `pipeline.test.mjs` — target validation (scheduled/empty ref resolves to the `origin/main` tip,
  branch names and short SHAs refused, unreachable SHAs refused, scope/model allowlists), corpus
  caps, per-run nonce fences (two runs never share a nonce, a malformed nonce throws, the
  repository's own `constants.mjs` is neutralized, and a forged-delimiter fixture cannot close the
  fence), prompt assembly (the nonce reaches both rendered files, no `{{PLACEHOLDER}}` survives,
  the trusted suffix follows the last corpus fence, and the vocabulary is injected from
  `constants.mjs` so it cannot drift), schema validation, every rejection reason,
  credential/shell smuggling, prompt injection, findings-cap overflow, redaction, sanitizers,
  SARIF shape including `finding.detail` reaching `message.text`, composite-action pin coverage,
  summary polarity, the offline dry run, and a repo walk proving no script creates issues,
  comments, or repository writes.
- `workflow-invariants.test.mjs` — parses the real workflow YAML and asserts: no PR triggers,
  weekly Monday schedule, deny-all workflow permissions, no write permission other than
  `security-events`, per-job timeouts and concurrency, allowlisted inputs, 40-hex action pins,
  no shell interpolation of model output, the model job is gated/environment-protected/tool-less,
  the dry-run job holds no secret and never uploads to code scanning, `--ignore-scripts` in the
  audit path, no workflow sets `SECURITY_AUDIT_TEST_MODE` (the reachability escape hatch stays
  unreachable from CI), `persist-credentials: false`, every `continue-on-error` step is re-raised,
  and the legacy no-op gitleaks gate is gone.

Fixtures never contain a literal credential; token-shaped strings are constructed at runtime so
the repository's own secret scanner does not flag its test data.
