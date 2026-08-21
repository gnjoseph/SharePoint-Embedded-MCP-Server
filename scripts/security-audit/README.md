# `scripts/security-audit`

Zero-dependency Node ESM helpers behind
[`.github/workflows/security-audit.yml`](../../.github/workflows/security-audit.yml).
They use only the Node standard library, so they run with `node` alone — no `npm ci` required.

Operator-facing documentation lives in [`docs/SECURITY-AUDIT.md`](../../docs/SECURITY-AUDIT.md).

## Scripts

| Script | Purpose | Exit codes |
| --- | --- | --- |
| `validate-target.mjs` | Validates the manual inputs: 40-hex SHA reachable from `main`, allowlisted scope/model, boolean dry-run | `0` ok, `1` rejected |
| `collect-corpus.mjs` | Collects the allowlisted, capped corpus and writes a manifest | `0` ok, `1` error |
| `validate-response.mjs` | Parses, schema-checks, rejects, and redacts the model response | `0` ok, `1` malformed, `3` unsafe (fail closed) |
| `to-sarif.mjs` | Converts an accepted report to SARIF 2.1.0 | `0` ok, `1` error |
| `sanitize-findings.mjs` | Strips secret material from `npm audit` / gitleaks reports | `0` ok, `1` error |
| `check-action-pins.mjs` | Fails if any workflow action is not pinned to a 40-hex SHA | `0` clean, `1` violations |
| `summarize.mjs` | Builds the run summary and decides pass/fail | `0` pass, `1` a deterministic job failed |
| `dry-run.mjs` | Offline end-to-end run against a synthetic response | `0` ok, non-zero on failure |

`prompt.md` is the system prompt and output contract sent to the model.

## Layout

```
lib/constants.mjs    single source of truth: caps, allowlists, statuses
lib/mini-yaml.mjs    fail-closed YAML-subset parser used by the tests
lib/controls.mjs     parses docs/SECURITY-CONTROLS.md into a code set
lib/redaction.mjs    reject/redact pattern sets
fixtures/            synthetic, malformed, unsafe and injection fixtures
tests/               node:test suites (no vitest, no coverage thresholds)
```

## Common invocations

```bash
node scripts/security-audit/validate-target.mjs --ref <40-hex-sha> --scope server-core
node scripts/security-audit/collect-corpus.mjs  --scope server-core --out .security-audit
node scripts/security-audit/validate-response.mjs \
  --response .security-audit/response.txt \
  --manifest .security-audit/corpus-manifest.json \
  --out      .security-audit/model-report.json
node scripts/security-audit/to-sarif.mjs --report .security-audit/model-report.json \
  --out .security-audit/model-report.sarif
node scripts/security-audit/check-action-pins.mjs
```

Or via npm: `security:audit:dry-run`, `security:audit:test`, `security:audit:pins`.

## Tests

```bash
npm run security:audit:test
```

- `pipeline.test.mjs` — corpus caps and delimiters, schema validation, every rejection reason,
  credential/shell smuggling, prompt injection, findings-cap overflow, redaction, sanitizers,
  SARIF shape, summary polarity, the offline dry run, and a repo walk proving no script
  creates issues, comments, or repository writes.
- `workflow-invariants.test.mjs` — parses the real workflow YAML and asserts: no PR triggers,
  weekly Monday schedule, deny-all workflow permissions, no write permission other than
  `security-events`, per-job timeouts and concurrency, allowlisted inputs, 40-hex action pins,
  no shell interpolation of model output, the model job is gated/environment-protected/tool-less,
  the dry-run job holds no secret and never uploads to code scanning, `--ignore-scripts` in the
  audit path, `persist-credentials: false`, every `continue-on-error` step is re-raised, and the
  legacy no-op gitleaks gate is gone.

Fixtures never contain a literal credential; token-shaped strings are constructed at runtime so
the repository's own secret scanner does not flag its test data.
