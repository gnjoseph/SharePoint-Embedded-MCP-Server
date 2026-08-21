#!/usr/bin/env node
/**
 * Renders the audit run summary and decides the overall exit status.
 *
 * The deterministic jobs (CodeQL, dependency audit, secret scan, action pinning)
 * gate the run. The model job is advisory: when it is skipped because no
 * credential is provisioned the summary states `AI NOT_CONFIGURED` explicitly
 * rather than implying the audit passed.
 *
 * Usage:
 *   node scripts/security-audit/summarize.mjs \
 *     --codeql success --dependency-audit success --secret-scan success \
 *     --action-pins success --model skipped [--out <file>]
 */

import { appendFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { STATUS } from './lib/constants.mjs';

/** Deterministic jobs whose failure fails the run. */
const REQUIRED_JOBS = Object.freeze([
  ['codeql', 'CodeQL (security-extended)'],
  ['dependency-audit', 'Dependency audit (npm audit --audit-level=high)'],
  ['secret-scan', 'Secret scan (gitleaks, checksum-verified)'],
  ['action-pins', 'Action pinning'],
]);

/**
 * @param {string[]} argv
 * @returns {Record<string, string>}
 */
function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) {
      args[key] = 'true';
    } else {
      args[key] = next;
      i += 1;
    }
  }
  return args;
}

/**
 * Maps a GitHub Actions job result onto the status literal reported for the
 * model layer.
 *
 * @param {string} result
 * @param {boolean} dryRun
 */
export function modelStatus(result, dryRun) {
  if (dryRun) return STATUS.dryRun;
  switch (result) {
    case 'success':
      return STATUS.completed;
    case 'skipped':
    case '':
    case undefined:
      return STATUS.notConfigured;
    default:
      return STATUS.failed;
  }
}

/**
 * @param {Record<string, string>} args
 * @returns {{ markdown: string, failed: boolean, status: string }}
 */
export function buildSummary(args) {
  const dryRun = args['dry-run'] === 'true';
  const status = modelStatus(args.model ?? 'skipped', dryRun);

  const rows = REQUIRED_JOBS.map(([key, label]) => {
    const result = args[key] ?? 'skipped';
    const icon = result === 'success' ? '✅' : result === 'skipped' ? '⏭️' : '❌';
    return `| ${label} | ${icon} ${result} |`;
  });

  const failed = REQUIRED_JOBS.some(([key]) => (args[key] ?? 'skipped') !== 'success');

  const lines = [
    '## Weekly repository security audit',
    '',
    `Target commit: \`${args.target ?? 'unknown'}\``,
    `Scope: \`${args.scope ?? 'unknown'}\``,
    '',
    '### Deterministic checks',
    '',
    '| Check | Result |',
    '| --- | --- |',
    ...rows,
    '',
    '### Model-assisted review',
    '',
    `Status: **${status}**`,
    '',
  ];

  if (status === STATUS.notConfigured) {
    lines.push(
      'The model-assisted pass did not run. It requires a protected `security-audit-ai`',
      'environment holding a least-scope `COPILOT_PAT`, plus repository variable',
      '`SECURITY_AUDIT_AI_ENABLED=true`. No inference was attempted and no model',
      'findings were produced — this run makes **no** claim about model-detectable issues.',
      '',
    );
  } else if (status === STATUS.dryRun) {
    lines.push(
      'Synthetic dry run: the schema, redaction and SARIF conversion path was exercised',
      'against a fixture. No credential was used and no inference was performed, so these',
      'results carry no security signal.',
      '',
    );
  }

  lines.push(
    'Model findings are advisory and require human triage. They never gate pull requests.',
    '',
  );

  return { markdown: `${lines.join('\n')}\n`, failed, status };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const { markdown, failed, status } = buildSummary(args);

  if (args.out) writeFileSync(args.out, markdown, 'utf8');
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown, 'utf8');
  }
  process.stdout.write(markdown);

  if (failed) {
    process.stderr.write('security-audit: one or more deterministic checks did not succeed\n');
    process.exit(1);
  }
  process.stdout.write(`security-audit: deterministic checks passed; model status ${status}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
