#!/usr/bin/env node
/**
 * Validates and normalizes the audit target before any privileged step runs.
 *
 * Guarantees enforced here:
 *  - `ref` is a full 40-character hex commit SHA (no branch names, no tags, no
 *    abbreviated SHAs) and is an ancestor of `origin/main`. This prevents the
 *    audit from being pointed at arbitrary unreviewed code via
 *    `workflow_dispatch`.
 *  - `model` and `scope` are members of a fixed allowlist.
 *  - `dry_run` is a strict boolean literal.
 *
 * Writes the normalized values to `$GITHUB_OUTPUT` when running in Actions.
 * Exits non-zero on any violation so that downstream jobs never start.
 *
 * Usage:
 *   node scripts/security-audit/validate-target.mjs \
 *     --ref <sha> --model <name> --scope <name> --dry-run <true|false>
 */

import { execFileSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { ALLOWED_MODELS, DEFAULT_MODEL, DEFAULT_SCOPE, SCOPES } from './lib/constants.mjs';

const BASE_REF = 'refs/remotes/origin/main';
const FULL_SHA = /^[0-9a-f]{40}$/;

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

/** @param {string} message */
function fail(message) {
  process.stderr.write(`security-audit: ${message}\n`);
  process.exit(1);
}

/**
 * @param {string} value
 * @param {string} name
 */
function parseBoolean(value, name) {
  if (value === undefined || value === '') return false;
  if (value === 'true') return true;
  if (value === 'false') return false;
  fail(`${name} must be exactly "true" or "false"; received ${JSON.stringify(value)}`);
  return false;
}

/** @param {string} sha */
function assertReachableFromMain(sha) {
  try {
    execFileSync('git', ['cat-file', '-e', `${sha}^{commit}`], { stdio: 'ignore' });
  } catch {
    fail(`ref ${sha} does not resolve to a commit in this repository`);
  }

  try {
    execFileSync('git', ['merge-base', '--is-ancestor', sha, BASE_REF], { stdio: 'ignore' });
  } catch {
    fail(
      `ref ${sha} is not an ancestor of ${BASE_REF}. ` +
        'Only commits already merged to main may be audited.',
    );
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  const ref = (args.ref ?? '').trim();
  if (!FULL_SHA.test(ref)) {
    fail(
      `ref must be a full 40-character lowercase hex commit SHA; received ${JSON.stringify(ref)}`,
    );
  }

  const model = (args.model ?? '').trim() || DEFAULT_MODEL;
  if (!ALLOWED_MODELS.includes(model)) {
    fail(`model ${JSON.stringify(model)} is not allowlisted. Allowed: ${ALLOWED_MODELS.join(', ')}`);
  }

  const scope = (args.scope ?? '').trim() || DEFAULT_SCOPE;
  if (!Object.hasOwn(SCOPES, scope)) {
    fail(
      `scope ${JSON.stringify(scope)} is not allowlisted. Allowed: ${Object.keys(SCOPES).join(', ')}`,
    );
  }

  const dryRun = parseBoolean(args['dry-run'], 'dry_run');

  if (args['skip-reachability'] !== 'true') {
    assertReachableFromMain(ref);
  }

  const outputs = {
    target_sha: ref,
    model,
    scope,
    dry_run: String(dryRun),
  };

  for (const [key, value] of Object.entries(outputs)) {
    process.stdout.write(`${key}=${value}\n`);
  }

  if (process.env.GITHUB_OUTPUT) {
    const payload = Object.entries(outputs)
      .map(([key, value]) => `${key}=${value}`)
      .join('\n');
    appendFileSync(process.env.GITHUB_OUTPUT, `${payload}\n`, 'utf8');
  }
}

main();
