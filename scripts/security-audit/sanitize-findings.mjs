#!/usr/bin/env node
/**
 * Reduces raw scanner output to counts and non-sensitive identifiers.
 *
 * Rationale: `npm audit --json` embeds dependency graph detail, and a Gitleaks
 * report embeds the matched secret material itself. Neither may be retained as a
 * build artifact on a public repository. This script converts either into a
 * summary that is safe to publish, and the raw report is discarded by the caller.
 *
 * Usage:
 *   node scripts/security-audit/sanitize-findings.mjs \
 *     --kind npm-audit|gitleaks --in <file> --out <file>
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

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
 * Keeps only severity counts and advisory identifiers.
 *
 * @param {unknown} raw Parsed `npm audit --json` output.
 */
export function sanitizeNpmAudit(raw) {
  const metadata = raw?.metadata?.vulnerabilities ?? {};
  const advisories = new Set();

  for (const entry of Object.values(raw?.vulnerabilities ?? {})) {
    for (const via of entry?.via ?? []) {
      if (via && typeof via === 'object' && via.url) advisories.add(String(via.url));
    }
  }

  return {
    kind: 'npm-audit',
    counts: {
      critical: Number(metadata.critical ?? 0),
      high: Number(metadata.high ?? 0),
      moderate: Number(metadata.moderate ?? 0),
      low: Number(metadata.low ?? 0),
      info: Number(metadata.info ?? 0),
    },
    advisories: [...advisories].sort(),
  };
}

/**
 * Keeps rule identifiers and file paths. Never the matched secret, its
 * surrounding context, the commit author or the commit message.
 *
 * @param {unknown} raw Parsed Gitleaks JSON report.
 */
export function sanitizeGitleaks(raw) {
  const entries = Array.isArray(raw) ? raw : [];
  /** @type {Record<string, number>} */
  const byRule = {};
  const files = new Set();

  for (const entry of entries) {
    const rule = String(entry?.RuleID ?? entry?.ruleID ?? 'unknown');
    byRule[rule] = (byRule[rule] ?? 0) + 1;
    const file = entry?.File ?? entry?.file;
    if (file) files.add(String(file));
  }

  return {
    kind: 'gitleaks',
    total: entries.length,
    byRule,
    files: [...files].sort(),
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const { kind } = args;
  if (!kind || !args.in || !args.out) {
    process.stderr.write(
      'usage: sanitize-findings.mjs --kind npm-audit|gitleaks --in <file> --out <file>\n',
    );
    process.exit(1);
  }

  let raw;
  try {
    const text = readFileSync(args.in, 'utf8').trim();
    raw = text === '' ? null : JSON.parse(text);
  } catch (error) {
    process.stderr.write(`security-audit: unable to parse ${args.in}: ${error.message}\n`);
    process.exit(1);
  }

  let summary;
  if (kind === 'npm-audit') summary = sanitizeNpmAudit(raw ?? {});
  else if (kind === 'gitleaks') summary = sanitizeGitleaks(raw ?? []);
  else {
    process.stderr.write(`security-audit: unknown kind ${JSON.stringify(kind)}\n`);
    process.exit(1);
  }

  writeFileSync(args.out, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
  process.stdout.write(`security-audit: sanitized ${kind} summary written to ${args.out}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
