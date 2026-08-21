#!/usr/bin/env node
/**
 * Verifies that every `uses:` reference in `.github/workflows` is pinned to a
 * full 40-character commit SHA and carries a human-readable version comment.
 *
 * A floating tag (`@v4`) is mutable: whoever controls the tag controls what runs
 * inside the workflow, including in jobs that hold `security-events: write`.
 * Local (`./…`) and Docker (`docker://…`) references are out of scope.
 *
 * The check is line-based rather than YAML-based so that it still fires on files
 * this repository's YAML subset parser cannot represent.
 *
 * Usage:
 *   node scripts/security-audit/check-action-pins.mjs [--dir .github/workflows]
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const USES_RE = /^\s*(?:-\s+)?uses:\s*(\S+)\s*(.*)$/;
const SHA_RE = /^[0-9a-f]{40}$/;
const VERSION_COMMENT_RE = /#\s*\S+/;

/**
 * @param {string} text
 * @param {string} file
 * @returns {Array<{ file: string, line: number, uses: string, reason: string }>}
 */
export function checkWorkflowSource(text, file) {
  /** @type {Array<{ file: string, line: number, uses: string, reason: string }>} */
  const violations = [];
  const lines = text.split(/\r?\n/);

  lines.forEach((line, index) => {
    const match = USES_RE.exec(line);
    if (!match) return;

    const [, reference, trailing] = match;
    if (reference.startsWith('./') || reference.startsWith('docker://')) return;

    const at = reference.lastIndexOf('@');
    const record = { file, line: index + 1, uses: reference };

    if (at === -1) {
      violations.push({ ...record, reason: 'missing-ref' });
      return;
    }

    const ref = reference.slice(at + 1);
    if (!SHA_RE.test(ref)) {
      violations.push({ ...record, reason: 'not-sha-pinned' });
      return;
    }

    if (!VERSION_COMMENT_RE.test(trailing)) {
      violations.push({ ...record, reason: 'missing-version-comment' });
    }
  });

  return violations;
}

/**
 * @param {string} dir
 */
export function checkWorkflowDirectory(dir) {
  const files = readdirSync(dir)
    .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
    .sort();

  return files.flatMap((name) =>
    checkWorkflowSource(readFileSync(join(dir, name), 'utf8'), `${dir}/${name}`),
  );
}

function main() {
  const argv = process.argv.slice(2);
  const dirIndex = argv.indexOf('--dir');
  const dir = dirIndex === -1 ? '.github/workflows' : argv[dirIndex + 1];

  let violations;
  try {
    violations = checkWorkflowDirectory(dir);
  } catch (error) {
    process.stderr.write(`security-audit: unable to read ${dir}: ${error.message}\n`);
    process.exit(1);
    return;
  }

  if (violations.length === 0) {
    process.stdout.write(`security-audit: all workflow actions in ${dir} are SHA-pinned\n`);
    return;
  }

  for (const violation of violations) {
    process.stderr.write(
      `${violation.file}:${violation.line}: ${violation.reason}: ${violation.uses}\n`,
    );
  }
  process.stderr.write(
    `security-audit: ${violations.length} unpinned or undocumented action reference(s)\n`,
  );
  process.exit(1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
