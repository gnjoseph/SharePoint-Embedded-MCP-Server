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
 * Both surfaces are scanned:
 *   - every `*.yml` / `*.yaml` under the workflow directory, recursively; and
 *   - every composite/local action (`action.yml` / `action.yaml`) anywhere under
 *     the repository root. A composite action runs with the calling workflow's
 *     permissions, so an unpinned `uses:` inside one is just as dangerous while
 *     being invisible to a workflow-directory-only scan.
 *
 * Usage:
 *   node scripts/security-audit/check-action-pins.mjs [--dir .github/workflows] [--root .]
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const USES_RE = /^\s*(?:-\s+)?uses:\s*(\S+)\s*(.*)$/;
const SHA_RE = /^[0-9a-f]{40}$/;
const VERSION_COMMENT_RE = /#\s*\S+/;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'coverage', '.security-audit']);
const COMPOSITE_NAMES = new Set(['action.yml', 'action.yaml']);

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
 * Recursively lists files under `dir` that satisfy `predicate`.
 *
 * @param {string} dir
 * @param {(name: string) => boolean} predicate
 * @returns {string[]} POSIX-style paths, sorted for deterministic output.
 */
export function collectFiles(dir, predicate) {
  /** @type {string[]} */
  const found = [];

  /** @param {string} current */
  function walk(current) {
    for (const entry of readdirSync(current, { withFileTypes: true }).sort((a, b) =>
      a.name.localeCompare(b.name),
    )) {
      if (entry.name.startsWith('.') && entry.isDirectory() && entry.name !== '.github') continue;
      const full = join(current, entry.name);
      // `withFileTypes` reports symlinks separately; resolve them defensively so a
      // symlinked workflow directory is still scanned rather than silently skipped.
      const isDirectory = entry.isDirectory() || (entry.isSymbolicLink() && safeIsDirectory(full));
      if (isDirectory) {
        if (SKIP_DIRS.has(entry.name)) continue;
        walk(full);
        continue;
      }
      if (predicate(entry.name)) found.push(full.split('\\').join('/'));
    }
  }

  walk(dir);
  return found.sort();
}

/** @param {string} target */
function safeIsDirectory(target) {
  try {
    return statSync(target).isDirectory();
  } catch {
    return false;
  }
}

/**
 * Scans every YAML file under `dir`, recursively.
 *
 * @param {string} dir
 */
export function checkWorkflowDirectory(dir) {
  const files = collectFiles(dir, (name) => name.endsWith('.yml') || name.endsWith('.yaml'));

  return files.flatMap((file) => checkWorkflowSource(readFileSync(file, 'utf8'), file));
}

/**
 * Scans composite/local actions (`action.yml` / `action.yaml`) anywhere under
 * `root`. Composite actions run with the calling workflow's permissions, so an
 * unpinned `uses:` inside one is exactly as dangerous as an unpinned `uses:` in
 * the workflow itself, yet it is invisible to a workflow-directory-only scan.
 *
 * @param {string} root
 */
export function checkCompositeActions(root) {
  const files = collectFiles(root, (name) => COMPOSITE_NAMES.has(name));

  return files.flatMap((file) => checkWorkflowSource(readFileSync(file, 'utf8'), file));
}

function main() {
  const argv = process.argv.slice(2);
  const dirIndex = argv.indexOf('--dir');
  const dir = dirIndex === -1 ? '.github/workflows' : argv[dirIndex + 1];
  const rootIndex = argv.indexOf('--root');
  const root = rootIndex === -1 ? '.' : argv[rootIndex + 1];

  let violations;
  let scanned;
  try {
    const workflowFiles = collectFiles(
      dir,
      (name) => name.endsWith('.yml') || name.endsWith('.yaml'),
    );
    const compositeFiles = checkCompositeActionPaths(root, workflowFiles);
    scanned = workflowFiles.length + compositeFiles.length;
    violations = [
      ...workflowFiles.flatMap((file) => checkWorkflowSource(readFileSync(file, 'utf8'), file)),
      ...compositeFiles.flatMap((file) => checkWorkflowSource(readFileSync(file, 'utf8'), file)),
    ];
  } catch (error) {
    process.stderr.write(`security-audit: unable to read ${dir}: ${error.message}\n`);
    process.exit(1);
    return;
  }

  if (violations.length === 0) {
    process.stdout.write(
      `security-audit: all actions are SHA-pinned across ${scanned} workflow/composite file(s)\n`,
    );
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

/**
 * @param {string} root
 * @param {string[]} alreadyScanned
 */
function checkCompositeActionPaths(root, alreadyScanned) {
  const seen = new Set(alreadyScanned);
  return collectFiles(root, (name) => COMPOSITE_NAMES.has(name)).filter((file) => !seen.has(file));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
