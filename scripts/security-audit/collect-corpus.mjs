#!/usr/bin/env node
/**
 * Collects the bounded, allowlisted corpus that is sent to the model.
 *
 * Security properties:
 *  - Only files under the scope's directory prefixes are considered.
 *  - Only allowlisted extensions are read; deny patterns remove tests, build
 *    output and vendored code.
 *  - Hard caps on file count, per-file bytes and total bytes. Oversized files are
 *    skipped rather than truncated, so the model never reasons about a partial
 *    file and reports a line number that does not exist upstream.
 *  - Every file body is fenced with fixed delimiters and the prompt instructs the
 *    model to treat the contents as untrusted data, never as instructions.
 *  - File discovery uses `git ls-files`, so untracked and ignored files (which
 *    may contain local secrets) are never collected.
 *
 * Emits:
 *  - `<out>/corpus.txt`          delimiter-fenced file bodies
 *  - `<out>/corpus-manifest.json` path -> { bytes, lines } used to validate that
 *                                 model findings reference real files and lines
 *
 * Usage:
 *   node scripts/security-audit/collect-corpus.mjs --scope <name> --out <dir>
 */

import { execFileSync } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  ALLOWED_EXTENSIONS,
  CORPUS_DELIMITERS,
  CORPUS_DENY_PATTERNS,
  CORPUS_LIMITS,
  DEFAULT_SCOPE,
  SCOPES,
} from './lib/constants.mjs';

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

/** @returns {string[]} Repository-relative, POSIX-separated tracked paths. */
function listTrackedFiles() {
  const stdout = execFileSync('git', ['ls-files', '-z'], {
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  return stdout.split('\0').filter(Boolean);
}

/**
 * @param {string} file
 * @param {string[]} prefixes
 */
function isEligible(file, prefixes) {
  if (!prefixes.some((prefix) => file.startsWith(prefix))) return false;
  if (!ALLOWED_EXTENSIONS.includes(path.extname(file))) return false;
  if (CORPUS_DENY_PATTERNS.some((pattern) => pattern.test(file))) return false;
  return true;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const scope = (args.scope ?? '').trim() || DEFAULT_SCOPE;
  const outDir = (args.out ?? '').trim() || 'security-audit-out';

  const prefixes = SCOPES[scope];
  if (!prefixes) {
    fail(`scope ${JSON.stringify(scope)} is not allowlisted`);
  }

  const candidates = listTrackedFiles()
    .filter((file) => isEligible(file, prefixes))
    .sort();

  /** @type {Record<string, { bytes: number, lines: number }>} */
  const manifest = {};
  const chunks = [];
  const skipped = [];
  let totalBytes = 0;
  let fileCount = 0;

  for (const file of candidates) {
    if (fileCount >= CORPUS_LIMITS.maxFiles) {
      skipped.push({ file, reason: 'max-files' });
      continue;
    }

    let size;
    try {
      size = statSync(file).size;
    } catch {
      skipped.push({ file, reason: 'unreadable' });
      continue;
    }

    if (size > CORPUS_LIMITS.maxFileBytes) {
      skipped.push({ file, reason: 'max-file-bytes' });
      continue;
    }
    if (totalBytes + size > CORPUS_LIMITS.maxTotalBytes) {
      skipped.push({ file, reason: 'max-total-bytes' });
      continue;
    }

    const body = readFileSync(file, 'utf8');
    const lines = body.split('\n').length;

    manifest[file] = { bytes: size, lines };
    totalBytes += size;
    fileCount += 1;

    chunks.push(
      [
        `${CORPUS_DELIMITERS.begin} path=${file} lines=${lines}`,
        body.replace(/\s+$/, ''),
        CORPUS_DELIMITERS.end,
        '',
      ].join('\n'),
    );
  }

  if (fileCount === 0) {
    fail(`scope ${scope} produced an empty corpus; nothing to audit`);
  }

  mkdirSync(outDir, { recursive: true });
  writeFileSync(path.join(outDir, 'corpus.txt'), chunks.join('\n'), 'utf8');
  writeFileSync(
    path.join(outDir, 'corpus-manifest.json'),
    `${JSON.stringify({ scope, fileCount, totalBytes, files: manifest, skipped }, null, 2)}\n`,
    'utf8',
  );

  process.stdout.write(
    `security-audit: corpus scope=${scope} files=${fileCount} bytes=${totalBytes} skipped=${skipped.length}\n`,
  );

  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `corpus_files=${fileCount}\ncorpus_bytes=${totalBytes}\n`,
      'utf8',
    );
  }
}

main();
