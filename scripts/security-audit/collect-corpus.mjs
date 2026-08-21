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
 *  - Every file body is fenced with a PER-RUN CRYPTOGRAPHIC NONCE. A static fence
 *    is forgeable — this repository's own `lib/constants.mjs` contains the fence
 *    sentinel — so the nonce is generated fresh for every run and cannot appear
 *    in repository content. Any sentinel literal found inside a collected body is
 *    neutralized before emission, and a body that somehow contains the run nonce
 *    aborts the collection outright.
 *  - File discovery uses `git ls-files`, so untracked and ignored files (which
 *    may contain local secrets) are never collected.
 *  - `--repo-root` points at the *audited* checkout, which is separate from the
 *    trusted controller checkout this script is executed from. The controller
 *    never runs code from, and never sources helper scripts out of, the audited
 *    tree — so auditing a historical commit cannot change audit behaviour.
 *
 * Emits:
 *  - `<out>/corpus.txt`          delimiter-fenced file bodies
 *  - `<out>/corpus-manifest.json` nonce + path -> { bytes, lines } used to
 *                                 validate that model findings reference real
 *                                 files and lines, and to render the prompt with
 *                                 the exact fence in use
 *
 * Usage:
 *   node scripts/security-audit/collect-corpus.mjs --scope <name> --out <dir> [--repo-root <dir>]
 */

import { execFileSync } from 'node:child_process';
import { appendFileSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  ALLOWED_EXTENSIONS,
  corpusDelimiters,
  CORPUS_DENY_PATTERNS,
  CORPUS_LIMITS,
  DEFAULT_SCOPE,
  generateCorpusNonce,
  neutralizeDelimiters,
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

/**
 * @param {string} repoRoot Directory of the checkout to enumerate.
 * @returns {string[]} Repository-relative, POSIX-separated tracked paths.
 */
function listTrackedFiles(repoRoot) {
  const stdout = execFileSync('git', ['ls-files', '-z'], {
    cwd: repoRoot,
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
  // The audited content lives in a *separate* checkout from the trusted
  // controller scripts, so the corpus root is explicit. Manifest keys stay
  // repository-relative so findings reference real repository paths rather
  // than the controller's `target/` staging directory.
  const repoRoot = (args['repo-root'] ?? '').trim() || '.';

  const prefixes = SCOPES[scope];
  if (!prefixes) {
    fail(`scope ${JSON.stringify(scope)} is not allowlisted`);
  }

  const candidates = listTrackedFiles(repoRoot)
    .filter((file) => isEligible(file, prefixes))
    .sort();

  /** @type {Record<string, { bytes: number, lines: number }>} */
  const manifest = {};
  const chunks = [];
  const skipped = [];
  let totalBytes = 0;
  let fileCount = 0;
  let neutralizedTotal = 0;

  // Fresh, unguessable fence for this run only. Repository content cannot
  // contain it, so no collected file can close its own fence.
  const nonce = generateCorpusNonce();
  const delimiters = corpusDelimiters(nonce);

  for (const file of candidates) {
    if (fileCount >= CORPUS_LIMITS.maxFiles) {
      skipped.push({ file, reason: 'max-files' });
      continue;
    }

    let size;
    try {
      size = statSync(path.join(repoRoot, file)).size;
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

    const rawBody = readFileSync(path.join(repoRoot, file), 'utf8');

    // Defence in depth: a body must never be able to emit anything that looks
    // like a fence. The nonce makes forgery infeasible; neutralization makes it
    // impossible even to write the sentinel token into the corpus.
    if (rawBody.includes(nonce)) {
      fail(`file ${file} contains the run nonce; aborting corpus collection`);
    }
    const { value: body, neutralized } = neutralizeDelimiters(rawBody);
    neutralizedTotal += neutralized;
    const lines = body.split('\n').length;

    manifest[file] = { bytes: size, lines };
    totalBytes += size;
    fileCount += 1;

    chunks.push(
      [
        `${delimiters.begin} path=${file} lines=${lines}`,
        body.replace(/\s+$/, ''),
        delimiters.end,
        '',
      ].join('\n'),
    );
  }

  if (fileCount === 0) {
    fail(`scope ${scope} produced an empty corpus; nothing to audit`);
  }

  const corpus = chunks.join('\n');

  // Final assertion: exactly one begin and one end fence per collected file.
  const beginCount = corpus.split(delimiters.begin).length - 1;
  const endCount = corpus.split(delimiters.end).length - 1;
  if (beginCount !== fileCount || endCount !== fileCount) {
    fail(
      `corpus fence integrity check failed: expected ${fileCount} pairs, found begin=${beginCount} end=${endCount}`,
    );
  }

  mkdirSync(outDir, { recursive: true });
  writeFileSync(path.join(outDir, 'corpus.txt'), corpus, 'utf8');
  writeFileSync(
    path.join(outDir, 'corpus-manifest.json'),
    `${JSON.stringify(
      {
        scope,
        nonce,
        delimiters: { begin: delimiters.begin, end: delimiters.end },
        fileCount,
        totalBytes,
        neutralized: neutralizedTotal,
        files: manifest,
        skipped,
      },
      null,
      2,
    )}\n`,
    'utf8',
  );

  process.stdout.write(
    `security-audit: corpus scope=${scope} files=${fileCount} bytes=${totalBytes} skipped=${skipped.length} neutralized=${neutralizedTotal}\n`,
  );

  if (process.env.GITHUB_OUTPUT) {
    // The nonce is deliberately NOT exported as a step output: it is carried in
    // the manifest and consumed only by `build-prompt.mjs` inside the same job.
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `corpus_files=${fileCount}\ncorpus_bytes=${totalBytes}\ncorpus_neutralized=${neutralizedTotal}\n`,
      'utf8',
    );
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
