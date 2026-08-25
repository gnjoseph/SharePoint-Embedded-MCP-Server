#!/usr/bin/env node
/**
 * Verifies that every external action reference is immutable and carries a
 * human-readable version comment. This covers both `uses:` values and external
 * `runs.image: docker://...` values in local Docker action metadata.
 *
 * A floating tag (`@v4`) is mutable: whoever controls the tag controls what runs
 * inside the workflow, including in the job that holds the advisory credential
 * used to file a private vulnerability report.
 * Local (`./…`) `uses:` references are out of scope, but the referenced local
 * action metadata is scanned separately. Docker references must use an
 * immutable `sha256` digest.
 *
 * The check parses YAML before inspecting executable references. Unsupported
 * or ambiguous constructs fail closed rather than being ignored.
 *
 * Both surfaces are scanned:
 *   - every `*.yml` / `*.yaml` under the workflow directory, recursively; and
 *   - every local action (`action.yml` / `action.yaml`) anywhere under the
 *     repository root. Composite actions can contain nested `uses:` values, and
 *     Docker actions can name a registry image in `runs.image`; both execute with
 *     the calling workflow's trust and are invisible to a workflow-only scan.
 *
 * Usage:
 *   node scripts/security-audit/check-action-pins.mjs [--dir .github/workflows] [--root .]
 */

import { readdirSync, readFileSync, realpathSync } from 'node:fs';
import { isAbsolute, join, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  LineCounter,
  isAlias,
  isMap,
  isPair,
  isScalar,
  isSeq,
  parseAllDocuments,
} from 'yaml';

const SHA_RE = /^[0-9a-f]{40}$/;
const DOCKER_DIGEST_RE = /^docker:\/\/[^\s]+@sha256:[0-9a-fA-F]{64}$/;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'coverage', '.security-audit']);
const ACTION_METADATA_NAMES = new Set(['action.yml', 'action.yaml']);

/**
 * Returns the YAML comment on a physical line, ignoring `#` characters inside
 * quoted scalars.
 *
 * @param {string} line
 * @returns {string}
 */
function lineComment(line) {
  let inSingle = false;
  let inDouble = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (character === "'" && !inDouble) {
      if (inSingle && line[index + 1] === "'") {
        index += 1;
        continue;
      }
      inSingle = !inSingle;
      continue;
    }
    if (character === '"' && !inSingle) {
      let escaped = false;
      for (let cursor = index - 1; cursor >= 0 && line[cursor] === '\\'; cursor -= 1) {
        escaped = !escaped;
      }
      if (!escaped) inDouble = !inDouble;
      continue;
    }
    if (
      character === '#' &&
      !inSingle &&
      !inDouble &&
      (index === 0 || /\s/u.test(line[index - 1]))
    ) {
      return line.slice(index + 1).trim();
    }
  }
  return '';
}

/**
 * Reads a scalar string pair and records its physical line and trailing comment.
 *
 * @param {import('yaml').Pair} pair
 * @param {string} keyName
 * @param {string} file
 * @param {LineCounter} lineCounter
 * @param {string[]} lines
 * @returns {{ line: number, value: string, comment: string }}
 */
function stringPairRecord(pair, keyName, file, lineCounter, lines) {
  if (
    !isScalar(pair.value) ||
    typeof pair.value.value !== 'string' ||
    !pair.key.range ||
    !pair.value.range
  ) {
    throw new Error(`${file}: every ${keyName} value must be a scalar string`);
  }

  const keyPosition = lineCounter.linePos(pair.key.range[0]);
  const valueStart = lineCounter.linePos(pair.value.range[0]);
  const valueEnd = lineCounter.linePos(pair.value.range[1]);
  if (keyPosition.line !== valueStart.line || valueStart.line !== valueEnd.line) {
    throw new Error(`${file}:${keyPosition.line}: multi-line ${keyName} values are not supported`);
  }

  return {
    line: keyPosition.line,
    value: pair.value.value,
    comment: lineComment(lines[keyPosition.line - 1] ?? ''),
  };
}

/**
 * Parses a workflow or local action and returns its document plus every `uses`
 * mapping.
 *
 * The traversal is intentionally schema-agnostic and conservative: a `uses`
 * key in any mapping is checked. Aliases, anchors, tags, merge keys, complex
 * keys, multi-document streams, and multi-line `uses` values are rejected
 * because they can make the executable reference ambiguous.
 *
 * @param {string} text
 * @param {string} file
 * @returns {{
 *   document: import('yaml').Document,
 *   lineCounter: LineCounter,
 *   lines: string[],
 *   references: Array<{ file: string, line: number, uses: string, comment: string }>
 * }}
 */
function parsePolicySource(text, file) {
  const lineCounter = new LineCounter();
  const documents = parseAllDocuments(text, {
    lineCounter,
    prettyErrors: false,
    strict: true,
    uniqueKeys: true,
  });

  if (documents.length !== 1) {
    throw new Error(`${file}: expected exactly one YAML document`);
  }

  const document = documents[0];
  const problems = [...document.errors, ...document.warnings];
  if (problems.length > 0) {
    throw new Error(`${file}: invalid YAML: ${problems[0].message}`);
  }

  const lines = text.split(/\r?\n/);
  /** @type {Array<{ file: string, line: number, uses: string, comment: string }>} */
  const references = [];

  /** @param {unknown} node */
  function walk(node) {
    if (node === null || node === undefined) return;
    if (isAlias(node)) {
      throw new Error(`${file}: YAML aliases are not supported by the pin policy`);
    }
    if (
      typeof node === 'object' &&
      node !== null &&
      ('anchor' in node || 'tag' in node) &&
      (node.anchor || node.tag)
    ) {
      throw new Error(`${file}: YAML anchors and tags are not supported by the pin policy`);
    }
    if (isSeq(node)) {
      for (const item of node.items) walk(item);
      return;
    }
    if (!isMap(node)) return;

    for (const pair of node.items) {
      if (!isPair(pair) || !isScalar(pair.key) || typeof pair.key.value !== 'string') {
        throw new Error(`${file}: complex YAML mapping keys are not supported by the pin policy`);
      }
      if (pair.key.value === '<<') {
        throw new Error(`${file}: YAML merge keys are not supported by the pin policy`);
      }

      if (pair.key.value === 'uses') {
        const record = stringPairRecord(pair, 'uses', file, lineCounter, lines);

        references.push({
          file,
          line: record.line,
          uses: record.value,
          comment: record.comment,
        });
      }

      walk(pair.value);
    }
  }

  walk(document.contents);
  return { document, lineCounter, lines, references };
}

/**
 * Parses a workflow or local action and returns every `uses` mapping.
 *
 * @param {string} text
 * @param {string} file
 * @returns {Array<{ file: string, line: number, uses: string, comment: string }>}
 */
export function extractUses(text, file) {
  return parsePolicySource(text, file).references;
}

/**
 * Returns the external registry image declared by a local Docker action.
 *
 * Repository Dockerfiles are local code and therefore do not use the
 * `docker://` registry-reference form. External images do, and must pass the
 * same digest/comment policy as a Docker `uses:` value.
 *
 * @param {ReturnType<typeof parsePolicySource>} parsed
 * @param {string} file
 * @returns {Array<{ file: string, line: number, uses: string, comment: string }>}
 */
function extractLocalDockerImages(parsed, file) {
  const root = parsed.document.contents;
  if (!isMap(root)) return [];

  const runsPair = root.items.find(
    (pair) => isPair(pair) && isScalar(pair.key) && pair.key.value === 'runs',
  );
  if (!runsPair) return [];
  if (!isMap(runsPair.value)) {
    throw new Error(`${file}: runs must be a YAML mapping`);
  }

  const usingPair = runsPair.value.items.find(
    (pair) => isPair(pair) && isScalar(pair.key) && pair.key.value === 'using',
  );
  if (!usingPair) return [];
  const using = stringPairRecord(
    usingPair,
    'runs.using',
    file,
    parsed.lineCounter,
    parsed.lines,
  );
  if (using.value.toLowerCase() !== 'docker') return [];

  const imagePair = runsPair.value.items.find(
    (pair) => isPair(pair) && isScalar(pair.key) && pair.key.value === 'image',
  );
  if (!imagePair) {
    throw new Error(`${file}: a Docker action must declare runs.image`);
  }
  const image = stringPairRecord(
    imagePair,
    'runs.image',
    file,
    parsed.lineCounter,
    parsed.lines,
  );
  if (!image.value.startsWith('docker://')) return [];

  return [{
    file,
    line: image.line,
    uses: image.value,
    comment: image.comment,
  }];
}

/**
 * @param {Array<{ file: string, line: number, uses: string, comment: string }>} references
 * @returns {Array<{ file: string, line: number, uses: string, reason: string }>}
 */
function checkReferences(references) {
  /** @type {Array<{ file: string, line: number, uses: string, reason: string }>} */
  const violations = [];

  for (const { file, line, uses: reference, comment } of references) {
    if (reference.startsWith('./')) continue;
    const at = reference.lastIndexOf('@');
    const record = { file, line, uses: reference };

    if (reference.startsWith('docker://')) {
      if (!DOCKER_DIGEST_RE.test(reference)) {
        violations.push({ ...record, reason: 'not-digest-pinned' });
        continue;
      }
      if (comment === '') {
        violations.push({ ...record, reason: 'missing-version-comment' });
      }
      continue;
    }

    if (at === -1) {
      violations.push({ ...record, reason: 'missing-ref' });
      continue;
    }

    const ref = reference.slice(at + 1);
    if (!SHA_RE.test(ref)) {
      violations.push({ ...record, reason: 'not-sha-pinned' });
      continue;
    }

    if (comment === '') {
      violations.push({ ...record, reason: 'missing-version-comment' });
    }
  }

  return violations;
}

/**
 * @param {string} text
 * @param {string} file
 * @returns {Array<{ file: string, line: number, uses: string, reason: string }>}
 */
export function checkWorkflowSource(text, file) {
  return checkReferences(parsePolicySource(text, file).references);
}

/**
 * Checks both nested `uses:` values and `runs.image` metadata in a local action.
 *
 * @param {string} text
 * @param {string} file
 * @returns {Array<{ file: string, line: number, uses: string, reason: string }>}
 */
export function checkLocalActionSource(text, file) {
  const parsed = parsePolicySource(text, file);
  return checkReferences([
    ...parsed.references,
    ...extractLocalDockerImages(parsed, file),
  ]);
}

/**
 * Resolves `absolute` and asserts the real path stays inside `rootReal`.
 *
 * The walk refuses to follow symlinks, but a caller can still point `--root` or
 * `--dir` at a path whose *ancestors* are links. Re-checking containment on every
 * visited entry keeps the scan confined to a single real directory tree even when
 * the entry point itself was reached through a link.
 *
 * @param {string} rootReal Canonical (already realpath-resolved) scan root.
 * @param {string} absolute Path to verify.
 * @returns {string} The canonical path of `absolute`.
 */
function assertWithinRoot(rootReal, absolute) {
  let real;
  try {
    real = realpathSync.native(absolute);
  } catch (error) {
    throw new Error(
      `security-audit: cannot resolve ${absolute}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const rel = relative(rootReal, real);
  if (rel !== '' && (rel.startsWith('..') || isAbsolute(rel))) {
    throw new Error(`security-audit: path escapes the scan root: ${absolute} -> ${real}`);
  }
  return real;
}

/**
 * Recursively lists files under `dir` that satisfy `predicate`.
 *
 * Symlinks are rejected outright — both symlinked files and symlinked directories
 * cause a fail-closed throw rather than a skip. A repository that ships a link
 * into `/etc`, into another checkout, or back into itself would otherwise let the
 * pin scanner read (or loop over) content outside the audited tree, and a link
 * that shadows a local action could hide an unpinned executable reference.
 * Refusing to follow links also makes filesystem cycles unreachable; the `seen`
 * set below is belt-and-braces for hard-linked or bind-mounted directories.
 *
 * @param {string} dir
 * @param {(name: string) => boolean} predicate
 * @returns {string[]} POSIX-style paths, sorted for deterministic output.
 * @throws {Error} When a symlink, an escaping path, or a directory cycle is found.
 */
export function collectFiles(dir, predicate) {
  /** @type {string[]} */
  const found = [];

  let rootReal;
  try {
    rootReal = realpathSync.native(dir);
  } catch (error) {
    throw new Error(
      `security-audit: cannot resolve the scan root ${dir}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  /** @type {Set<string>} */
  const seen = new Set([rootReal]);

  /** @param {string} current */
  function walk(current) {
    for (const entry of readdirSync(current, { withFileTypes: true }).sort((a, b) =>
      a.name.localeCompare(b.name),
    )) {
      const full = join(current, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error(`security-audit: refusing to follow symlink: ${full}`);
      }
      if (entry.isDirectory()) {
        // Hidden directories are scanned unless explicitly named here. Local
        // actions often live in `.actions/`; skipping them wholesale would let
        // mutable nested `uses` or Docker image references bypass enforcement.
        if (SKIP_DIRS.has(entry.name)) continue;
        const real = assertWithinRoot(rootReal, full);
        if (seen.has(real)) {
          throw new Error(`security-audit: directory cycle detected at ${full}`);
        }
        seen.add(real);
        walk(full);
        continue;
      }
      // Sockets, FIFOs and device nodes are never audit inputs.
      if (!entry.isFile()) continue;
      if (predicate(entry.name)) {
        assertWithinRoot(rootReal, full);
        found.push(full.split('\\').join('/'));
      }
    }
  }

  walk(dir);
  return found.sort();
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
 * Scans local actions (`action.yml` / `action.yaml`) anywhere under `root`.
 * Composite `uses:` references and external Docker `runs.image` references are
 * both checked.
 *
 * @param {string} root
 */
export function checkLocalActions(root) {
  const files = collectFiles(root, (name) => ACTION_METADATA_NAMES.has(name));

  return files.flatMap((file) => checkLocalActionSource(readFileSync(file, 'utf8'), file));
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
    const localActionFiles = checkLocalActionPaths(root, workflowFiles);
    const localActionSet = new Set(localActionFiles);
    const workflowOnlyFiles = workflowFiles.filter((file) => !localActionSet.has(file));
    scanned = workflowOnlyFiles.length + localActionFiles.length;
    violations = [
      ...workflowOnlyFiles.flatMap((file) =>
        checkWorkflowSource(readFileSync(file, 'utf8'), file)),
      ...localActionFiles.flatMap((file) =>
        checkLocalActionSource(readFileSync(file, 'utf8'), file)),
    ];
  } catch (error) {
    process.stderr.write(`security-audit: unable to read ${dir}: ${error.message}\n`);
    process.exit(1);
    return;
  }

  if (violations.length === 0) {
    if (process.env.GITHUB_ACTIONS !== 'true') {
      process.stdout.write(
        `security-audit: all external actions are immutably pinned across ${scanned} workflow/local-action file(s)\n`,
      );
    }
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
function checkLocalActionPaths(root, alreadyScanned) {
  const files = collectFiles(root, (name) => ACTION_METADATA_NAMES.has(name));
  for (const file of alreadyScanned) {
    const name = file.slice(file.lastIndexOf('/') + 1);
    if (ACTION_METADATA_NAMES.has(name)) files.push(file);
  }
  return [...new Set(files)].sort();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
