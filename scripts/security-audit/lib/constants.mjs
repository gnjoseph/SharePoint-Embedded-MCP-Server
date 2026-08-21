/**
 * Shared, immutable configuration for the weekly repository security audit.
 *
 * Everything in this module is intentionally declarative so that the security
 * boundaries of the audit (what may be read, how much may be read, which models
 * may be used) are auditable in one place and assertable from tests.
 *
 * No runtime dependencies: Node built-ins only.
 */

import { randomBytes } from 'node:crypto';

/** Repository-relative path of the control legend used to anchor findings. */
export const CONTROL_LEGEND_PATH = 'docs/SECURITY-CONTROLS.md';

/**
 * Corpus caps. These are hard limits: `collect-corpus.mjs` refuses to emit a
 * corpus that exceeds them rather than silently truncating the security-relevant
 * tail of a file.
 */
export const CORPUS_LIMITS = Object.freeze({
  /** Maximum number of files sent to the model. */
  maxFiles: 40,
  /** Maximum bytes for any single file. Larger files are skipped, not clipped. */
  maxFileBytes: 96 * 1024,
  /** Maximum total bytes across the whole corpus. */
  maxTotalBytes: 512 * 1024,
});

/**
 * Allowlisted audit scopes. A scope maps to a set of repository-relative
 * directory prefixes; nothing outside these prefixes is ever collected.
 */
export const SCOPES = Object.freeze({
  'server-core': ['src/'],
  tools: ['src/tools/', 'src/tooling/'],
  workflows: ['.github/workflows/', 'scripts/'],
  full: ['src/', 'scripts/', '.github/workflows/'],
});

/** Default scope when `workflow_dispatch` does not supply one. */
export const DEFAULT_SCOPE = 'server-core';

/**
 * File extensions eligible for collection. Binary and lockfile-shaped content is
 * never included.
 */
export const ALLOWED_EXTENSIONS = Object.freeze(['.ts', '.mts', '.mjs', '.js', '.yml', '.yaml']);

/**
 * Paths that are never collected even when they match a scope prefix.
 * Test files dominate the corpus by volume and dilute the audit signal.
 */
export const CORPUS_DENY_PATTERNS = Object.freeze([
  /(^|\/)node_modules\//,
  /(^|\/)dist\//,
  /(^|\/)coverage\//,
  /\.test\.(ts|mts|mjs|js)$/,
  /\.d\.ts$/,
  /(^|\/)__fixtures__\//,
  /(^|\/)security-audit\/fixtures\//,
]);

/**
 * Models the workflow is permitted to request. The `workflow_dispatch` input is
 * validated against this list; anything else aborts before any credential is
 * touched.
 */
export const ALLOWED_MODELS = Object.freeze([
  'claude-opus-5',
  'claude-sonnet-4.5',
  'gpt-4.1',
  'gpt-5',
]);

/** Default model for the audit. */
export const DEFAULT_MODEL = 'claude-opus-5';

/** Accepted finding severities, ordered from most to least severe. */
export const SEVERITIES = Object.freeze(['critical', 'high', 'medium', 'low']);

/** Accepted finding confidences. */
export const CONFIDENCES = Object.freeze(['high', 'medium', 'low']);

/** Accepted finding categories. */
export const CATEGORIES = Object.freeze([
  'injection',
  'prompt-injection',
  'authz',
  'authn',
  'secret-exposure',
  'path-traversal',
  'ssrf',
  'unsafe-deserialization',
  'error-leakage',
  'supply-chain',
  'crypto',
  'denial-of-service',
  'logic',
]);

/**
 * Literal used when a finding does not map to an existing control in
 * `docs/SECURITY-CONTROLS.md`. Anything else must match a documented code.
 */
export const UNMAPPED_CONTROL = 'UNMAPPED';

/** Maximum number of findings accepted from a single model response. */
export const MAX_FINDINGS = 50;

/** Maximum characters accepted for any single free-text finding field. */
export const MAX_FIELD_CHARS = 1200;

/**
 * Sentinel token embedded in every corpus fence.
 *
 * The token alone is NOT a security boundary: it is a fixed string that lives in
 * this file, which is itself inside the `workflows` and `full` scopes, so any
 * attacker (and this repository's own source) can reproduce it verbatim. The
 * boundary is the per-run nonce appended to it — see `generateCorpusNonce()`.
 */
export const DELIMITER_SENTINEL = 'SPE_AUDIT_UNTRUSTED_FILE';

/** Replacement written over any sentinel literal found inside collected content. */
export const DELIMITER_NEUTRALIZED = 'SPE_AUDIT_NEUTRALIZED_MARKER';

/** Number of random bytes backing a corpus nonce (48 hex characters). */
export const CORPUS_NONCE_BYTES = 24;

/**
 * Generate a fresh, unguessable delimiter nonce for a single audit run.
 *
 * Rationale: a static fence can be forged by any file that happens to contain
 * the literal — including this repository's own constants file. A per-run
 * nonce cannot be present in repository content, so a collected file is
 * incapable of closing the fence around itself or opening a new one.
 */
export function generateCorpusNonce() {
  return randomBytes(CORPUS_NONCE_BYTES).toString('hex');
}

/**
 * Build the begin/end fence for a given run nonce.
 *
 * @param {string} nonce Hex nonce from `generateCorpusNonce()`.
 * @returns {{ nonce: string, begin: string, end: string }}
 */
export function corpusDelimiters(nonce) {
  if (typeof nonce !== 'string' || !/^[0-9a-f]{16,}$/.test(nonce)) {
    throw new TypeError('corpusDelimiters requires a hex nonce of at least 16 characters');
  }
  return Object.freeze({
    nonce,
    begin: `<<<${DELIMITER_SENTINEL}_BEGIN:${nonce}>>>`,
    end: `<<<${DELIMITER_SENTINEL}_END:${nonce}>>>`,
  });
}

/**
 * Neutralize every sentinel literal inside untrusted content.
 *
 * Collected files may legitimately contain the sentinel (this file does). They
 * are escaped rather than rejected so that the `workflows` and `full` scopes
 * remain auditable, while the emitted corpus can never contain a string that
 * looks like a fence.
 *
 * @param {string} text Untrusted file content.
 * @returns {{ value: string, neutralized: number }}
 */
export function neutralizeDelimiters(text) {
  const pattern = new RegExp(DELIMITER_SENTINEL, 'g');
  const matches = String(text).match(pattern);
  if (!matches) {
    return { value: String(text), neutralized: 0 };
  }
  return {
    value: String(text).replace(pattern, DELIMITER_NEUTRALIZED),
    neutralized: matches.length,
  };
}

/** SARIF tool driver name, surfaced in code scanning. */
export const TOOL_NAME = 'SPE MCP Security Audit';

/** SARIF tool driver information URI. */
export const TOOL_URI =
  'https://github.com/microsoft/SharePoint-Embedded-MCP-Server/blob/main/docs/SECURITY-AUDIT.md';

/** Status literals emitted by the audit; asserted by tests and the summary job. */
export const STATUS = Object.freeze({
  notConfigured: 'AI NOT_CONFIGURED',
  dryRun: 'AI DRY_RUN',
  completed: 'AI COMPLETED',
  failed: 'AI FAILED',
});
