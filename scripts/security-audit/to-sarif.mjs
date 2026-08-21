#!/usr/bin/env node
/**
 * Converts a sanitized findings report into SARIF 2.1.0.
 *
 * Only the sanitized report produced by `validate-response.mjs` is accepted as
 * input; raw model output is never converted. Rule metadata is derived from the
 * finding category so that code scanning groups results sensibly.
 *
 * Usage:
 *   node scripts/security-audit/to-sarif.mjs --report <file> --out <file> [--synthetic]
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { SEVERITIES, TOOL_NAME, TOOL_URI } from './lib/constants.mjs';

/** Maps finding severity to a SARIF `level`. */
const SARIF_LEVEL = Object.freeze({
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
});

/** Maps finding severity to a `security-severity` score for code scanning. */
const SECURITY_SEVERITY = Object.freeze({
  critical: '9.5',
  high: '7.5',
  medium: '5.0',
  low: '2.0',
});

// The severity vocabulary lives in lib/constants.mjs and is enforced by
// validate-response.mjs. These two maps must cover it exactly. Without this
// assertion a new severity would silently degrade to `warning` here and lose
// its security-severity score, so the drift is made fatal at module load
// rather than discovered in a SARIF upload.
for (const severity of SEVERITIES) {
  if (!(severity in SARIF_LEVEL) || !(severity in SECURITY_SEVERITY)) {
    throw new Error(
      `to-sarif.mjs is out of sync with SEVERITIES: no mapping for "${severity}". ` +
        'Add it to SARIF_LEVEL and SECURITY_SEVERITY.',
    );
  }
}

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
 * @param {{ findings: Array<Record<string, unknown>> }} report
 * @param {{ synthetic?: boolean }} [options]
 */
export function toSarif(report, options = {}) {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  const categories = [...new Set(findings.map((f) => String(f.category)))].sort();

  const rules = categories.map((category) => ({
    id: `spe-audit/${category}`,
    name: category.replace(/(^|-)([a-z])/g, (_, sep, ch) => (sep ? '' : '') + ch.toUpperCase()),
    shortDescription: { text: `Model-identified ${category} risk` },
    fullDescription: {
      text:
        `Potential ${category} weakness reported by the scheduled security audit. ` +
        'Findings are advisory and require human triage before action.',
    },
    defaultConfiguration: { level: 'warning' },
    properties: {
      tags: ['security', 'ai-assisted', category],
      precision: 'medium',
    },
  }));

  const results = findings.map((finding) => {
    const severity = String(finding.severity);
    // validate-response.mjs rejects any severity outside SEVERITIES before a
    // report reaches this converter, and the module-load assertion above
    // guarantees every SEVERITIES entry is mapped. An unmapped severity here
    // means the sanitized report was not produced by the validator, so fail
    // closed rather than downgrade it to a warning.
    if (!(severity in SARIF_LEVEL)) {
      throw new Error(`Unmapped finding severity "${severity}" in sanitized report.`);
    }
    return {
      ruleId: `spe-audit/${finding.category}`,
      ruleIndex: categories.indexOf(String(finding.category)),
      level: SARIF_LEVEL[severity],
      message: {
        text: [
          String(finding.title),
          String(finding.detail),
          `Control: ${finding.control}`,
          `Confidence: ${finding.confidence}`,
          `Remediation: ${finding.remediation}`,
          `Suggested test: ${finding.test}`,
        ].join('\n\n'),
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: String(finding.file), uriBaseId: '%SRCROOT%' },
            region: { startLine: Number(finding.line) },
          },
        },
      ],
      properties: {
        'security-severity': SECURITY_SEVERITY[severity],
        confidence: finding.confidence,
        control: finding.control,
        synthetic: Boolean(options.synthetic),
      },
    };
  });

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            informationUri: TOOL_URI,
            semanticVersion: '1.0.0',
            rules,
          },
        },
        properties: {
          synthetic: Boolean(options.synthetic),
          acceptedCount: report?.acceptedCount ?? findings.length,
          rejectedCount: report?.rejectedCount ?? 0,
        },
        results,
      },
    ],
  };
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.report || !args.out) {
    process.stderr.write('usage: to-sarif.mjs --report <file> --out <file> [--synthetic]\n');
    process.exit(1);
  }

  const report = JSON.parse(readFileSync(args.report, 'utf8'));
  const sarif = toSarif(report, { synthetic: args.synthetic === 'true' });
  writeFileSync(args.out, `${JSON.stringify(sarif, null, 2)}\n`, 'utf8');
  process.stdout.write(`security-audit: wrote ${sarif.runs[0].results.length} SARIF result(s)\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
