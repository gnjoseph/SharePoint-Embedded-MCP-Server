// Structural invariants for the security-audit workflow.
//
// These assertions encode the threat model, not style preferences: each one
// corresponds to a way the workflow could be turned into an attack primitive if
// it were edited carelessly.
import { strict as assert } from 'node:assert';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

import { parseYaml } from '../lib/mini-yaml.mjs';
import { ALLOWED_MODELS, DEFAULT_MODEL, SCOPES } from '../lib/constants.mjs';

const REPO_ROOT = path.resolve(import.meta.dirname, '..', '..', '..');
const WORKFLOW_DIR = path.join(REPO_ROOT, '.github', 'workflows');
const AUDIT_WORKFLOW = path.join(WORKFLOW_DIR, 'security-audit.yml');

// Comments are allowed to name a construct in order to explain why it is
// absent; only executable lines are checked for the dangerous constructs.
function stripComments(raw) {
  return raw
    .split(/\r?\n/)
    .filter((line) => !/^\s*#/.test(line))
    .join('\n');
}

function readWorkflow(file) {
  const raw = readFileSync(file, 'utf8');
  return { raw, code: stripComments(raw), doc: parseYaml(raw, path.basename(file)) };
}

const audit = readWorkflow(AUDIT_WORKFLOW);

test('audit workflow has no pull request triggers', () => {
  const triggers = Object.keys(audit.doc.on);
  assert.deepEqual(triggers.sort(), ['schedule', 'workflow_dispatch']);
  assert.equal(triggers.includes('pull_request'), false);
  assert.equal(triggers.includes('pull_request_target'), false);
  assert.equal(triggers.includes('issue_comment'), false);
  assert.equal(triggers.includes('fork'), false);
});

test('audit workflow runs weekly on Monday', () => {
  const schedules = audit.doc.on.schedule;
  assert.equal(Array.isArray(schedules), true);
  assert.equal(schedules.length, 1);
  const cron = schedules[0].cron;
  const dayOfWeek = cron.trim().split(/\s+/)[4];
  assert.equal(dayOfWeek, '1');
});

test('audit workflow denies all permissions at workflow level', () => {
  assert.deepEqual(audit.doc.permissions, {});
});

test('audit workflow grants no write permission other than security-events', () => {
  for (const [name, job] of Object.entries(audit.doc.jobs)) {
    assert.ok(job.permissions, `job ${name} must declare explicit permissions`);
    for (const [scope, level] of Object.entries(job.permissions)) {
      if (level !== 'write') continue;
      assert.equal(
        scope,
        'security-events',
        `job ${name} must not request ${scope}: write`,
      );
    }
  }
});

test('audit workflow never requests issue or pull-request permissions', () => {
  for (const [name, job] of Object.entries(audit.doc.jobs)) {
    for (const scope of Object.keys(job.permissions ?? {})) {
      assert.notEqual(scope, 'issues', `job ${name} must not touch issues`);
      assert.notEqual(
        scope,
        'pull-requests',
        `job ${name} must not touch pull requests`,
      );
    }
  }
});

test('audit workflow creates no issues, comments or discussions', () => {
  const forbidden = [
    'issues.create',
    'createComment',
    'create-issue',
    'gh issue create',
    'gh pr comment',
    'gh api /repos/.*/issues',
    'peter-evans/create-issue',
  ];
  for (const needle of forbidden) {
    assert.equal(
      new RegExp(needle).test(audit.raw),
      false,
      `workflow must not contain ${needle}`,
    );
  }
});

test('every job declares a timeout and the workflow declares concurrency', () => {
  assert.ok(audit.doc.concurrency, 'workflow must declare concurrency');
  assert.equal(audit.doc.concurrency['cancel-in-progress'], 'false');
  for (const [name, job] of Object.entries(audit.doc.jobs)) {
    assert.ok(
      job['timeout-minutes'],
      `job ${name} must declare timeout-minutes`,
    );
  }
});

test('manual inputs are constrained to allowlists', () => {
  const inputs = audit.doc.on.workflow_dispatch.inputs;
  assert.deepEqual(inputs.model.options.sort(), [...ALLOWED_MODELS].sort());
  assert.equal(inputs.model.default, DEFAULT_MODEL);
  assert.deepEqual(inputs.scope.options.sort(), Object.keys(SCOPES).sort());
  assert.equal(inputs.dry_run.type, 'boolean');
  assert.equal(inputs.dry_run.default, 'false');
});

test('all workflow actions are pinned to 40-hex commit SHAs', () => {
  const files = readdirSync(WORKFLOW_DIR).filter((f) => /\.ya?ml$/.test(f));
  assert.ok(files.length >= 3, 'expected the repo workflows to be present');
  for (const file of files) {
    const raw = readFileSync(path.join(WORKFLOW_DIR, file), 'utf8');
    const lines = raw.split(/\r?\n/);
    lines.forEach((line, index) => {
      const match = /^\s*(?:-\s+)?uses:\s*(\S+)/.exec(line);
      if (!match) return;
      const ref = match[1].replace(/^['"]|['"]$/g, '');
      if (ref.startsWith('./') || ref.startsWith('docker://')) return;
      const at = ref.lastIndexOf('@');
      assert.notEqual(at, -1, `${file}:${index + 1} action has no ref`);
      assert.match(
        ref.slice(at + 1),
        /^[0-9a-f]{40}$/,
        `${file}:${index + 1} action ${ref} must be SHA-pinned`,
      );
    });
  }
});

test('model output is never interpolated into a shell command', () => {
  // `${{ }}` is substituted before bash sees the script, so referencing a model
  // response inside `run:` is remote code execution on the runner.
  assert.equal(
    /\$\{\{\s*steps\.[A-Za-z0-9_-]*\.outputs\.response\s*\}\}/.test(audit.raw),
    false,
    'model response must be passed by file path via env, never inlined',
  );
  assert.match(
    audit.raw,
    /RESPONSE_FILE:\s*\$\{\{\s*steps\.[A-Za-z0-9_-]+\.outputs\.response-file\s*\}\}/,
  );
});

test('the model job is gated, environment-protected and tool-less', () => {
  const job = audit.doc.jobs['model-audit'];
  assert.match(job.if, /vars\.SECURITY_AUDIT_AI_ENABLED == 'true'/);
  assert.equal(job.environment, 'security-audit-ai');
  assert.equal(
    /copilot-allow-tools/.test(audit.code),
    false,
    'allowing tools would give the model shell access',
  );
  assert.equal(/--allow-all-tools/.test(audit.code), false);
});

test('the dry-run job holds no secret and never uploads to code scanning', () => {
  const job = audit.doc.jobs['model-audit-dry-run'];
  assert.deepEqual(job.permissions, { contents: 'read' });
  assert.equal(job.environment, undefined);
  const rendered = JSON.stringify(job);
  assert.equal(/COPILOT_PAT/.test(rendered), false);
  assert.equal(/upload-sarif/.test(rendered), false);
});

test('dependency install in the audit path never runs repository scripts', () => {
  const installs = audit.raw.match(/npm (?:ci|install)[^\n]*/g) ?? [];
  for (const line of installs) {
    if (line.includes('--global') || line.includes('-g ')) continue;
    assert.match(
      line,
      /--ignore-scripts/,
      `install without --ignore-scripts executes repository lifecycle code: ${line}`,
    );
  }
});

test('no workflow enables the reachability test-mode escape hatch', () => {
  // `SECURITY_AUDIT_TEST_MODE=1` skips the reachable-from-main check. It exists
  // solely for offline unit tests and must never appear in a workflow.
  const files = readdirSync(WORKFLOW_DIR).filter((f) => /\.ya?ml$/.test(f));
  for (const file of files) {
    const raw = readFileSync(path.join(WORKFLOW_DIR, file), 'utf8');
    assert.ok(
      !raw.includes('SECURITY_AUDIT_TEST_MODE'),
      `${file}: workflows must not disable the reachability gate`,
    );
  }
});

test('checkouts do not persist credentials', () => {
  const files = readdirSync(WORKFLOW_DIR).filter((f) => /\.ya?ml$/.test(f));
  for (const file of files) {
    const raw = readFileSync(path.join(WORKFLOW_DIR, file), 'utf8');
    const checkouts = (raw.match(/uses:\s*actions\/checkout@/g) ?? []).length;
    const disabled = (raw.match(/persist-credentials:\s*false/g) ?? []).length;
    assert.equal(
      disabled,
      checkouts,
      `${file}: every checkout must set persist-credentials: false`,
    );
  }
});

test('every continue-on-error step is re-raised by an explicit failure gate', () => {
  // continue-on-error is legitimate when a scanner's findings must be
  // sanitized before the job fails, but only if the outcome is re-raised.
  // Without that gate it is exactly the no-op pattern this change removes.
  const files = readdirSync(WORKFLOW_DIR).filter((f) => /\.ya?ml$/.test(f));
  for (const file of files) {
    const { raw, code, doc } = readWorkflow(path.join(WORKFLOW_DIR, file));
    for (const [jobName, job] of Object.entries(doc.jobs ?? {})) {
      for (const step of job.steps ?? []) {
        if (step['continue-on-error'] !== 'true') continue;
        assert.ok(
          step.id,
          `${file}/${jobName}: continue-on-error step needs an id`,
        );
        assert.match(
          raw,
          new RegExp(`steps\\.${step.id}\\.outcome == 'failure'`),
          `${file}/${jobName}: step ${step.id} tolerates failure but never re-raises it`,
        );
      }
    }
    assert.equal(
      /continue-on-error:\s*true[\s\S]*?\n\s*-\s+name:[\s\S]*$/.test(code) &&
        !/outcome == 'failure'/.test(code),
      false,
    );
  }
});

test('the legacy no-op gitleaks gate is gone from the security workflow', () => {
  const raw = readFileSync(path.join(WORKFLOW_DIR, 'security.yml'), 'utf8');
  const code = stripComments(raw);
  assert.equal(
    /GITLEAKS_LICENSE/.test(code),
    false,
    'the licence gate made the job unconditionally green',
  );
  assert.equal(/gitleaks\/gitleaks-action/.test(code), false);
  assert.match(code, /sha256sum --check --strict/);
  assert.match(code, /exit "\$\{status\}"/);
});
