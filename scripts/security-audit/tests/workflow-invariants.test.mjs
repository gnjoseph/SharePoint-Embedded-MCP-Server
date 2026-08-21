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

// ---------------------------------------------------------------------------
// Controller / target separation.
//
// The commit under audit is untrusted input. Helper scripts must always come
// from the protected default branch (the workflow's own event SHA), and the
// audited tree must always land in `target/`. Checking out the target over the
// workspace root would both execute attacker-controlled scripts and break for
// any historical commit that predates `scripts/security-audit/`.
// ---------------------------------------------------------------------------

// Jobs that execute a helper script from `scripts/security-audit/` and also
// need the audited tree present.
const CONTROLLER_JOBS = [
  'dependency-audit',
  'secret-scan',
  'action-pins',
  'model-audit',
  'model-audit-dry-run',
];

function checkoutSteps(job) {
  return (job.steps ?? []).filter((step) =>
    /^actions\/checkout@/.test(step.uses ?? ''),
  );
}

test('jobs that run helper scripts check out the controller before the target', () => {
  for (const name of CONTROLLER_JOBS) {
    const job = audit.doc.jobs[name];
    assert.ok(job, `job ${name} must exist`);
    const checkouts = checkoutSteps(job);
    assert.equal(
      checkouts.length,
      2,
      `job ${name} must check out the controller and the target separately`,
    );

    const [controller, target] = checkouts;
    assert.equal(
      controller.with.ref,
      undefined,
      `job ${name}: the controller checkout must not override ref (it must stay on the protected default branch)`,
    );
    assert.equal(
      controller.with.path,
      undefined,
      `job ${name}: the controller checkout must land at the workspace root`,
    );
    assert.equal(controller.with['persist-credentials'], 'false');

    assert.equal(
      target.with.path,
      'target',
      `job ${name}: the audited tree must be isolated in target/`,
    );
    assert.match(
      target.with.ref,
      /needs\.validate-inputs\.outputs\.target_sha/,
      `job ${name}: the target checkout must use the validated target SHA`,
    );
    assert.equal(target.with['persist-credentials'], 'false');

    assert.ok(
      (job.steps ?? []).indexOf(controller) < (job.steps ?? []).indexOf(target),
      `job ${name}: the controller checkout must run first — actions/checkout runs git clean -ffdx in its destination`,
    );
  }
});

test('the CodeQL job checks out the target only and analyses target/', () => {
  const job = audit.doc.jobs.codeql;
  const checkouts = checkoutSteps(job);
  assert.equal(checkouts.length, 1, 'CodeQL runs no helper script');
  assert.equal(checkouts[0].with.path, 'target');

  const init = job.steps.find((step) =>
    /codeql-action\/init@/.test(step.uses ?? ''),
  );
  assert.equal(
    init.with['source-root'],
    'target',
    'CodeQL must analyse the audited tree, not the controller checkout',
  );
});

test('no helper script is ever executed from the target checkout', () => {
  // Helper scripts are trusted controller code. Running `node target/...`
  // would execute code from the commit under audit.
  assert.equal(
    /node\s+target\//.test(audit.code),
    false,
    'helper scripts must be invoked from the controller checkout',
  );
  assert.equal(
    /working-directory:\s*target\/scripts/.test(audit.code),
    false,
    'helper scripts must not run with the audited tree as their working directory',
  );
  const invocations = audit.code.match(/node\s+\S*scripts\/security-audit\/\S+/g) ?? [];
  assert.ok(invocations.length > 0, 'expected helper script invocations');
  for (const invocation of invocations) {
    assert.match(
      invocation,
      /node\s+scripts\/security-audit\//,
      `helper invocations must be controller-relative: ${invocation}`,
    );
  }
});

test('npm operations against the audited tree are confined to target/', () => {
  const job = audit.doc.jobs['dependency-audit'];
  const npmSteps = (job.steps ?? []).filter((step) =>
    /^\s*npm (?:ci|audit)\b/m.test(step.run ?? ''),
  );
  assert.ok(npmSteps.length >= 2, 'expected npm ci and npm audit steps');
  for (const step of npmSteps) {
    assert.equal(
      step['working-directory'],
      'target',
      `npm step "${step.name}" must operate on the audited tree`,
    );
  }
  // setup-node's dependency cache keys off the workspace root lockfile, which
  // now belongs to the controller rather than the audited commit.
  const setupNode = (job.steps ?? []).find((step) =>
    /actions\/setup-node@/.test(step.uses ?? ''),
  );
  assert.equal(
    setupNode.with.cache,
    undefined,
    'setup-node caching would key off the controller lockfile, not the audited one',
  );
});

// ---------------------------------------------------------------------------
// SARIF attribution.
//
// Without explicit ref/sha, code scanning attributes findings to the event SHA
// (current main tip) even when an older commit was analysed. `sha` must be the
// HEAD of `ref`, so historical audits cannot be represented safely and are not
// uploaded at all.
// ---------------------------------------------------------------------------

test('CodeQL results carry an explicit target ref, sha and checkout path', () => {
  const analyze = audit.doc.jobs.codeql.steps.find((step) =>
    /codeql-action\/analyze@/.test(step.uses ?? ''),
  );
  assert.match(analyze.with.ref, /needs\.validate-inputs\.outputs\.target_ref/);
  assert.match(analyze.with.sha, /needs\.validate-inputs\.outputs\.target_sha/);
  assert.match(analyze.with.checkout_path, /github\.workspace.*target/);
  assert.match(
    analyze.with.upload,
    /is_main_tip == 'true'/,
    'uploads must be suppressed when the target is not the current main tip',
  );
});

test('model SARIF upload is attributed to the target and gated on main tip', () => {
  const job = audit.doc.jobs['model-audit'];
  const upload = (job.steps ?? []).find((step) =>
    /codeql-action\/upload-sarif@/.test(step.uses ?? ''),
  );
  assert.ok(upload, 'the model job must upload through code scanning');
  assert.match(upload.if, /is_main_tip == 'true'/);
  assert.match(upload.with.ref, /needs\.validate-inputs\.outputs\.target_ref/);
  assert.match(upload.with.sha, /needs\.validate-inputs\.outputs\.target_sha/);
  assert.match(upload.with.checkout_path, /github\.workspace.*target/);

  // Findings for a historical target must fail closed rather than be published
  // (public repository: no raw-findings artifact) or mis-attributed.
  const fallback = (job.steps ?? []).find(
    (step) => /is_main_tip != 'true'/.test(step.if ?? ''),
  );
  assert.ok(fallback, 'historical targets need an explicit fail-closed path');
  assert.match(fallback.run, /exit 1/);
});

test('validate-inputs publishes the outputs the attribution gates depend on', () => {
  const outputs = audit.doc.jobs['validate-inputs'].outputs;
  for (const key of ['target_sha', 'target_ref', 'is_main_tip']) {
    assert.ok(outputs[key], `validate-inputs must publish ${key}`);
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

// The model job ships repository source to an external provider. Running it
// before the secret scanner has passed would mean a freshly committed
// credential is egressed to the provider before anyone knows it exists, so the
// dependency edge is part of the security contract rather than an ordering
// preference.
test('the model job cannot run before the secret scan succeeds', () => {
  const needs = audit.doc.jobs['model-audit'].needs;
  assert.ok(Array.isArray(needs), 'model-audit needs must be a list');
  assert.ok(
    needs.includes('validate-inputs'),
    'model-audit consumes validate-inputs outputs',
  );
  assert.ok(
    needs.includes('secret-scan'),
    'no source may reach the provider before the secret scan passes',
  );
});

// Secret-scan output is the one artifact that can disclose an unrotated
// credential's location. Everything published outside the job log must be
// counts only: a rule identifier paired with a file path tells a reader which
// file holds which credential class, which is pre-rotation disclosure.
test('the secret-scan job publishes counts only and deletes the raw report first', () => {
  const steps = audit.doc.jobs['secret-scan'].steps;
  const sanitizeIndex = steps.findIndex(
    (step) => typeof step.run === 'string' && /rm -f \.security-audit\/gitleaks\.json/.test(step.run),
  );
  const uploadIndex = steps.findIndex(
    (step) => typeof step.uses === 'string' && step.uses.startsWith('actions/upload-artifact@'),
  );
  assert.ok(sanitizeIndex >= 0, 'the raw gitleaks report must be deleted in-job');
  assert.ok(uploadIndex >= 0, 'the sanitized summary is uploaded');
  assert.ok(
    sanitizeIndex < uploadIndex,
    'the raw report must be gone before any upload step runs',
  );

  const uploadPath = steps[uploadIndex].with.path;
  assert.equal(uploadPath, '.security-audit/gitleaks-summary.json');
  assert.equal(
    /gitleaks\.json$/.test(uploadPath),
    false,
    'the raw report must never be uploaded',
  );

  for (const step of steps) {
    if (typeof step.run !== 'string') continue;
    assert.equal(
      /gitleaks\.json"? >> "?\$\{?GITHUB_STEP_SUMMARY/.test(step.run),
      false,
      'the raw report must never reach the public job summary',
    );
  }
});

// `npm install -g <pkg>@<version>` still resolves ranged transitive
// dependencies at install time, so the installed tree is not reproducible.
// The tool is installed from a committed manifest instead, and the job fails
// closed when the accompanying lockfile has not been provisioned.
test('the Copilot CLI is installed reproducibly from a committed manifest', () => {
  const code = audit.code;
  assert.equal(
    /npm install -g/.test(code),
    false,
    'a global ranged install is not reproducible',
  );
  assert.match(code, /npm ci --ignore-scripts/);
  assert.match(code, /if \[ ! -f tools\/copilot-cli\/package-lock\.json \]/);
  assert.match(code, /exit 1/);

  const inference = audit.doc.jobs['model-audit'].steps.find(
    (step) => typeof step.uses === 'string' && step.uses.startsWith('actions/ai-inference@'),
  );
  assert.ok(inference, 'the model job runs the inference action');
  assert.equal(
    inference.with['copilot-cli-path'],
    'tools/copilot-cli/node_modules/.bin/copilot',
  );

  const manifest = JSON.parse(
    readFileSync(path.join(REPO_ROOT, 'tools', 'copilot-cli', 'package.json'), 'utf8'),
  );
  assert.equal(manifest.private, true, 'the tool manifest must never be published');
  const pin = manifest.dependencies['@github/copilot'];
  assert.match(pin, /^\d+\.\d+\.\d+/, 'the Copilot CLI must be pinned to an exact version');
});
