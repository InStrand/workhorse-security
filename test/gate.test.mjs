// The gate, end to end, with the pinned scanners on throwaway repositories. The cases that
// matter most are the planted negatives: a change that tries to excuse or hide itself must
// still be stopped, and a scanner that fails must never read as a pass.
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { main } from '../lib/cli.mjs';
import { FINGERPRINT_KEY } from '../lib/findings.mjs';
import { loadRegistry } from '../lib/registry.mjs';
import { gateChange } from '../lib/scan.mjs';
import { PACK_ROOT, UsageError, must } from '../lib/util.mjs';
import { DEFINER_WITHOUT_PATH, GRANT_TO_ANON, TOKEN, commit, makeRepo, remove, scratch } from './helpers.mjs';

const registry = loadRegistry();
const dirs = [];
after(() => dirs.forEach(remove));

function fixture(files) {
  const repo = makeRepo();
  const out = scratch('out');
  dirs.push(repo, out);
  return { repo, out, base: commit(repo, files, 'base') };
}

const gate = ({ repo, out }, base, head) => gateChange(registry, repo, base, head, out).summary;
const blocking = (summary, id) => summary.checks.find((check) => check.check === id).blocking;

test('a finding that was already there does not stop an unrelated change', () => {
  const f = fixture({ 'db/001.sql': DEFINER_WITHOUT_PATH });
  const head = commit(f.repo, { 'README.md': 'hello\n', 'db/000_new_first.sql': '-- a comment that moves nothing\n' });
  const summary = gate(f, f.base, head);
  assert.equal(summary.outcome, 'pass');
  assert.equal(summary.checks.find((check) => check.check === 'semgrep').unchanged, 1);
});

test('a finding moved by unrelated edits keeps its identity', () => {
  const f = fixture({ 'db/001.sql': DEFINER_WITHOUT_PATH });
  const head = commit(f.repo, { 'db/001.sql': `-- header added\n\n\n${DEFINER_WITHOUT_PATH}` });
  assert.equal(gate(f, f.base, head).outcome, 'pass');
});

test('a finding the change adds stops it, and the report carries its identity and state', () => {
  const f = fixture({ 'db/001.sql': DEFINER_WITHOUT_PATH });
  const head = commit(f.repo, { 'db/002.sql': GRANT_TO_ANON });
  const summary = gate(f, f.base, head);
  assert.equal(summary.outcome, 'findings');
  assert.equal(blocking(summary, 'semgrep'), 1);
  const results = JSON.parse(readFileSync(join(f.out, 'scan.sarif'), 'utf8')).runs.flatMap((run) => run.results);
  assert.deepEqual(results.map((result) => result.baselineState).sort(), ['new', 'unchanged']);
  assert.ok(results.every((result) => /^[0-9a-f]{64}$/.test(result.partialFingerprints[FINGERPRINT_KEY])));
});

test('the output holds only the record, in the pack\'s rule names, with no path of this machine', () => {
  const f = fixture({ 'db/001.sql': DEFINER_WITHOUT_PATH });
  const head = commit(f.repo, { 'db/002.sql': GRANT_TO_ANON, '.github/workflows/ci.yml': 'on: pull_request_target\njobs: {}\n', 'deploy/.env': `GITHUB_TOKEN=${TOKEN}\n` });
  assert.equal(gate(f, f.base, head).outcome, 'findings');
  assert.deepEqual(readdirSync(f.out).sort(), ['scan.sarif', 'summary.json'], 'what each tool wrote is not kept');
  const text = readFileSync(join(f.out, 'scan.sarif'), 'utf8');
  const runs = JSON.parse(text).runs;
  assert.equal(runs.length, 3);
  const ids = runs.flatMap((run) => [...run.results.map((result) => result.ruleId), ...run.tool.driver.rules.map((rule) => rule.id)]);
  for (const id of ['postgres-grant-to-anon', 'dangerous-triggers', 'github-pat']) assert.ok(ids.includes(id), `${id} is named as the pack names it`);
  assert.deepEqual(ids.filter((id) => !/^[a-z0-9-]+$/.test(id)), []);
  for (const local of [PACK_ROOT, PACK_ROOT.slice(1).split('/').join('.'), f.repo, tmpdir()]) assert.ok(!text.includes(local), `the report holds ${local}`);
});

test('removing the protection from an untouched definition is a new finding', () => {
  const safe = DEFINER_WITHOUT_PATH.replace('security definer as', "security definer set search_path = '' as");
  const f = fixture({ 'db/001.sql': safe });
  assert.equal(gate(f, f.base, commit(f.repo, { 'README.md': 'x\n' })).outcome, 'pass');
  const head = commit(f.repo, { 'db/001.sql': DEFINER_WITHOUT_PATH });
  assert.equal(blocking(gate(f, f.base, head), 'semgrep'), 1);
});

test('a change cannot excuse itself: exceptions are read from the base revision', () => {
  const exception = { schema: 1, exceptions: [{ paths: ['db/'], reason: 'reviewed', owner: 'someone' }] };
  const f = fixture({ 'README.md': 'x\n' });
  const selfExcused = commit(f.repo, { 'db/002.sql': GRANT_TO_ANON, 'security/config.json': JSON.stringify(exception) });
  assert.equal(gate(f, f.base, selfExcused).outcome, 'findings');
  // Once the exception is in the base revision, the same kind of change is accepted and counted.
  const next = commit(f.repo, { 'db/003.sql': GRANT_TO_ANON.replace('accounts', 'orders') });
  const summary = gate(f, selfExcused, next);
  assert.equal(summary.outcome, 'pass');
  assert.equal(summary.checks.find((check) => check.check === 'semgrep').excepted, 2);
});

test('a config kept outside the repository is the whole config: no revision of the repository adds to it', () => {
  const owner = { reason: 'reviewed', owner: 'someone' };
  const f = fixture({ 'README.md': 'x\n' });
  const outside = join(scratch('config'), 'config.json');
  dirs.push(join(outside, '..'));
  writeFileSync(outside, JSON.stringify({ schema: 1, exceptions: [{ paths: ['db/'], ...owner }] }));
  const withFile = (base, head) => gateChange(registry, f.repo, base, head, f.out, outside).summary;
  const head = commit(f.repo, { 'db/002.sql': GRANT_TO_ANON });
  assert.equal(gate(f, f.base, head).outcome, 'findings', 'without the file nothing excepts db/');
  assert.equal(withFile(f.base, head).outcome, 'pass');
  // The head brings its own config, which excepts src/. The file outside does not.
  const inRepo = JSON.stringify({ schema: 1, exceptions: [{ paths: ['src/'], ...owner }] });
  const selfExcused = commit(f.repo, { 'src/003.sql': GRANT_TO_ANON.replace('accounts', 'orders'), 'security/config.json': inRepo });
  for (const summary of [withFile(head, selfExcused), withFile(undefined, selfExcused)]) {
    assert.equal(summary.outcome, 'findings', 'not with a base, and not on a first push, where the head would otherwise supply the config');
    assert.equal(blocking(summary, 'semgrep'), 1);
  }
  // Once that config is the base revision's, it still adds nothing to the file.
  const next = commit(f.repo, { 'src/004.sql': GRANT_TO_ANON.replace('accounts', 'invoices') });
  assert.equal(blocking(withFile(selfExcused, next), 'semgrep'), 1);
});

test('a file name that decodes to an excepted path is not excepted', () => {
  const exception = { schema: 1, exceptions: [{ paths: ['fixtures/'], reason: 'known cases', owner: 'someone' }] };
  const f = fixture({ 'README.md': 'x\n', 'security/config.json': JSON.stringify(exception), 'fixtures/known.sql': GRANT_TO_ANON });
  // Neither file is under fixtures/. Each has "%2F", which decodes to "/", in its own name.
  const head = commit(f.repo, { 'fixtures%2Fgrant.sql': GRANT_TO_ANON.replace('accounts', 'orders'), 'fixtures%2Ftoken.env': `GITHUB_TOKEN=${TOKEN}\n` });
  const summary = gate(f, f.base, head);
  assert.equal(summary.outcome, 'findings');
  assert.equal(blocking(summary, 'semgrep'), 1);
  assert.equal(blocking(summary, 'gitleaks'), 1);
  assert.equal(summary.checks.find((check) => check.check === 'semgrep').excepted, 1, 'the file that is under fixtures/ is still excepted');
});

test('a base that was named and is not a commit stops the gate, so the head cannot supply the exceptions', async (t) => {
  const exception = { schema: 1, exceptions: [{ paths: ['db/'], reason: 'reviewed', owner: 'someone' }] };
  const f = fixture({ 'README.md': 'x\n' });
  const selfExcused = commit(f.repo, { 'db/002.sql': GRANT_TO_ANON, 'security/config.json': JSON.stringify(exception) });
  for (const bogus of ['1234567890abcdef1234567890abcdef12345678', 'no-such-branch']) {
    assert.throws(() => gate(f, bogus, selfExcused), (error) => error instanceof UsageError && error.message.includes(`"${bogus}" is not a commit`));
  }
  // From the command line the same change exits 2 and the message names the ref.
  const errors = t.mock.method(console, 'error', () => {});
  assert.equal(await main(['gate', f.repo, '--base', 'no-such-branch', '--head', selfExcused, '--out', f.out]), 2);
  assert.match(errors.mock.calls[0].arguments[0], /"no-such-branch" is not a commit/);
  // Only a base that was not named is a first push: no base at all, or the all-zero SHA.
  assert.equal(gate(f, undefined, f.base).base, null);
  assert.equal(gate(f, '', f.base).base, null);
});

test('a change cannot hide itself with a scanner ignore file or an inline comment', () => {
  const f = fixture({ 'README.md': 'x\n' });
  const workflow = [
    'on:',
    '  pull_request_target: # zizmor: ignore[dangerous-triggers]',
    'permissions: {}',
    'jobs:',
    '  test:',
    '    runs-on: ubuntu-latest',
    '    permissions:',
    '      contents: read',
    '    steps:',
    '      - run: echo hello',
    '',
  ].join('\n');
  const head = commit(f.repo, {
    '.semgrepignore': 'db/\n',
    'db/nested/.semgrepignore': '*.sql\n',
    'db/002.sql': `${GRANT_TO_ANON.trimEnd()} -- nosemgrep\n`,
    'db/nested/003.sql': GRANT_TO_ANON,
    '.github/workflows/ci.yml': workflow,
    '.gitleaksignore': '*\n',
    'deploy/.env': `GITHUB_TOKEN=${TOKEN} # gitleaks:allow\n`,
  });
  const summary = gate(f, f.base, head);
  assert.equal(summary.outcome, 'findings');
  assert.equal(blocking(summary, 'semgrep'), 2);
  assert.ok(blocking(summary, 'zizmor') >= 1);
  assert.equal(blocking(summary, 'gitleaks'), 1);
});

test('the caller\'s environment cannot point the gate at another repository', () => {
  const f = fixture({ 'README.md': 'x\n' });
  const head = commit(f.repo, { 'deploy/.env': `GITHUB_TOKEN=${TOKEN}\n`, 'db/002.sql': GRANT_TO_ANON });
  // GIT_DIR in the caller's environment names a clean repository. Git, and gitleaks through git,
  // would read that one instead of the repository the gate was given.
  const decoy = fixture({ 'README.md': 'clean\n' });
  process.env.GIT_DIR = join(decoy.repo, '.git');
  process.env.GIT_WORK_TREE = decoy.repo;
  try {
    const summary = gate(f, f.base, head);
    assert.equal(blocking(summary, 'gitleaks'), 1);
    assert.equal(blocking(summary, 'semgrep'), 1);
  } finally {
    delete process.env.GIT_DIR;
    delete process.env.GIT_WORK_TREE;
  }
});

test('a secret added and then removed inside the change is still found', () => {
  const f = fixture({ 'README.md': 'x\n' });
  commit(f.repo, { 'deploy/.env': `GITHUB_TOKEN=${TOKEN}\n` }, 'add');
  const head = commit(f.repo, { 'deploy/.env': null }, 'remove');
  const summary = gate(f, f.base, head);
  assert.equal(blocking(summary, 'gitleaks'), 1);
  assert.equal(summary.checks.find((check) => check.check === 'gitleaks').surface, 'commits');
});

test('a first push has no base, so every finding counts', () => {
  const f = fixture({ 'db/001.sql': DEFINER_WITHOUT_PATH });
  const summary = gate(f, '0000000000000000000000000000000000000000', f.base);
  assert.equal(summary.base, null);
  assert.equal(summary.outcome, 'findings');
  assert.equal(summary.checks.find((check) => check.check === 'gitleaks').surface, 'commits');
});

test('a first push is judged on the commits reachable from its head, and on no other ref', () => {
  const f = fixture({ 'README.md': 'x\n' });
  must('git', ['-C', f.repo, 'checkout', '--quiet', '-b', 'someone-elses-branch']);
  commit(f.repo, { 'other/.env': `GITHUB_TOKEN=${TOKEN}\n` }, 'a secret on another branch');
  must('git', ['-C', f.repo, 'checkout', '--quiet', 'main']);
  commit(f.repo, { 'deploy/.env': `GITHUB_TOKEN=${TOKEN}\n` }, 'add');
  const head = commit(f.repo, { 'deploy/.env': null }, 'remove');
  const { summary, findings } = gateChange(registry, f.repo, undefined, head, f.out);
  // The pushed history still counts in full, including what a later commit removed.
  assert.deepEqual(findings.filter((finding) => finding.check === 'gitleaks').map((finding) => finding.path), ['deploy/.env']);
  assert.equal(blocking(summary, 'gitleaks'), 1);
});

test('a clean change passes and says which checks did not apply', () => {
  const f = fixture({ 'README.md': 'x\n' });
  const summary = gate(f, f.base, commit(f.repo, { 'src/a.txt': 'y\n' }));
  assert.equal(summary.outcome, 'pass');
  assert.equal(summary.checks.find((check) => check.check === 'zizmor').status, 'not_applicable');
  assert.equal(summary.checks.find((check) => check.check === 'semgrep').status, 'ran');
});

test('a scanner that fails is an error, never a pass', () => {
  const broken = JSON.parse(JSON.stringify(registry));
  broken.checks.find((check) => check.id === 'semgrep').argv.tree.push('--no-such-flag');
  const f = fixture({ 'README.md': 'x\n' });
  const head = commit(f.repo, { 'src/a.txt': 'y\n' });
  const { summary } = gateChange(broken, f.repo, f.base, head, f.out);
  assert.equal(summary.outcome, 'error');
  assert.equal(summary.checks.find((check) => check.check === 'semgrep').status, 'error');
});
