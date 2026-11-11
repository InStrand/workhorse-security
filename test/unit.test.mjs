// Unit tests for the parts that need no scanner: the registry's rules, the repository config,
// path patterns, and the comparison of findings. Each rule has a case that must be refused.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { applyExceptions, emptyConfig, validateConfig } from '../lib/config.mjs';
import { blocks, compareFindings, findingsFromSarif, finish, readSarif } from '../lib/findings.mjs';
import { loadFragmentRegistry } from '../lib/fragments.mjs';
import { crossesDataBoundary, gates, loadRegistry, validateRegistry } from '../lib/registry.mjs';
import { UsageError, childEnv, pathMatcher } from '../lib/util.mjs';
import { remove, scratch } from './helpers.mjs';

const clone = (value) => JSON.parse(JSON.stringify(value));
const finding = (fingerprint, extra = {}) => ({ check: 'semgrep', rule: 'r', path: 'a.sql', fingerprint, state: null, exception: null, ...extra });

test('the committed registries are valid', () => {
  const registry = loadRegistry();
  assert.deepEqual(registry.checks.map((check) => check.id), ['gitleaks', 'zizmor', 'semgrep']);
  assert.ok(registry.checks.every(gates), 'every check today is deterministic');
  assert.ok(!registry.checks.some(crossesDataBoundary), 'no check today sends anything to a provider');
  assert.equal(loadFragmentRegistry().modes.at(-1).needs.length, 0);
});

test('the registry refuses what must not be declared', () => {
  const mutate = (change) => {
    const registry = clone(loadRegistry());
    change(registry);
    return () => validateRegistry(registry);
  };
  // A tree is a copy the pack made; a check that reads it gets no path back to the repository.
  assert.throws(mutate((r) => r.checks[2].argv.tree.push('{repo}')), /must not use \{repo\}/);
  assert.throws(mutate((r) => r.checks[0].flags.push('{repo}')), /argv\.tree: must not use \{repo\}/);
  assert.throws(mutate((r) => { r.checks[0].flags = '--redact'; }), /expected a list of arguments/);
  assert.throws(mutate((r) => { r.checks[0].argv.commits = r.checks[0].argv.commits.filter((arg) => !arg.includes('{commits}')); }), /must use \{commits\}/);
  assert.throws(mutate((r) => r.checks[0].argv.tree.push('{commits}')), /argv\.tree: must not use \{commits\}/);
  assert.throws(mutate((r) => { r.checks[0].argv.history = r.checks[0].argv.commits; }), /argv\.history: unknown surface/);
  assert.throws(mutate((r) => { r.checks[2].argv.tree = r.checks[2].argv.tree.filter((arg) => arg !== '{out}'); }), /must use \{out\}/);
  assert.throws(mutate((r) => { r.checks[1].class = 'advisory'; }), /class: expected/);
  assert.throws(mutate((r) => { r.checks[1].gate = true; }), /unknown key "gate"/);
  assert.throws(mutate((r) => { r.tools.gitleaks.artifacts['linux-x64'].sha256 = 'abc'; }), /expected a SHA-256/);
  assert.throws(mutate((r) => { r.tools.zizmor.version = 'latest'; }), /expected an exact version/);
  assert.throws(mutate((r) => { r.checks[1].id = 'gitleaks'; }), /duplicate id/);
  assert.throws(mutate((r) => { delete r.checks[0].canaries; }), /canaries: expected/);
});

test('a model check can be declared, and never gates', () => {
  const registry = clone(loadRegistry());
  registry.checks.push({ ...clone(registry.checks[2]), id: 'reviewer', class: 'model', sends_to: ['anthropic'] });
  validateRegistry(registry);
  const reviewer = registry.checks.at(-1);
  assert.equal(gates(reviewer), false);
  assert.equal(crossesDataBoundary(reviewer), true);
});

test('the repository config refuses typos and unowned exceptions', () => {
  const ok = { schema: 1, data_paths: ['seed/'], exceptions: [{ paths: ['canaries/'], reason: 'fixtures', owner: 'ryan' }] };
  assert.deepEqual(validateConfig(ok, 'config').data_paths, ['seed/']);
  assert.throws(() => validateConfig({ schema: 1, exeptions: [] }, 'config'), UsageError);
  assert.throws(() => validateConfig({ schema: 1, exceptions: [{ paths: ['a/'], reason: 'x' }] }, 'config'), /owner: required/);
  assert.throws(() => validateConfig({ schema: 1, exceptions: [{ paths: ['a/'], reason: 'x', owner: 'y', expires: 'soon' }] }, 'config'), /YYYY-MM-DD/);
  assert.throws(() => validateConfig({ schema: 2 }, 'config'), /schema: expected 1/);
});

test('an exception covers its paths, checks and rules until it expires', () => {
  const config = validateConfig({
    schema: 1,
    exceptions: [
      { paths: ['fixtures/'], reason: 'known-bad fixtures', owner: 'ryan' },
      { paths: ['db/**/*.sql'], checks: ['semgrep'], rules: ['r'], reason: 'reviewed', owner: 'ryan', expires: '2026-06-30' },
    ],
  }, 'config');
  const findings = [
    finding('1', { path: 'fixtures/x.sql' }),
    finding('2', { path: 'db/a/b.sql' }),
    finding('3', { path: 'db/a/b.sql', rule: 'other' }),
    finding('4', { path: 'src/x.sql' }),
  ];
  assert.equal(applyExceptions(findings, config, '2026-06-30').expired, 0);
  assert.deepEqual(findings.map((item) => item.exception !== null), [true, true, false, false]);
  const later = [finding('2', { path: 'db/a/b.sql' })];
  assert.equal(applyExceptions(later, config, '2026-07-01').expired, 1);
  assert.equal(later[0].exception, null, 'an expired exception covers nothing');
});

test('path patterns', () => {
  assert.ok(pathMatcher('supabase/')('supabase/migrations/1.sql'));
  assert.ok(!pathMatcher('supabase/')('app/supabase/1.sql'));
  assert.ok(pathMatcher('**/*.sql')('a/b/c.sql'));
  assert.ok(pathMatcher('**/*.sql')('c.sql'));
  assert.ok(pathMatcher('.github/workflows/*.yml')('.github/workflows/ci.yml'));
  assert.ok(!pathMatcher('.github/workflows/*.yml')('.github/workflows/sub/ci.yml'));
  assert.ok(pathMatcher('**')('anything/at/all'));
  assert.ok(!pathMatcher('*.sql')('a/b.sql'));
});

test('comparison counts repeats and reports what disappeared', () => {
  const base = [finding('a'), finding('a'), finding('b')];
  const head = [finding('a'), finding('a'), finding('a'), finding('c')];
  const { absent } = compareFindings(base, head);
  assert.deepEqual(head.map((item) => item.state), ['unchanged', 'unchanged', 'new', 'new']);
  assert.deepEqual(absent.map((item) => item.fingerprint), ['b']);
  assert.deepEqual(head.map(blocks), [false, false, true, true]);
});

test('a finding that was never compared blocks, and an accepted one does not', () => {
  assert.equal(blocks(finding('a')), true);
  assert.equal(blocks(finding('a', { exception: { reason: 'r', owner: 'o' } })), false);
});

test('a tool that writes anything but runs with results has not reported', () => {
  const check = { id: 'tool' };
  for (const text of ['', 'not json', 'null', '{}', '{"runs":[]}', '{"runs":[{}]}', '{"runs":[{"results":null}]}', '{"runs":[{"results":[]},{}]}']) {
    assert.throws(() => readSarif(text, check), `accepted ${JSON.stringify(text)}`);
  }
  assert.equal(readSarif('{"runs":[{"results":[]}]}', check).runs.length, 1);
});

test('rule ids lose the prefix a tool adds, in the results and in the rule list', () => {
  const raw = 'Users.someone.pack.checks.semgrep.rules.grant-to-anon';
  const text = JSON.stringify({
    runs: [{
      tool: { driver: { rules: [{ id: raw, name: raw, shortDescription: { text: `Semgrep Finding: ${raw}` }, help: { text: 'unrelated' } }] } },
      results: [{ ruleId: raw, message: { text: 'm' } }],
    }],
  });
  const [run] = readSarif(text, { id: 'semgrep', rule_id_strip: '^.*\\.' }).runs;
  assert.equal(run.results[0].ruleId, 'grant-to-anon');
  assert.deepEqual(run.tool.driver.rules[0], { id: 'grant-to-anon', name: 'grant-to-anon', shortDescription: { text: 'Semgrep Finding: grant-to-anon' }, help: { text: 'unrelated' } });
  assert.equal(readSarif(text, { id: 'other' }).runs[0].results[0].ruleId, raw, 'a check with no prefix to strip keeps the tool\'s ids');
});

test('a record written for a reader who must not see a path never holds text from it', () => {
  const quoted = 'A real person';
  const result = (uri) => ({
    ruleId: 'r',
    message: { text: 'm' },
    locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 2, snippet: { text: quoted } }, contextRegion: { snippet: { text: quoted } } } }],
    codeFlows: [{ message: { text: quoted } }],
    properties: { anything_a_tool_adds: quoted },
  });
  const log = { runs: [{ tool: { driver: { rules: [] } }, results: [result('seed/customers.sql'), result('db/001.sql')] }] };
  const findings = findingsFromSarif(log, { id: 'semgrep' }, { kind: 'commits', repo: '/nowhere' });
  const out = scratch('record');
  try {
    finish([{ check: 'semgrep', surface: 'commits', status: 'ran', log, findings }], emptyConfig(), out, {}, ['seed/']);
    const written = readFileSync(join(out, 'scan.sarif'), 'utf8');
    const [seed, other] = JSON.parse(written).runs[0].results;
    assert.equal(written.split(quoted).length - 1, 4, 'only the finding outside the hidden path keeps its text');
    assert.deepEqual(Object.keys(seed).sort(), ['locations', 'message', 'partialFingerprints', 'ruleId']);
    assert.deepEqual(seed.locations[0].physicalLocation, { artifactLocation: { uri: 'seed/customers.sql' }, region: { startLine: 2 } });
    assert.equal(other.properties.anything_a_tool_adds, quoted);
  } finally {
    remove(out);
  }
});

test('a tree finding the pack cannot locate is a failure, and a reported path is taken as written', () => {
  const dir = scratch('tree');
  try {
    writeFileSync(join(dir, 'a.sql'), 'grant select on t to anon;\n');
    const surface = { kind: 'tree', dir, files: ['a.sql'] };
    const at = (uri) => ({ runs: [{ results: [{ ruleId: 'r', message: { text: 'm' }, locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 1 } } }] }] }] });
    const read = (uri) => findingsFromSarif(at(uri), { id: 'semgrep' }, surface);
    assert.equal(read('a.sql')[0].path, 'a.sql');
    assert.equal(read('./a.sql')[0].fingerprint, read('a.sql')[0].fingerprint);
    assert.throws(() => read('missing.sql'), /"missing\.sql", which is not a file of the surface/);
    assert.throws(() => read('../a.sql'), /not a file of the surface/);
    assert.throws(() => read('a%2Esql'), /"a%2Esql"/, 'a percent sequence in a file name is not decoded');
    assert.equal(findingsFromSarif(at('x%2Fy.env'), { id: 'gitleaks' }, { kind: 'commits', repo: '/nowhere' })[0].path, 'x%2Fy.env');
  } finally {
    remove(dir);
  }
});

test('a process the pack starts gets no credential and no switch from its caller', () => {
  const env = childEnv({
    PATH: '/usr/bin', HOME: '/home/someone', TMPDIR: '/tmp', LANG: 'en_AU.UTF-8',
    GITHUB_TOKEN: 'token', ANTHROPIC_API_KEY: 'key', AWS_SECRET_ACCESS_KEY: 'key',
    GIT_DIR: '/elsewhere/.git', GIT_WORK_TREE: '/elsewhere', GIT_CONFIG_COUNT: '1',
    SEMGREP_BASELINE_COMMIT: 'abc', ZIZMOR_CONFIG: '/elsewhere/zizmor.yml', GITLEAKS_CONFIG: '/elsewhere/gitleaks.toml',
    PYTHONPATH: '/elsewhere', NODE_OPTIONS: '--require /elsewhere/x.js',
  });
  assert.deepEqual(env, { PATH: '/usr/bin', HOME: '/home/someone', TMPDIR: '/tmp', LANG: 'en_AU.UTF-8', NO_COLOR: '1' });
});

test('commit findings are identified by commit and line', () => {
  const log = {
    runs: [{
      tool: { driver: { rules: [] } },
      results: [{
        ruleId: 'github-pat',
        message: { text: 'secret' },
        partialFingerprints: { commitSha: 'abc' },
        locations: [{ physicalLocation: { artifactLocation: { uri: 'deploy/.env' }, region: { startLine: 2 } } }],
      }],
    }],
  };
  const check = { id: 'gitleaks' };
  const [first] = findingsFromSarif(log, check, { kind: 'commits', repo: '/nowhere' });
  log.runs[0].results[0].partialFingerprints.commitSha = 'def';
  const [second] = findingsFromSarif(log, check, { kind: 'commits', repo: '/nowhere' });
  assert.equal(first.commit, 'abc');
  assert.notEqual(first.fingerprint, second.fingerprint);
});
