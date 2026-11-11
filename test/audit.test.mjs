// Audit preparation: the data boundary is a property of the surface, the coverage mode is the
// name of what resolved, and the run file says what the audit had and did not have.
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { prepareAudit } from '../lib/audit.mjs';
import { allPins } from '../lib/cli.mjs';
import { resolveFragments, sourcePins } from '../lib/fragments.mjs';
import { installPins } from '../lib/pins.mjs';
import { loadRegistry } from '../lib/registry.mjs';
import { UsageError } from '../lib/util.mjs';
import { DEFINER_WITHOUT_PATH, GRANT_TO_ANON, commit, makeRepo, remove, scratch } from './helpers.mjs';

const registry = loadRegistry();
const dirs = [];
after(() => {
  dirs.forEach(remove);
  delete process.env.WHS_SKILLS_DIRS;
});

function fixture() {
  const repo = makeRepo();
  const work = scratch('audit');
  dirs.push(repo, work);
  commit(repo, {
    'README.md': 'sample\n',
    'db/001.sql': DEFINER_WITHOUT_PATH,
    'seed/customers.sql': `insert into customers (name) values ('A real person');\n${GRANT_TO_ANON}`,
    'seed/nested/more.sql': "insert into customers (name) values ('Another');\n",
  });
  const config = join(work, 'config.json');
  writeFileSync(config, JSON.stringify({ schema: 1, repository: 'sample', tier: 'customer', data_paths: ['seed/'], exceptions: [] }));
  const skills = join(work, 'skills');
  mkdirSync(skills);
  return { repo, work, config, skills, runs: join(work, 'runs') };
}

const prepare = (f) => prepareAudit(registry, f.repo, { config: f.config, runs: f.runs }, () => {});
const readRun = (f, n) => JSON.parse(readFileSync(join(f.runs, 'sample', `run-${n}`, 'whs-run.json'), 'utf8'));

test('the surface leaves the data paths out and the leads keep no text from them', () => {
  const f = fixture();
  process.env.WHS_SKILLS_DIRS = f.skills;
  assert.equal(prepare(f), 0);
  const runDir = join(f.runs, 'sample', 'run-1');
  assert.ok(existsSync(join(runDir, 'surface', 'db', '001.sql')));
  assert.ok(!existsSync(join(runDir, 'surface', 'seed')), 'no data path reaches the surface');
  assert.ok(!existsSync(join(runDir, 'surface', '.git')));

  const run = readRun(f, 1);
  assert.equal(run.surface.files_left_out, 2);
  assert.deepEqual(run.data_paths, ['seed/']);
  assert.ok(run.fragments.some((fragment) => fragment.id === 'postgres-supabase'));
  assert.ok(run.not_read.length > 0, 'the run file says what was not read');

  // The local scan still read the data path: the grant in the seed file is a finding.
  const results = JSON.parse(readFileSync(join(runDir, 'preflight', 'scan.sarif'), 'utf8')).runs.flatMap((sarifRun) => sarifRun.results);
  const at = (path) => results.find((result) => result.locations[0].physicalLocation.artifactLocation.uri === path);
  assert.ok(at('seed/customers.sql'), 'deterministic checks scan the data paths');
  assert.equal(at('seed/customers.sql').locations[0].physicalLocation.region.snippet, undefined, 'but their text does not reach the model');
  assert.ok(at('db/001.sql').locations[0].physicalLocation.region.snippet, 'other findings keep their text');
  assert.ok(!readFileSync(join(runDir, 'preflight', 'scan.sarif'), 'utf8').includes('A real person'));
  const leads = JSON.parse(readFileSync(join(runDir, 'preflight', 'leads.json'), 'utf8'));
  assert.deepEqual(leads.map((lead) => lead.rule).sort(), ['postgres-definer-without-search-path', 'postgres-grant-to-anon']);
});

test('the coverage mode names the sources that resolved', () => {
  const f = fixture();
  process.env.WHS_SKILLS_DIRS = f.skills;
  prepare(f);
  const open = readRun(f, 1);
  assert.equal(open.mode, 'open');
  assert.ok(open.not_available.some((source) => source.id === 'jsm-security-audit-for-saas'), 'what was missing is recorded');
  const processSource = open.sources.find((source) => source.role === 'process');
  assert.equal(processSource.resolved, true);
  assert.match(processSource.version, /^[0-9a-f]{40}$/, 'the process is pinned by commit');
  assert.ok(existsSync(join(processSource.path, 'validate-findings.cjs')));

  // The same target with the licensed skill installed is a full run, and a second run directory.
  const skill = join(f.skills, 'security-audit-for-saas');
  mkdirSync(join(skill, 'references'), { recursive: true });
  writeFileSync(join(skill, 'SKILL.md'), '# stand-in\n');
  writeFileSync(join(skill, 'references', 'KERNEL.md'), '# stand-in\n');
  prepare(f);
  const full = readRun(f, 2);
  assert.equal(full.mode, 'full');
  assert.ok(!full.not_available.some((source) => source.id === 'jsm-security-audit-for-saas'));
});

test('whs install is the one command that fetches, and it installs the pinned audit process', async () => {
  const pins = allPins(registry);
  assert.ok(pins.some((pin) => pin.name === 'cloudflare-security-audit' && pin.install === 'git'), 'the audit process is among the pins whs install installs');
  assert.deepEqual(pins.filter((pin) => pin.install !== 'git').map((pin) => pin.name), ['gitleaks', 'zizmor', 'semgrep']);

  // A machine where nothing has been installed.
  const f = fixture();
  const cache = scratch('cache');
  dirs.push(cache);
  const toolsDir = process.env.WHS_TOOLS_DIR;
  process.env.WHS_SKILLS_DIRS = f.skills;
  process.env.WHS_TOOLS_DIR = join(cache, 'tools');
  try {
    assert.deepEqual(resolveFragments(f.repo, 'HEAD').missing_required, ['cloudflare-security-audit']);
    assert.throws(() => prepare(f), /required source not available: cloudflare-security-audit\. Run: node bin\/whs\.mjs install/);
    assert.ok(!existsSync(join(cache, 'sources')) && !existsSync(f.runs), 'neither command fetched or wrote anything');
    await installPins(sourcePins(), () => {});
    const [processSource] = resolveFragments(f.repo, 'HEAD').sources;
    assert.equal(processSource.resolved, true);
    assert.ok(processSource.path.startsWith(cache));
  } finally {
    if (toolsDir === undefined) delete process.env.WHS_TOOLS_DIR;
    else process.env.WHS_TOOLS_DIR = toolsDir;
  }
});

test('an audit refuses to start without a repository config', () => {
  const f = fixture();
  process.env.WHS_SKILLS_DIRS = f.skills;
  assert.throws(() => prepareAudit(registry, f.repo, { runs: f.runs }, () => {}), UsageError);
  assert.ok(!existsSync(f.runs), 'nothing was written');
});
