// Surfaces: what a reader may see follows from what it declares, and one reader's surface never
// depends on another reader. Each case plants what would break that and checks it is refused or
// has no effect.
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { loadRegistry, validateRegistry } from '../lib/registry.mjs';
import { scan } from '../lib/scan.mjs';
import { commitTree, commits, hiddenFrom, tree } from '../lib/surface.mjs';
import { GRANT_TO_ANON, TOKEN, commit, makeRepo, remove } from './helpers.mjs';

const registry = loadRegistry();
const clone = (value) => JSON.parse(JSON.stringify(value));
const dirs = [];
after(() => dirs.forEach(remove));

function repoWith(files) {
  const repo = makeRepo();
  dirs.push(repo);
  return { repo, head: commit(repo, files) };
}

const paths = (results, id) => results.find((result) => result.check === id).findings.map((finding) => finding.path).sort();
const LOCAL = { id: 'local-reader', sends_to: [] };
const SENDING = { id: 'sending-reader', sends_to: ['a provider'] };

test('what one check switches off in its copy never changes what another check reads', () => {
  // Semgrep's copy loses every .semgrepignore and zizmor's copy loses its ignore comments.
  // A secret in either place is still gitleaks's to find, whichever checks run beside it.
  const { repo, head } = repoWith({
    'README.md': 'x\n',
    'sub/.semgrepignore': `# ${TOKEN}\n`,
    '.github/workflows/ci.yml': `on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi # zizmor: ignore[${TOKEN}]\n`,
  });
  const expected = ['.github/workflows/ci.yml', 'sub/.semgrepignore'];
  assert.deepEqual(paths(scan(registry, commitTree(repo, head), []), 'gitleaks'), expected);
  assert.deepEqual(paths(scan(registry, commitTree(repo, head), [], ['gitleaks']), 'gitleaks'), expected);
});

test('an ignore file for gitleaks in the tree hides nothing from gitleaks', () => {
  const { repo, head } = repoWith({
    'deploy/.env': `GITHUB_TOKEN=${TOKEN}\n`,
    '.gitleaksignore': 'deploy/.env:github-pat:1\ndeploy/.env:generic-api-key:1\n',
  });
  assert.deepEqual(paths(scan(registry, commitTree(repo, head), [], ['gitleaks']), 'gitleaks'), ['deploy/.env']);
});

test('a commit cannot use git attributes to keep a file out of a tree or out of the history', () => {
  const orders = GRANT_TO_ANON.replace('accounts', 'orders');
  const repo = makeRepo();
  dirs.push(repo);
  const base = commit(repo, { 'README.md': 'x\n' });
  commit(repo, { 'db/002.sql': GRANT_TO_ANON, 'db/003.sql': orders, 'deploy/.env': `GITHUB_TOKEN=${TOKEN}\n` });
  // export-ignore drops a file from `git archive`, -diff drops its text from `git log -p`,
  // and eol=crlf rewrites it on the way out.
  const head = commit(repo, { '.gitattributes': 'db/002.sql export-ignore\ndeploy/.env -diff\ndb/003.sql text eol=crlf\n' });
  assert.deepEqual(paths(scan(registry, commitTree(repo, head), [], ['semgrep']), 'semgrep'), ['db/002.sql', 'db/003.sql']);
  assert.deepEqual(paths(scan(registry, commits(repo, `${base}..${head}`), []), 'gitleaks'), ['deploy/.env']);
  assert.deepEqual(paths(scan(registry, commits(repo, '--all'), []), 'gitleaks'), ['deploy/.env']);
  const surface = commitTree(repo, head).open(LOCAL, []);
  try {
    assert.equal(readFileSync(join(surface.dir, 'db/003.sql'), 'utf8'), orders, 'the copy is the commit, byte for byte');
  } finally {
    surface.close();
  }
});

test('an ignore file for gitleaks in the checkout hides nothing from gitleaks over commits', () => {
  const repo = makeRepo();
  dirs.push(repo);
  const base = commit(repo, { 'README.md': 'x\n' });
  const added = commit(repo, { 'deploy/.env': `GITHUB_TOKEN=${TOKEN}\n` });
  // The next commit of the same change names the finding by its fingerprint: commit, file, rule, line.
  const head = commit(repo, { '.gitleaksignore': `${added}:deploy/.env:github-pat:1\n${added}:deploy/.env:generic-api-key:1\n` });
  assert.deepEqual(paths(scan(registry, commits(repo, `${base}..${head}`), []), 'gitleaks'), ['deploy/.env']);
});

test('a check that sends content to a provider reads the tree without the data paths; a local check reads all of it', () => {
  const sending = clone(registry);
  sending.checks.push({ ...clone(sending.checks.find((check) => check.id === 'semgrep')), id: 'semgrep-hosted', sends_to: ['a provider'] });
  validateRegistry(sending);
  const { repo, head } = repoWith({
    'db/001.sql': GRANT_TO_ANON,
    'seed/customers.sql': GRANT_TO_ANON.replace('accounts', 'customers'),
    'seed/deep/more.sql': GRANT_TO_ANON.replace('accounts', 'orders'),
  });
  const results = scan(sending, commitTree(repo, head), ['seed/'], ['semgrep', 'semgrep-hosted']);
  assert.deepEqual(paths(results, 'semgrep'), ['db/001.sql', 'seed/customers.sql', 'seed/deep/more.sql']);
  assert.deepEqual(paths(results, 'semgrep-hosted'), ['db/001.sql']);
});

test('the data boundary is one function of the reader', () => {
  assert.deepEqual(hiddenFrom(LOCAL, ['seed/']), []);
  assert.deepEqual(hiddenFrom(SENDING, ['seed/']), ['seed/']);
});

test('a surface that still holds a hidden file, or a git directory, is refused before any reader gets it', () => {
  // A builder that ignores what it was told to leave out.
  const careless = tree((dir) => {
    mkdirSync(join(dir, 'seed'));
    writeFileSync(join(dir, 'seed', 'customers.sql'), 'x\n');
    writeFileSync(join(dir, 'a.sql'), 'x\n');
  });
  assert.throws(() => careless.open(SENDING, ['seed/']), /sending-reader holds 1 file\(s\) it must not hold, the first is seed\/customers\.sql/);
  const surface = careless.open(LOCAL, ['seed/']);
  assert.deepEqual(surface.files, ['a.sql', 'seed/customers.sql']);
  surface.close();
  assert.ok(!existsSync(surface.dir), 'closing a surface removes the copy');

  const withGitDirectory = tree((dir) => {
    mkdirSync(join(dir, 'vendor', '.git'), { recursive: true });
    writeFileSync(join(dir, 'vendor', '.git', 'config'), '[core]\n');
  });
  assert.throws(() => withGitDirectory.open(LOCAL, []), /vendor\/\.git\/config/);
});

test('commits are never opened for a reader that sends content, and the registry refuses the declaration', () => {
  assert.throws(() => commits('/nowhere', '--all').open(SENDING), /sending-reader sends content to a provider and cannot read commits/);
  const declared = clone(registry);
  declared.checks.find((check) => check.id === 'gitleaks').sends_to = ['a provider'];
  assert.throws(() => validateRegistry(declared), /argv\.commits: a check that sends content to a provider reads a tree only/);
});
