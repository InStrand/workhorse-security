// Prepares a deep audit: everything that can be done without a model, done once, in code.
//
//   1. the repository config is required, so "no data paths" is a statement and never an omission
//   2. sources and fragments are resolved and the coverage mode is named
//   3. the model's surface is one commit copied out of git with the data paths left out: the
//      model reads that copy and nothing else, so the data boundary does not rest on an instruction
//   4. the deterministic checks scan the whole commit and its history locally; their findings go
//      to the model as leads, and the report is written without the text of anything under a
//      data path, so that text is never in the run directory
//   5. the run file records what the audit had, and what it did not read
// Steps 3 and 4 are not rules of this file. The model is a reader that declares where it sends
// content, as a check does, and surface.mjs derives what such a reader may see.
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { CONFIG_PATH, loadConfigAtCommit, loadConfigFile } from './config.mjs';
import { blocks, finish, place } from './findings.mjs';
import { resolveFragments } from './fragments.mjs';
import { scan } from './scan.mjs';
import { commitTree, commits, filesAt, hiddenFrom, requireCommit } from './surface.mjs';
import { PACK_ROOT, UsageError, run, sha256 } from './util.mjs';

/** The model that runs the audit: the reader of the run directory. It is not a pinned tool, so it is not in the registry. */
const MODEL = { id: 'deep-audit', sends_to: ['the model provider of the session that runs the audit'] };

const NOT_READ = [
  'deployed state: no live-state adapter ran, so function bodies, grants and settings are as the repository states them',
  'platform settings: no posture check ran',
  'advisories: no feed was matched against the dependencies',
];

function nextRunDir(root, name) {
  const base = join(root, name);
  mkdirSync(base, { recursive: true });
  const taken = readdirSync(base).map((entry) => /^run-(\d+)$/.exec(entry)?.[1]).filter(Boolean).map(Number);
  const dir = join(base, `run-${Math.max(0, ...taken) + 1}`);
  mkdirSync(dir);
  return dir;
}

/** Findings grouped by check and rule, as starting points for reconnaissance. */
function leads(findings) {
  const groups = new Map();
  for (const finding of findings.filter(blocks)) {
    const key = `${finding.check}/${finding.rule}`;
    const group = groups.get(key) ?? { check: finding.check, rule: finding.rule, count: 0, message: finding.message, locations: [] };
    group.count += 1;
    if (group.locations.length < 40) group.locations.push(place(finding));
    groups.set(key, group);
  }
  return [...groups.values()].sort((a, b) => b.count - a.count);
}

export function prepareAudit(registry, repo, options, log = console.log) {
  const commit = requireCommit(repo, options.ref ?? 'HEAD');
  const configPath = options.config ? resolve(options.config) : null;
  const config = configPath ? loadConfigFile(configPath) : loadConfigAtCommit(repo, commit);
  if (!config) {
    throw new UsageError(`an audit needs a repository config: ${CONFIG_PATH} in the repository, or --config <file> from the engagement repository`);
  }
  const resolved = resolveFragments(repo, commit);
  if (resolved.missing_required.length > 0) {
    throw new UsageError(`required source not available: ${resolved.missing_required.join(', ')}. Run: node bin/whs.mjs install`);
  }

  const name = config.repository ?? basename(repo);
  const runDir = nextRunDir(resolve(options.runs ?? join(homedir(), 'security-audit-skill')), name);
  // The model's surface is opened like any reader's. It stays in the run directory, so it is not closed.
  const surface = commitTree(repo, commit).open(MODEL, config.data_paths, join(runDir, 'surface'));
  const leftOut = filesAt(repo, commit).length - surface.files.length;

  // The deterministic checks send nothing, so the surfaces opened for them hold the whole commit
  // and its history. The record of what they found is written for the model.
  const preflightDir = join(runDir, 'preflight');
  const results = [commitTree(repo, commit), commits(repo, '--all')].flatMap((target) => scan(registry, target, config.data_paths));
  const outcome = finish(results, config, preflightDir, { operation: 'audit-preflight', commit }, hiddenFrom(MODEL, config.data_paths));
  writeFileSync(join(preflightDir, 'leads.json'), `${JSON.stringify(leads(outcome.findings), null, 2)}\n`);

  const pack = run('git', ['-C', PACK_ROOT, 'rev-parse', 'HEAD']);
  const runFile = {
    schema: 1,
    created: new Date().toISOString(),
    pack: { commit: pack.status === 0 ? pack.stdout.trim() : null, modified: run('git', ['-C', PACK_ROOT, 'status', '--porcelain']).stdout.trim().length > 0 },
    target: { repository: name, path: repo, commit, worktree_modified: run('git', ['-C', repo, 'status', '--porcelain']).stdout.trim().length > 0 },
    config: configPath ? { path: configPath, sha256: sha256(readFileSync(configPath)) } : { path: `${CONFIG_PATH} at ${commit}` },
    mode: resolved.mode,
    sources: resolved.sources,
    fragments: resolved.fragments,
    not_available: resolved.not_available,
    data_paths: config.data_paths,
    surface: { path: surface.dir, files: surface.files.length, files_left_out: leftOut },
    preflight: { path: preflightDir, outcome: outcome.summary.outcome, checks: outcome.summary.checks },
    not_read: NOT_READ,
    record: config.record ?? null,
  };
  writeFileSync(join(runDir, 'whs-run.json'), `${JSON.stringify(runFile, null, 2)}\n`);

  const processSource = resolved.sources.find((source) => source.role === 'process' && source.resolved);
  log(`run directory   ${runDir}`);
  log(`coverage mode   ${resolved.mode}${resolved.not_available.length ? ` (not available: ${resolved.not_available.map((source) => source.id).join(', ')})` : ''}`);
  log(`surface         ${surface.dir} (${surface.files.length} files, ${leftOut} left out as data paths)`);
  log(`preflight       ${outcome.summary.outcome}: ${outcome.findings.filter(blocks).length} finding(s) in ${join(preflightDir, 'leads.json')}`);
  log(`process         ${processSource.path}/SKILL.md`);
  log(`fragments       ${resolved.fragments.map((fragment) => fragment.id).join(', ') || 'none apply'}`);
  log(`next            follow skills/workhorse-security-audit/SKILL.md from step 2 with ${join(runDir, 'whs-run.json')}`);
  return outcome.summary.outcome === 'error' ? 2 : 0;
}
