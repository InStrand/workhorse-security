// Runs checks. Each check reads a target through a surface opened for it alone. Two operations:
//   scan  one target, every check that reads its kind
//   gate  a change: commit-reading checks over its commits, tree-reading checks over the head
//         tree compared with the base tree, so only what the change added can stop it
// Both fail closed: a check that errors, or writes no SARIF, is a failure, never a pass.
// The outcome and the report are the record's (findings.mjs); printing is the command's (cli.mjs).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { emptyConfig, loadConfigAtCommit, loadConfigFile } from './config.mjs';
import { compareFindings, findingsFromSarif, finish, readSarif } from './findings.mjs';
import { argvOn, gates } from './registry.mjs';
import { commitTree, commits, noRevision, removeTempDir, requireCommit, tempDir } from './surface.mjs';
import { requireTool } from './pins.mjs';
import { PACK_ROOT, matchesAny, run } from './util.mjs';

const TIMEOUT_MS = 20 * 60 * 1000;

function argvFor(check, surface, outFile) {
  const values = {
    '{pack}': PACK_ROOT,
    '{out}': outFile,
    '{repo}': surface.repo ?? '',
    '{commits}': surface.select ?? '',
  };
  return argvOn(check, surface.kind).map((arg) => arg.replace(/\{[a-z]+\}/g, (placeholder) => values[placeholder]));
}

/**
 * Runs one check on one surface. Returns status "ran", "not_applicable" or "error". What the
 * tool writes is raw: its own rule names, and text from every file it flagged. It goes to a
 * directory that is removed here. Only the record (findings.mjs) is kept.
 */
function runCheck(registry, check, surface) {
  const base = { check: check.id, surface: surface.kind, log: null, findings: [] };
  if (surface.kind === 'tree' && !surface.files.some((file) => matchesAny(check.applies, file))) {
    return { ...base, status: 'not_applicable' };
  }
  const tool = registry.tools[check.tool];
  const bin = requireTool(check.tool, tool);
  const scratch = tempDir('report');
  try {
    const outFile = join(scratch, 'report.sarif');
    const result = run(bin, argvFor(check, surface, outFile), {
      cwd: surface.dir ?? surface.repo,
      timeout: TIMEOUT_MS,
    });
    if (result.status !== 0) {
      return { ...base, status: 'error', error: `${check.tool} exited ${result.status}: ${result.stderr.trim().split('\n').slice(-3).join(' | ')}` };
    }
    const log = readSarif(check.stdout ? result.stdout : readFileSync(outFile, 'utf8'), check);
    return { ...base, status: 'ran', log, findings: findingsFromSarif(log, check, surface), version: tool.version };
  } catch (error) {
    return { ...base, status: 'error', error: `${check.tool} wrote no readable SARIF: ${error.message}` };
  } finally {
    removeTempDir(scratch);
  }
}

/**
 * One check reads one target. The surface is opened for that check and for nothing else, so
 * there is no way to hand a check a surface that was built for another reader.
 */
function read(registry, check, target, dataPaths) {
  const surface = target.open(check, dataPaths);
  try {
    return runCheck(registry, check, surface);
  } finally {
    surface.close();
  }
}

/** Reads one target with every deterministic check that reads its kind. */
export function scan(registry, target, dataPaths, ids) {
  return registry.checks
    .filter((check) => gates(check) && check.argv[target.kind] && (!ids || ids.includes(check.id)))
    .map((check) => read(registry, check, target, dataPaths));
}

/**
 * Judges a change. The exceptions come from the base revision, so the change cannot excuse
 * itself; a repository with no base revision yet (its first push) uses the head's. Only a base
 * that was not named is a first push: a base that was named and cannot be read stops the gate,
 * because falling back to the head's exceptions would let the change excuse itself. When the
 * config is a file kept outside the repository, it is the whole config: no revision of the
 * repository adds to it, the head least of all.
 */
export function gateChange(registry, repo, baseRef, headRef, outDir, configFile) {
  const head = requireCommit(repo, headRef);
  const base = noRevision(baseRef) ? null : requireCommit(repo, baseRef);
  const config = configFile ? loadConfigFile(configFile) : loadConfigAtCommit(repo, base ?? head) ?? emptyConfig();
  // A check that can read commits reads the change's commits. Every other check reads the head
  // tree and is compared with the base tree. No check judges the same change twice.
  const gating = registry.checks.filter(gates);
  const readsCommits = (check) => Boolean(check.argv.commits);
  const on = (check, target) => read(registry, check, target, config.data_paths);
  const fromTrees = gating.filter((check) => !readsCommits(check)).map((check) => {
    const after = on(check, commitTree(repo, head));
    const before = base ? on(check, commitTree(repo, base)) : null;
    if (before?.status === 'error') return { ...after, status: 'error', error: `base tree: ${before.error}` };
    compareFindings(before?.findings ?? [], after.findings);
    return after;
  });
  // Commit-reading checks see every commit in the change, including a secret added and then
  // removed. With no base the change is every commit reachable from the head, and no other ref.
  const change = commits(repo, base ? `${base}..${head}` : head);
  const fromCommits = gating.filter(readsCommits).map((check) => {
    const result = on(check, change);
    for (const finding of result.findings) finding.state = 'new';
    return result;
  });
  return finish([...fromTrees, ...fromCommits], config, outDir, { operation: 'gate', base, head });
}
