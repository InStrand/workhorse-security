// The repository config: the one file a repository (or, for a repository we do not own, the
// engagement repository) writes about itself. Everything else comes from the pack.
//
//   data_paths   files that never go to a provider. They are removed from the surface that any
//                check with a non-empty sends_to reads. Local checks still scan them.
//   exceptions   findings a named person accepted, with a reason and an optional expiry. They
//                are the only way to accept a finding: scanners' own ignore comments and ignore
//                files are switched off, and a change is judged with the exceptions of its base
//                revision, so a change cannot excuse itself.
import { UsageError, matchesAny, readJson, run } from './util.mjs';

export const CONFIG_PATH = 'security/config.json';
const CONFIG_KEYS = ['schema', 'repository', 'tier', 'data_paths', 'exceptions', 'record'];
const EXCEPTION_KEYS = ['paths', 'checks', 'rules', 'reason', 'owner', 'expires'];
const TIERS = ['workhorse', 'customer'];

export const emptyConfig = () => ({ schema: 1, data_paths: [], exceptions: [] });

const isStrings = (value) => Array.isArray(value) && value.every((item) => typeof item === 'string' && item.length > 0);

export function validateConfig(config, where) {
  const problems = [];
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    throw new UsageError(`${where} is not valid: expected an object`);
  }
  for (const key of Object.keys(config)) {
    if (!CONFIG_KEYS.includes(key)) problems.push(`unknown key "${key}"`);
  }
  if (config.schema !== 1) problems.push('schema: expected 1');
  if (config.tier !== undefined && !TIERS.includes(config.tier)) problems.push(`tier: expected ${TIERS.join(' or ')}`);
  if (config.data_paths !== undefined && !isStrings(config.data_paths)) problems.push('data_paths: expected a list of path patterns');
  if (config.exceptions !== undefined && !Array.isArray(config.exceptions)) problems.push('exceptions: expected a list');
  for (const [index, exception] of (Array.isArray(config.exceptions) ? config.exceptions : []).entries()) {
    const at = `exceptions[${index}]`;
    for (const key of Object.keys(exception)) {
      if (!EXCEPTION_KEYS.includes(key)) problems.push(`${at}: unknown key "${key}"`);
    }
    if (!isStrings(exception.paths) || exception.paths.length === 0) problems.push(`${at}.paths: expected path patterns`);
    for (const key of ['checks', 'rules']) {
      if (exception[key] !== undefined && (!isStrings(exception[key]) || exception[key].length === 0)) {
        problems.push(`${at}.${key}: expected a list of ids, or leave it out for all`);
      }
    }
    for (const key of ['reason', 'owner']) {
      if (typeof exception[key] !== 'string' || exception[key].trim().length === 0) problems.push(`${at}.${key}: required`);
    }
    if (exception.expires !== undefined && !/^\d{4}-\d{2}-\d{2}$/.test(exception.expires)) {
      problems.push(`${at}.expires: expected a date as YYYY-MM-DD`);
    }
  }
  if (problems.length > 0) throw new UsageError(`${where} is not valid:\n  ${problems.join('\n  ')}`);
  return { ...emptyConfig(), ...config };
}

export function loadConfigFile(path) {
  return validateConfig(readJson(path), path);
}

/** The config as committed at a revision, or null when that revision has none. */
export function loadConfigAtCommit(repo, commit, path = CONFIG_PATH) {
  const shown = run('git', ['-C', repo, 'show', `${commit}:${path}`]);
  if (shown.status !== 0) return null;
  let parsed;
  try {
    parsed = JSON.parse(shown.stdout);
  } catch (error) {
    throw new UsageError(`${path} at ${commit.slice(0, 12)} is not valid JSON: ${error.message}`);
  }
  return validateConfig(parsed, `${path} at ${commit.slice(0, 12)}`);
}

/**
 * Marks each finding an unexpired exception covers. An expired exception covers nothing, so the
 * finding returns to the open list on the day after the expiry date.
 */
export function applyExceptions(findings, config, today = new Date().toISOString().slice(0, 10)) {
  const active = config.exceptions.filter((exception) => !exception.expires || exception.expires >= today);
  const covers = (list, id) => list === undefined || list.includes('*') || list.includes(id);
  for (const finding of findings) {
    const exception = active.find(
      (candidate) =>
        matchesAny(candidate.paths, finding.path) && covers(candidate.checks, finding.check) && covers(candidate.rules, finding.rule),
    );
    if (exception) finding.exception = { reason: exception.reason, owner: exception.owner, expires: exception.expires ?? null };
  }
  return { expired: config.exceptions.length - active.length };
}
