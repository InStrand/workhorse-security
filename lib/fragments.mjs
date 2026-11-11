// Knowledge for model checks: the sources an audit can draw on and the fragments the pack writes.
//
// A source is someone else's skill. It is either pinned here by git commit (a pin, installed by
// `whs install` like a scanner; see pins.mjs), or detected where it is already installed (a
// licensed skill is never copied). A fragment is a
// file in this pack, in the companion-file shape the audit process already reads, selected when
// the target has files that match it.
//
// The coverage mode is not a switch. It is the name of the set of sources that resolved, so the
// record always states what the audit had and what it did not.
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { isInstalled, pinProblems, toolsDir } from './pins.mjs';
import { filesAt, requireCommit } from './surface.mjs';
import { PACK_ROOT, UsageError, matchesAny, readJson, sha256 } from './util.mjs';

const SOURCE_KEYS = ['id', 'role', 'required', 'provides', 'licence', 'git', 'commit', 'subdir', 'skill', 'marker'];
const FRAGMENT_KEYS = ['id', 'file', 'applies', 'covers'];

export function loadFragmentRegistry(packRoot = PACK_ROOT) {
  const registry = readJson(join(packRoot, 'fragments', 'registry.json'));
  const problems = [];
  if (registry.schema !== 1) problems.push('schema: expected 1');
  for (const [index, source] of (registry.sources ?? []).entries()) {
    const at = `sources[${index}]`;
    for (const key of Object.keys(source)) if (!SOURCE_KEYS.includes(key)) problems.push(`${at}: unknown key "${key}"`);
    if (!['process', 'domain'].includes(source.role)) problems.push(`${at}.role: expected process or domain`);
    for (const key of ['id', 'provides', 'licence', 'marker']) if (typeof source[key] !== 'string') problems.push(`${at}.${key}: required`);
    const pinned = typeof source.git === 'string';
    if (pinned === (typeof source.skill === 'string')) problems.push(`${at}: give either git with commit, or skill`);
    if (pinned) for (const problem of pinProblems(sourcePin(source), packRoot)) problems.push(`${at}.${problem}`);
  }
  const ids = (registry.sources ?? []).map((source) => source.id);
  for (const [index, mode] of (registry.modes ?? []).entries()) {
    for (const id of mode.needs ?? []) if (!ids.includes(id)) problems.push(`modes[${index}].needs: unknown source "${id}"`);
  }
  if (!(registry.modes ?? []).some((mode) => (mode.needs ?? []).length === 0)) problems.push('modes: the last mode must need nothing');
  for (const [index, fragment] of (registry.fragments ?? []).entries()) {
    const at = `fragments[${index}]`;
    for (const key of Object.keys(fragment)) if (!FRAGMENT_KEYS.includes(key)) problems.push(`${at}: unknown key "${key}"`);
    if (!existsSync(join(packRoot, fragment.file ?? ''))) problems.push(`${at}.file: ${fragment.file} does not exist`);
    if (!Array.isArray(fragment.applies) || fragment.applies.length === 0) problems.push(`${at}.applies: expected path patterns`);
  }
  if (problems.length > 0) throw new UsageError(`fragments/registry.json is not valid:\n  ${problems.join('\n  ')}`);
  return registry;
}

function skillDirs() {
  if (process.env.WHS_SKILLS_DIRS !== undefined) return process.env.WHS_SKILLS_DIRS.split(':').filter(Boolean);
  return ['.claude', '.agents', '.codex'].map((name) => join(homedir(), name, 'skills'));
}

/** A source that is fetched from git, as a pin. Its proof is its marker file. */
function sourcePin(source) {
  const version = String(source.commit).slice(0, 12);
  const home = join(dirname(toolsDir()), 'sources', `${source.id}-${version}`);
  return { name: source.id, version, install: 'git', url: source.git, commit: source.commit, home, proof: join(home, source.subdir ?? '', source.marker ?? '') };
}

/** The sources `whs install` fetches. A source that is detected where it is installed is not a pin. */
export const sourcePins = (packRoot = PACK_ROOT) => loadFragmentRegistry(packRoot).sources.filter((source) => source.git).map(sourcePin);

function resolveSource(source) {
  const base = { id: source.id, role: source.role, required: source.required === true, provides: source.provides, licence: source.licence };
  if (source.git) {
    const resolved = isInstalled(sourcePin(source));
    return { ...base, resolved, path: resolved ? join(sourcePin(source).home, source.subdir ?? '') : null, version: resolved ? source.commit : null };
  }
  for (const dir of skillDirs()) {
    const path = join(dir, source.skill);
    if (existsSync(join(path, source.marker)) && existsSync(join(path, 'SKILL.md'))) {
      return { ...base, resolved: true, path, version: `sha256:${sha256(readFileSync(join(path, 'SKILL.md'))).slice(0, 16)}` };
    }
  }
  return { ...base, resolved: false, path: null, version: null };
}

/**
 * What an audit of this commit would use: the sources that resolved, the mode that names them,
 * and the fragments that apply. It fetches nothing: a pinned source resolves once `whs install` ran.
 */
export function resolveFragments(repo, ref, { packRoot = PACK_ROOT } = {}) {
  const registry = loadFragmentRegistry(packRoot);
  const commit = requireCommit(repo, ref);
  const sources = registry.sources.map(resolveSource);
  const resolved = new Set(sources.filter((source) => source.resolved).map((source) => source.id));
  const mode = registry.modes.find((candidate) => candidate.needs.every((id) => resolved.has(id))).mode;
  const files = filesAt(repo, commit);
  const fragments = registry.fragments
    .filter((fragment) => files.some((file) => matchesAny(fragment.applies, file)))
    .map((fragment) => ({
      id: fragment.id,
      path: join(packRoot, fragment.file),
      sha256: sha256(readFileSync(join(packRoot, fragment.file))),
      covers: fragment.covers ?? [],
    }));
  return {
    commit,
    mode,
    sources,
    fragments,
    not_available: sources.filter((source) => !source.resolved).map((source) => ({ id: source.id, provides: source.provides })),
    missing_required: sources.filter((source) => source.required && !source.resolved).map((source) => source.id),
  };
}
