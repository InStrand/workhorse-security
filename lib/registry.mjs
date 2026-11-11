// Loads and validates checks/registry.json: the tools (pins, see pins.mjs) and the checks that use them.
//
// A check is a pinned tool invocation that reads one surface and writes SARIF. Everything the
// pack does with a scanner is declared here, so adding a check is a registry entry plus canaries.
// What a check may do is derived from what it declares, never stated separately:
//   class "deterministic"  -> its findings can stop a change (see gates())
//   class "model"          -> its findings advise; its silence clears nothing
//   sends_to not empty     -> it only ever reads a tree with the data paths left out (see
//                             hiddenFrom() in surface.mjs), and never commits
//   neutralise             -> what is switched off in the copy that check reads, and only there
import { join } from 'node:path';
import { pinProblems } from './pins.mjs';
import { PACK_ROOT, UsageError, readJson } from './util.mjs';

const SURFACES = ['commits', 'tree'];
const CLASSES = ['deterministic', 'model'];
const TOOL_KEYS = ['version', 'source', 'install', 'bin', 'version_argv', 'artifacts', 'requirements'];
const CHECK_KEYS = ['id', 'finds', 'class', 'sends_to', 'tool', 'applies', 'canaries', 'argv', 'flags', 'stdout', 'rule_id_strip', 'neutralise'];
const NEUTRALISE_KEYS = ['replace_files', 'strip'];
const PLACEHOLDER = /\{[a-z]+\}/g;
const KNOWN_PLACEHOLDERS = ['{pack}', '{out}', '{commits}', '{repo}'];

export const gates = (check) => check.class === 'deterministic';
export const crossesDataBoundary = (check) => check.sends_to.length > 0;
/** The arguments for one surface: the surface's own, then the flags the check passes on every surface. */
export const argvOn = (check, surface) => [...check.argv[surface], ...(check.flags ?? [])];

const isStrings = (value) => Array.isArray(value) && value.every((item) => typeof item === 'string');
const unknownKeys = (object, allowed) => Object.keys(object).filter((key) => !allowed.includes(key));

function validateTool(name, tool, packRoot, problems) {
  const where = `tools.${name}`;
  for (const key of unknownKeys(tool, TOOL_KEYS)) problems.push(`${where}: unknown key "${key}"`);
  if (!/^\d+\.\d+\.\d+$/.test(tool.version ?? '')) problems.push(`${where}.version: expected an exact version`);
  if (typeof tool.bin !== 'string') problems.push(`${where}.bin: expected a file name`);
  if (!isStrings(tool.version_argv)) problems.push(`${where}.version_argv: expected a list of arguments`);
  // A tool is a pin with a binary. How it is fetched and verified is the pin's (pins.mjs).
  if (!['archive', 'pip'].includes(tool.install)) problems.push(`${where}.install: expected "archive" or "pip"`);
  else for (const problem of pinProblems(tool, packRoot)) problems.push(`${where}.${problem}`);
}

function validateArgv(where, surface, argv, check, problems) {
  const used = argv.flatMap((arg) => arg.match(PLACEHOLDER) ?? []);
  for (const placeholder of used) {
    if (!KNOWN_PLACEHOLDERS.includes(placeholder)) problems.push(`${where}: unknown placeholder ${placeholder}`);
  }
  const needs = (placeholder) => {
    if (!used.includes(placeholder)) problems.push(`${where}: must use ${placeholder}`);
  };
  const forbids = (placeholder) => {
    if (used.includes(placeholder)) problems.push(`${where}: must not use ${placeholder}`);
  };
  if (!check.stdout) needs('{out}');
  // Commits are read from the repository, and the selector says which ones. A tree is a copy the
  // pack made: a check that reads it gets no path back to the repository.
  for (const placeholder of ['{commits}', '{repo}']) (surface === 'commits' ? needs : forbids)(placeholder);
}

function validateCheck(check, index, registry, problems) {
  const where = `checks[${index}]${check.id ? ` (${check.id})` : ''}`;
  for (const key of unknownKeys(check, CHECK_KEYS)) problems.push(`${where}: unknown key "${key}"`);
  if (!/^[a-z][a-z0-9-]*$/.test(check.id ?? '')) problems.push(`${where}.id: expected lower-case letters, digits and hyphens`);
  if (typeof check.finds !== 'string' || check.finds.length === 0) problems.push(`${where}.finds: say what the check finds`);
  if (!CLASSES.includes(check.class)) problems.push(`${where}.class: expected ${CLASSES.join(' or ')}`);
  if (!isStrings(check.sends_to)) problems.push(`${where}.sends_to: expected a list of providers, empty when nothing leaves the machine`);
  if (!(check.tool in (registry.tools ?? {}))) problems.push(`${where}.tool: "${check.tool}" is not a pinned tool`);
  if (!isStrings(check.applies) || check.applies.length === 0) problems.push(`${where}.applies: expected path patterns`);
  if (!['per-rule', 'per-check'].includes(check.canaries)) problems.push(`${where}.canaries: expected "per-rule" or "per-check"`);
  const surfaces = Object.keys(check.argv ?? {});
  if (surfaces.length === 0) problems.push(`${where}.argv: expected at least one surface`);
  for (const surface of surfaces) {
    if (!SURFACES.includes(surface)) problems.push(`${where}.argv.${surface}: unknown surface`);
    else if (surface !== 'tree' && isStrings(check.sends_to) && crossesDataBoundary(check)) {
      problems.push(`${where}.argv.${surface}: a check that sends content to a provider reads a tree only, because data paths cannot be left out of ${surface}`);
    }
    else if (!isStrings(check.argv[surface]) || !isStrings(check.flags ?? [])) problems.push(`${where}.argv.${surface}: expected a list of arguments`);
    else validateArgv(`${where}.argv.${surface}`, surface, argvOn(check, surface), check, problems);
  }
  if (check.rule_id_strip !== undefined) {
    try {
      new RegExp(check.rule_id_strip);
    } catch {
      problems.push(`${where}.rule_id_strip: not a regular expression`);
    }
  }
  const neutralise = check.neutralise ?? {};
  for (const key of unknownKeys(neutralise, NEUTRALISE_KEYS)) problems.push(`${where}.neutralise: unknown key "${key}"`);
  for (const [name, content] of Object.entries(neutralise.replace_files ?? {})) {
    if (name.includes('/') || typeof content !== 'string') problems.push(`${where}.neutralise.replace_files: expected file name to content`);
  }
  if (neutralise.strip && (!isStrings(neutralise.strip.paths) || typeof neutralise.strip.regex !== 'string')) {
    problems.push(`${where}.neutralise.strip: expected paths and a regex`);
  }
}

/** Throws one UsageError that lists every problem, or returns the registry. */
export function validateRegistry(registry, packRoot = PACK_ROOT) {
  const problems = [];
  for (const key of unknownKeys(registry, ['schema', 'tools', 'checks'])) problems.push(`unknown key "${key}"`);
  if (registry.schema !== 1) problems.push('schema: expected 1');
  for (const [name, tool] of Object.entries(registry.tools ?? {})) validateTool(name, tool, packRoot, problems);
  if (!Array.isArray(registry.checks)) problems.push('checks: expected a list');
  const ids = new Set();
  for (const [index, check] of (registry.checks ?? []).entries()) {
    validateCheck(check, index, registry, problems);
    if (ids.has(check.id)) problems.push(`checks[${index}]: duplicate id "${check.id}"`);
    ids.add(check.id);
  }
  if (problems.length > 0) throw new UsageError(`checks/registry.json is not valid:\n  ${problems.join('\n  ')}`);
  return registry;
}

export function loadRegistry(packRoot = PACK_ROOT) {
  return validateRegistry(readJson(join(packRoot, 'checks', 'registry.json')), packRoot);
}
