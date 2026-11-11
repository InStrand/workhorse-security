// Canaries: proof that a check sees what it is there to see.
//
// A canary is a small known case under canaries/<check>/<case>/ with an expect.json that states
// which rules must report it and how many times. A case that expects nothing proves the check
// stays quiet on the correct form. Canaries run through the same code as a real scan.
//
// The suite fails when a check has no catching case or no quiet case, and, for checks whose
// rules the pack writes ("per-rule"), when any loaded rule has no catching case. A rule cannot
// be added without its proof.
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { loadedRules } from './findings.mjs';
import { gates } from './registry.mjs';
import { scan } from './scan.mjs';
import { tree } from './surface.mjs';
import { PACK_ROOT, readJson } from './util.mjs';

function casesFor(check, packRoot) {
  const root = join(packRoot, 'canaries', check.id);
  if (!existsSync(root)) return [];
  return readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && existsSync(join(root, entry.name, 'expect.json')))
    .map((entry) => ({ name: entry.name, dir: join(root, entry.name) }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** A case as a tree: its files, without expect.json, plus the files expect.json says to write from parts. */
function caseTree(testCase, expect) {
  return tree((dir) => {
    cpSync(testCase.dir, dir, { recursive: true });
    rmSync(join(dir, 'expect.json'));
    for (const [path, parts] of Object.entries(expect.files ?? {})) {
      mkdirSync(dirname(join(dir, path)), { recursive: true });
      writeFileSync(join(dir, path), parts.join(''));
    }
  });
}

function runCase(registry, check, testCase) {
  const expect = readJson(join(testCase.dir, 'expect.json'));
  const [result] = scan(registry, caseTree(testCase, expect), [], [check.id]);
  const problems = [];
  if (!result || result.status !== 'ran') {
    problems.push(`check did not run: ${result?.error ?? result?.status ?? 'not selected'}`);
    return { expect, problems, rules: [] };
  }
  const counts = {};
  for (const finding of result.findings) {
    counts[finding.rule] = (counts[finding.rule] ?? 0) + 1;
  }
  for (const [rule, wanted] of Object.entries(expect.expect)) {
    if ((counts[rule] ?? 0) !== wanted) problems.push(`${rule}: expected ${wanted}, found ${counts[rule] ?? 0}`);
  }
  if (!expect.allow_other_rules) {
    for (const [rule, count] of Object.entries(counts)) {
      if (!(rule in expect.expect)) problems.push(`${rule}: ${count} unexpected finding(s)`);
    }
  }
  return { expect, problems, rules: loadedRules(result.log) };
}

export function runCanaries(registry, { packRoot = PACK_ROOT, log = console.log } = {}) {
  let failures = 0;
  let total = 0;
  const fail = (message) => {
    failures += 1;
    log(`  FAIL ${message}`);
  };
  for (const check of registry.checks.filter(gates)) {
    const cases = casesFor(check, packRoot);
    const caught = new Set();
    const loaded = new Set();
    let quiet = 0;
    log(`${check.id}: ${cases.length} case(s)`);
    for (const testCase of cases) {
      total += 1;
      const { expect, problems, rules } = runCase(registry, check, testCase);
      rules.forEach((rule) => loaded.add(rule));
      if (problems.length > 0) {
        fail(`${check.id}/${testCase.name}: ${problems.join('; ')}`);
        continue;
      }
      const expected = Object.entries(expect.expect).filter(([, count]) => count > 0).map(([rule]) => rule);
      if (expected.length === 0) quiet += 1;
      expected.forEach((rule) => caught.add(rule));
      log(`  ok   ${check.id}/${testCase.name}`);
    }
    if (caught.size === 0) fail(`${check.id}: no case that the check must catch`);
    if (quiet === 0) fail(`${check.id}: no case that the check must stay quiet on`);
    if (check.canaries === 'per-rule') {
      for (const rule of [...loaded].sort()) {
        if (!/^[a-z0-9-]+$/.test(rule)) fail(`${check.id}: rule id "${rule}" must be lower-case letters, digits and hyphens`);
        else if (!caught.has(rule)) fail(`${check.id}: rule ${rule} has no case that it must catch`);
      }
    }
  }
  if (total === 0) fail('no canaries ran');
  log(`canaries: ${total} case(s), ${failures} failure(s)`);
  return failures;
}
