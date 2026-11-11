// The canary suite must itself fail when the proof is missing or wrong. Each case here plants
// one defect in a copy of the canaries and checks that the suite reports it.
import assert from 'node:assert/strict';
import { cpSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, test } from 'node:test';
import { runCanaries } from '../lib/canary.mjs';
import { loadRegistry } from '../lib/registry.mjs';
import { PACK_ROOT } from '../lib/util.mjs';
import { remove, scratch } from './helpers.mjs';

const registry = loadRegistry();
const dirs = [];
after(() => dirs.forEach(remove));

function suite(checkId, plant) {
  const packRoot = scratch('pack');
  dirs.push(packRoot);
  cpSync(join(PACK_ROOT, 'canaries'), join(packRoot, 'canaries'), { recursive: true });
  plant(join(packRoot, 'canaries'));
  const lines = [];
  const only = { ...registry, checks: registry.checks.filter((check) => check.id === checkId) };
  const failures = runCanaries(only, { packRoot, log: (line) => lines.push(line) });
  return { failures, output: lines.join('\n') };
}

test('a rule with no catching case fails the suite', () => {
  const { failures, output } = suite('semgrep', (canaries) => rmSync(join(canaries, 'semgrep', 'grant-to-anon'), { recursive: true }));
  assert.ok(failures > 0);
  assert.match(output, /rule postgres-grant-to-anon has no case that it must catch/);
});

test('a catching case that the check no longer catches fails the suite', () => {
  const { failures, output } = suite('semgrep', (canaries) => {
    writeFileSync(
      join(canaries, 'semgrep', 'definer-without-search-path', 'supabase', 'migrations', '0001_reset_login.sql'),
      "create function public.ok() returns int language sql security definer set search_path = '' as $$ select 1; $$;\n",
    );
  });
  assert.ok(failures > 0);
  assert.match(output, /postgres-definer-without-search-path: expected 2, found 0/);
});

test('a quiet case that starts reporting fails the suite', () => {
  const { failures, output } = suite('semgrep', (canaries) => {
    writeFileSync(join(canaries, 'semgrep', 'grant-not-to-anon', 'supabase', 'migrations', '0003_new.sql'), 'grant all on public.accounts to anon;\n');
  });
  assert.ok(failures > 0);
  assert.match(output, /grant-not-to-anon: postgres-grant-to-anon: 1 unexpected finding/);
});

test('a check with no canaries fails the suite', () => {
  const { failures, output } = suite('zizmor', (canaries) => rmSync(join(canaries, 'zizmor'), { recursive: true }));
  assert.ok(failures > 0);
  assert.match(output, /zizmor: no case that the check must catch/);
});

test('a check with no quiet case fails the suite', () => {
  const { failures, output } = suite('gitleaks', (canaries) => rmSync(join(canaries, 'gitleaks', 'placeholders-only'), { recursive: true }));
  assert.ok(failures > 0);
  assert.match(output, /gitleaks: no case that the check must stay quiet on/);
});
