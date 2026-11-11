// Pins: every external input the pack uses, at one exact version.
//
// A scanner (checks/registry.json "tools") and a knowledge source fetched from git
// (fragments/registry.json "sources") are the same thing: fetched by `whs install`, verified
// against what the registry pins, and kept in a cache directory keyed by name and version. No
// other command fetches anything. A check never runs a tool from PATH: it runs the version the
// registry pins, so the version in the registry is the version that ran.
//
// A pin is { name, version, install, home, proof } plus what its way of installing needs:
//   archive  artifacts: a URL and a SHA-256 per platform; the download is hashed before it is used
//   pip      requirements: a file in the pack with a hash for every package
//   git      url and commit: git checks the content against the commit id
// `proof` is a file that exists once the pin can be used.
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { PACK_ROOT, UsageError, must, run, sha256 } from './util.mjs';

export function toolsDir() {
  if (process.env.WHS_TOOLS_DIR) return process.env.WHS_TOOLS_DIR;
  const cache = process.env.XDG_CACHE_HOME || join(homedir(), '.cache');
  return join(cache, 'workhorse-security', 'tools');
}

const platformKey = () => `${process.platform}-${process.arch}`;

/** A scanner as a pin. Its proof is its binary. */
export function toolPin(name, tool) {
  const home = join(toolsDir(), `${name}-${tool.version}`);
  return { ...tool, name, home, proof: tool.install === 'pip' ? join(home, 'venv', 'bin', tool.bin) : join(home, tool.bin) };
}

function mustReportVersion(pin) {
  const version = run(pin.proof, pin.version_argv);
  if (version.status !== 0 || !`${version.stdout}${version.stderr}`.includes(pin.version)) {
    throw new UsageError(`${pin.name}: installed binary does not report version ${pin.version}`);
  }
}

// One entry per way of installing. `stamp` is the identity of what must be installed, so a change
// to the pin changes the stamp. `problems` is what the registry validators report. `fetch`
// installs into pin.home and verifies what it fetched.
const METHODS = {
  archive: {
    stamp: (pin) => pin.artifacts[platformKey()]?.sha256,
    problems(pin) {
      const artifacts = Object.entries(pin.artifacts ?? {});
      const problems = artifacts.length === 0 ? ['artifacts: expected one artefact per platform'] : [];
      for (const [platform, artifact] of artifacts) {
        if (!/^https:\/\//.test(artifact.url ?? '')) problems.push(`artifacts.${platform}.url: expected an https URL`);
        if (!/^[0-9a-f]{64}$/.test(artifact.sha256 ?? '')) problems.push(`artifacts.${platform}.sha256: expected a SHA-256`);
      }
      return problems;
    },
    async fetch(pin) {
      const artifact = pin.artifacts[platformKey()];
      if (!artifact) throw new UsageError(`${pin.name} has no pinned artefact for ${platformKey()}`);
      const response = await fetch(artifact.url, { redirect: 'follow' });
      if (!response.ok) throw new UsageError(`download failed (${response.status}): ${artifact.url}`);
      const bytes = Buffer.from(await response.arrayBuffer());
      const actual = sha256(bytes);
      if (actual !== artifact.sha256) {
        throw new UsageError(`${pin.name}: SHA-256 mismatch for ${artifact.url}\n  expected ${artifact.sha256}\n  actual   ${actual}`);
      }
      const archive = join(pin.home, 'download.tar.gz');
      writeFileSync(archive, bytes);
      must('tar', ['-xzf', archive, '-C', pin.home, pin.bin]);
      chmodSync(pin.proof, 0o755);
      mustReportVersion(pin);
    },
  },
  pip: {
    stamp: (pin) => sha256(readFileSync(join(PACK_ROOT, pin.requirements))),
    problems(pin, packRoot) {
      const present = typeof pin.requirements === 'string' && existsSync(join(packRoot, pin.requirements));
      return present ? [] : ['requirements: expected a hash-locked requirements file in the pack'];
    },
    fetch(pin) {
      const venv = join(pin.home, 'venv');
      // Installing uses the operator's environment: the Python it selects, proxies and mirrors.
      if (!existsSync(join(venv, 'bin', 'pip'))) must(process.env.WHS_PYTHON || 'python3', ['-m', 'venv', venv], { env: process.env });
      // Every package and its SHA-256 are listed in the requirements file; pip refuses anything else.
      must(join(venv, 'bin', 'pip'), [
        'install', '--quiet', '--disable-pip-version-check', '--require-hashes',
        '-r', join(PACK_ROOT, pin.requirements),
      ], { env: process.env });
      mustReportVersion(pin);
    },
  },
  git: {
    stamp: (pin) => pin.commit,
    problems(pin) {
      const problems = /^https:\/\//.test(pin.url ?? '') ? [] : ['git: expected an https URL'];
      if (!/^[0-9a-f]{40}$/.test(pin.commit ?? '')) problems.push('commit: expected a full commit SHA');
      return problems;
    },
    fetch(pin) {
      must('git', ['init', '--quiet', pin.home]);
      must('git', ['-C', pin.home, 'fetch', '--quiet', '--depth', '1', pin.url, pin.commit], { env: process.env });
      must('git', ['-C', pin.home, 'checkout', '--quiet', '--detach', 'FETCH_HEAD']);
      const head = must('git', ['-C', pin.home, 'rev-parse', 'HEAD']);
      if (head !== pin.commit) throw new UsageError(`${pin.name}: fetched ${head}, expected ${pin.commit}`);
    },
  },
};

/** What is wrong with how a pin says it is installed, for the registry validators. */
export function pinProblems(pin, packRoot = PACK_ROOT) {
  return METHODS[pin.install]?.problems(pin, packRoot) ?? [`install: expected one of ${Object.keys(METHODS).join(', ')}`];
}

export function isInstalled(pin) {
  const marker = join(pin.home, '.installed');
  return existsSync(marker) && readFileSync(marker, 'utf8').trim() === METHODS[pin.install].stamp(pin) && existsSync(pin.proof);
}

/** Resolves an installed tool or stops with the command that installs it. */
export function requireTool(name, tool) {
  const pin = toolPin(name, tool);
  if (!isInstalled(pin)) throw new UsageError(`${name} ${tool.version} is not installed. Run: node bin/whs.mjs install`);
  return pin.proof;
}

/** Installs every pin that is not installed yet. The stamp is written last, so a failed install is not mistaken for a good one. */
export async function installPins(pins, log = console.log) {
  for (const pin of pins) {
    if (isInstalled(pin)) {
      log(`ok       ${pin.name} ${pin.version}`);
      continue;
    }
    mkdirSync(pin.home, { recursive: true });
    await METHODS[pin.install].fetch(pin);
    const marker = join(pin.home, '.installed');
    writeFileSync(`${marker}.tmp`, `${METHODS[pin.install].stamp(pin)}\n`);
    renameSync(`${marker}.tmp`, marker);
    log(`installed ${pin.name} ${pin.version} -> ${pin.home}`);
  }
}
