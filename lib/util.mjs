// Shared helpers. Node standard library only: nothing here is installed.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PACK_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/** An error whose message is for the person running the command, with no stack trace. */
export class UsageError extends Error {}

export function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

export function readJson(path) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (error) {
    throw new UsageError(`cannot read ${path}: ${error.message}`);
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new UsageError(`${path} is not valid JSON: ${error.message}`);
  }
}

const KEPT_ENV = [
  'PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ',
  'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'LD_LIBRARY_PATH',
];

/**
 * The environment of every process the pack starts: enough to run git and a scanner, and no
 * more. A scanner reads content nobody has reviewed, so it gets no credential its caller holds.
 * Nothing the caller has set can point git at another repository (GIT_DIR and the rest of
 * GIT_*) or change what a scanner reports (a tool's own variables). Only a command that
 * installs a pin passes the caller's environment, because proxies and mirrors are the operator's.
 */
export function childEnv(env = process.env) {
  return { ...Object.fromEntries(KEPT_ENV.filter((name) => env[name] !== undefined).map((name) => [name, env[name]])), NO_COLOR: '1' };
}

/**
 * Runs a command without a shell, in childEnv() unless the caller passes an environment.
 * Returns status, stdout and stderr; never throws on a non-zero exit, because the caller
 * decides what a failure means.
 */
export function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024 * 1024,
    env: childEnv(),
    ...options,
  });
  if (result.error) {
    return { status: 127, stdout: '', stderr: String(result.error.message) };
  }
  return { status: result.status ?? 1, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

/** Runs a command that must succeed and returns its trimmed stdout. */
export function must(command, args, options = {}) {
  const result = run(command, args, options);
  if (result.status !== 0) {
    throw new UsageError(`${command} ${args.join(' ')} failed (${result.status}): ${result.stderr.trim()}`);
  }
  return result.stdout.trim();
}

/**
 * Path patterns, used wherever a path is matched (check applicability, exceptions, data paths):
 *   "dir/"      everything under dir
 *   "**"        any number of path segments
 *   "*" and "?" within one segment
 * Paths are repository-relative with forward slashes.
 */
export function pathMatcher(pattern) {
  if (pattern.endsWith('/')) {
    return (path) => path.startsWith(pattern);
  }
  let source = '';
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    if (char === '*' && pattern[index + 1] === '*') {
      if (pattern[index + 2] === '/') {
        source += '(?:.*/)?';
        index += 2;
      } else {
        source += '.*';
        index += 1;
      }
    } else if (char === '*') {
      source += '[^/]*';
    } else if (char === '?') {
      source += '[^/]';
    } else {
      source += char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  const regex = new RegExp(`^${source}$`);
  return (path) => regex.test(path);
}

export function matchesAny(patterns, path) {
  return patterns.some((pattern) => pathMatcher(pattern)(path));
}

/** Every regular file under dir, as sorted relative paths. Symbolic links are not followed. */
export function listFiles(dir) {
  const files = [];
  const walk = (relative) => {
    for (const entry of readdirSync(join(dir, relative), { withFileTypes: true })) {
      const path = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        walk(path);
      } else if (entry.isFile()) {
        files.push(path);
      }
    }
  };
  walk('');
  return files.sort();
}

/** Reads `--name value` and `--flag` options and positional arguments. */
export function parseArgs(argv, spec) {
  const options = {};
  const positional = [];
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const name = arg.slice(2);
    if (!(name in spec)) throw new UsageError(`unknown option ${arg}`);
    if (spec[name] === 'flag') {
      options[name] = true;
    } else {
      index += 1;
      if (index >= argv.length) throw new UsageError(`${arg} needs a value`);
      options[name] = argv[index];
    }
  }
  return { options, positional };
}
