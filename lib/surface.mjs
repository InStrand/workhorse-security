// Surfaces: what a check reads. A target says what there is to read; opening it for one reader
// gives that reader's surface, built by the pack, and the reader only receives it. Two kinds
// exist today:
//   tree     the files of one commit, copied out of git into a directory the pack owns
//   commits  the commits a selector names, read from the repository's objects
// Both are read through a view: a git directory the pack owns that holds the repository's
// objects and nothing a commit or a checkout could use to change how git reads them.
// What a reader may see is derived from what it declares: `sends_to` decides whether the data
// paths are left out, `neutralise` decides what is switched off in its copy.
// Platform settings, deployed state and advisory feeds are further kinds, built by adapters/.
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { crossesDataBoundary } from './registry.mjs';
import { UsageError, listFiles, matchesAny, must, run } from './util.mjs';

const ZERO_SHA = /^0+$/;

export function tempDir(label) {
  return mkdtempSync(join(tmpdir(), `whs-${label}-`));
}

export function removeTempDir(dir) {
  rmSync(dir, { recursive: true, force: true });
}

/** True when no revision was named: no ref, or the all-zero SHA GitHub sends for a new branch. */
export const noRevision = (ref) => !ref || ZERO_SHA.test(ref);

/** The full commit SHA for a ref. A ref that was named and is not a commit is a failure, never "no revision". */
export function requireCommit(repo, ref) {
  const result = noRevision(ref) ? null : run('git', ['-C', repo, 'rev-parse', '--verify', '--quiet', '--end-of-options', `${ref}^{commit}`]);
  if (result?.status !== 0) throw new UsageError(`"${ref}" is not a commit in ${repo}`);
  return result.stdout.trim();
}

/**
 * The commits of a repository that a selector names. The selector is what `git log` takes:
 *   "<base>..<head>"  the commits of a change
 *   "<commit>"        every commit reachable from one commit: a first push
 *   "--all"           every commit reachable from any ref: the whole history
 */
export function commits(repo, select) {
  return {
    kind: 'commits',
    open(reader) {
      // Files cannot be left out of commits, so a reader that sends content never reads them.
      if (crossesDataBoundary(reader)) throw new UsageError(`${reader.id} sends content to a provider and cannot read commits`);
      const view = openView(repo);
      return { kind: 'commits', repo: view, select, close: () => removeTempDir(view) };
    },
  };
}

// Every attribute a commit can set that changes what git writes out or shows, switched off.
const VIEW_ATTRIBUTES = '* -export-ignore -export-subst -text -eol -ident -filter -working-tree-encoding !diff\n';

/**
 * A bare git directory the pack owns, over a repository's objects and the names of its refs.
 * Nothing else of the repository is in it: no working tree, no index, no config, no hooks. Its
 * attributes file outranks any .gitattributes in a commit. Every surface is read through a
 * view, so nothing a change commits and nothing the checkout holds decides how git reads the
 * objects: a .gitattributes line cannot keep a file out of a tree (export-ignore) or out of the
 * history a scanner sees (-diff), and a scanner's ignore file in the working tree is not there.
 */
function openView(repo) {
  const view = tempDir('view');
  const inRepo = (name) => resolve(repo, must('git', ['-C', repo, 'rev-parse', '--git-path', name]));
  must('git', ['init', '--quiet', '--bare', '--template=', view]);
  for (const dir of ['info', 'objects/info']) mkdirSync(join(view, dir), { recursive: true });
  writeFileSync(join(view, 'info', 'attributes'), VIEW_ATTRIBUTES);
  writeFileSync(join(view, 'objects', 'info', 'alternates'), `${inRepo('objects')}\n`);
  // A shallow clone records where its history stops; without that, git would look for the missing parents.
  if (existsSync(inRepo('shallow'))) copyFileSync(inRepo('shallow'), join(view, 'shallow'));
  // "--all" means every ref and HEAD. HEAD may be detached, so it is kept as a ref of its own.
  const head = run('git', ['-C', repo, 'rev-parse', '--verify', '--quiet', 'HEAD^{commit}']).stdout.trim();
  const refs = must('git', ['-C', repo, 'for-each-ref', '--format=%(objectname) %(refname)']).split('\n');
  const lines = [...refs, head ? `${head} refs/whs/head` : ''].filter(Boolean);
  writeFileSync(join(view, 'packed-refs'), lines.map((line) => `${line}\n`).join(''));
  return view;
}

/**
 * The paths a reader never sees: every data path when it sends content to a provider, none when
 * it stays on this machine. This is the only place the data boundary is decided.
 */
export const hiddenFrom = (reader, dataPaths) => (crossesDataBoundary(reader) ? dataPaths : []);

/**
 * A tree of files that `fill(dir, hidden)` writes, leaving the hidden patterns out. Opening it
 * builds a copy for one reader and nobody else: without what that reader must not see, and with
 * what could switch that reader off neutralised. One reader's copy never changes what another
 * reads. The copy is checked before it is handed over, so a `fill` that left a hidden file in,
 * or a commit that carries a .git directory, stops here.
 */
export function tree(fill) {
  return {
    kind: 'tree',
    open(reader, dataPaths, dir = tempDir('tree')) {
      const hidden = hiddenFrom(reader, dataPaths);
      try {
        fill(dir, hidden);
        neutralise(dir, reader.neutralise ?? {});
        const files = listFiles(dir);
        const refused = files.filter((file) => matchesAny(hidden, file) || file.split('/').includes('.git'));
        if (refused.length > 0) throw new UsageError(`the surface for ${reader.id} holds ${refused.length} file(s) it must not hold, the first is ${refused[0]}`);
        return { kind: 'tree', dir, files, close: () => removeTempDir(dir) };
      } catch (error) {
        removeTempDir(dir);
        throw error;
      }
    },
  };
}

/** The files of one commit. */
export const commitTree = (repo, commit) => tree((dir, hidden) => materialiseTree(repo, commit, dir, hidden));

/** Every file path in one commit. */
export function filesAt(repo, commit) {
  return must('git', ['-C', repo, 'ls-tree', '-r', '--name-only', '-z', commit]).split('\0').filter(Boolean);
}

/** A path pattern as a git pathspec that excludes it. */
function excludePathspec(pattern) {
  return pattern.endsWith('/') ? `:(exclude)${pattern.slice(0, -1)}` : `:(exclude,glob)${pattern}`;
}

/**
 * Copies the files of one commit into dest, leaving out the excluded patterns. The copy comes
 * from git's objects through a view, so it is exactly the commit, byte for byte: no untracked
 * files, no local edits, and no file left out or rewritten by an attribute.
 */
function materialiseTree(repo, commit, dest, excluded) {
  mkdirSync(dest, { recursive: true });
  const view = openView(repo);
  const script = 'set -eo pipefail; view=$1; commit=$2; dest=$3; shift 3; git --git-dir="$view" archive --format=tar "$commit" -- . "$@" | tar -x -C "$dest"';
  try {
    must('bash', ['-c', script, 'whs', view, commit, dest, ...excluded.map(excludePathspec)]);
  } finally {
    removeTempDir(view);
  }
}

/**
 * Removes what lets scanned content switch a reader off. A check declares the files a
 * repository could use to hide paths from it (replaced with the pack's own content) and the
 * inline comments that silence it (stripped, keeping every line number). After this, the only
 * way to accept a finding is an exception in the repository config.
 */
function neutralise(dir, rules) {
  const files = listFiles(dir);
  for (const [name, content] of Object.entries(rules.replace_files ?? {})) {
    for (const file of files.filter((path) => basename(path) === name)) rmSync(join(dir, file));
    writeFileSync(join(dir, name), content);
  }
  if (rules.strip) {
    const regex = new RegExp(rules.strip.regex, 'g');
    for (const file of files.filter((path) => matchesAny(rules.strip.paths, path))) {
      const before = readFileSync(join(dir, file), 'utf8');
      const after = before.replace(regex, '');
      if (after !== before) writeFileSync(join(dir, file), after);
    }
  }
}
