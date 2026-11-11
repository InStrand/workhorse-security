// Throwaway git repositories for tests. Everything lives under the system temp directory.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { must } from '../lib/util.mjs';

const ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: 'test',
  GIT_AUTHOR_EMAIL: 'test@example.invalid',
  GIT_COMMITTER_NAME: 'test',
  GIT_COMMITTER_EMAIL: 'test@example.invalid',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_SYSTEM: '/dev/null',
  // Git reads ~/.config/git/ignore even with no global config. A developer's own ignore list
  // (commonly ".env") must not decide what these fixtures commit.
  GIT_CONFIG_COUNT: '1',
  GIT_CONFIG_KEY_0: 'core.excludesFile',
  GIT_CONFIG_VALUE_0: '/dev/null',
};

export function scratch(label) {
  return mkdtempSync(join(tmpdir(), `whs-test-${label}-`));
}

export function remove(dir) {
  rmSync(dir, { recursive: true, force: true });
}

export function makeRepo() {
  const repo = scratch('repo');
  must('git', ['init', '--quiet', '-b', 'main', repo], { env: ENV });
  return repo;
}

/** Writes the given files (null removes one), commits everything, and returns the commit SHA. */
export function commit(repo, files, message = 'change') {
  for (const [path, content] of Object.entries(files)) {
    if (content === null) {
      rmSync(join(repo, path));
    } else {
      mkdirSync(dirname(join(repo, path)), { recursive: true });
      writeFileSync(join(repo, path), content);
    }
  }
  must('git', ['-C', repo, 'add', '--all'], { env: ENV });
  must('git', ['-C', repo, 'commit', '--quiet', '--allow-empty', '-m', message], { env: ENV });
  return must('git', ['-C', repo, 'rev-parse', 'HEAD'], { env: ENV });
}

export const DEFINER_WITHOUT_PATH = `create function public.close_account(p_user uuid) returns void
language plpgsql security definer as $$
begin
  delete from accounts where id = p_user;
end;
$$;
`;

export const GRANT_TO_ANON = 'grant select on table public.accounts to anon;\n';

// Assembled here so that no token-shaped string exists in this repository.
export const TOKEN = ['ghp_', 'x7Kq2Lm9Rt4Vb8Nc3Zp6Wd1Yf5Hj0Gs7Ae2U'].join('');
