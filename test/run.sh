#!/usr/bin/env bash
# Runs the whole suite: the Node tests, the canaries, the shell tests, then shellcheck.
#
# The pre-push hook runs this from a `git archive` of the pushed commit, and CI runs it on
# Ubuntu and macOS. An empty suite fails: a run over zero tests is not a pass.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

failed=0
step() {
  local label=$1
  shift
  printf '==> %s\n' "$label"
  if "$@"; then printf '    ok\n'; else printf '    FAILED\n'; failed=$((failed + 1)); fi
}

step "pinned tools" node bin/whs.mjs install

node_tests=$(find test -maxdepth 1 -name '*.test.mjs' | sort)
if [ -z "$node_tests" ]; then
  printf 'run.sh: FAILED, no Node test files (test/*.test.mjs)\n' >&2
  failed=$((failed + 1))
else
  # shellcheck disable=SC2086
  step "node tests" node --test $node_tests
fi

step "canaries" node bin/whs.mjs canary

for t in test/*.test.sh; do
  [ -e "$t" ] || continue
  step "$t" bash "$t"
done

files=$(find . -path ./.git -prune -o -type f \( -name '*.sh' -o -path './.githooks/*' \) -print | sort)
if [ -z "$files" ]; then
  printf 'run.sh: FAILED, no scripts found for shellcheck\n' >&2
  failed=$((failed + 1))
elif command -v shellcheck >/dev/null 2>&1; then
  # shellcheck disable=SC2086
  step "shellcheck" shellcheck -x $files
else
  printf 'run.sh: shellcheck not installed; skipped\n' >&2
fi

printf 'run.sh: %d failure(s)\n' "$failed"
[ "$failed" -eq 0 ]
