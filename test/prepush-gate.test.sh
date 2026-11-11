#!/usr/bin/env bash
# Tests for .githooks/pre-push: the confidentiality gate and the test run on the pushed commit.
#
# Builds a throwaway repository with the hook active, a bare remote, and a stub test/run.sh that
# records when it ran and fails on request. Then pushes under each condition and checks that git
# refused or allowed the push.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
hook="$root/.githooks/pre-push"
work=$(mktemp -d "${TMPDIR:-/tmp}/whs-prepush-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
export HOME="$work/home"
mkdir -p "$HOME"
export WHS_CONFIDENTIAL_TERMS="$work/terms"
export WHS_TEST_MARKER="$work/ran"
unset WHS_TEST_FAIL
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid

repo="$work/repo"
git init -q -b main "$repo"
git init -q --bare "$work/remote.git"
git -C "$repo" remote add origin "$work/remote.git"
git -C "$repo" config core.hooksPath .githooks
mkdir -p "$repo/.githooks" "$repo/test"
cp "$hook" "$repo/.githooks/pre-push"
cat > "$repo/test/run.sh" <<'STUB'
#!/usr/bin/env bash
if [ -n "${WHS_TEST_MARKER:-}" ]; then printf 'ran\n' >> "$WHS_TEST_MARKER"; fi
if [ "${WHS_TEST_FAIL:-0}" = "1" ]; then exit 1; fi
exit 0
STUB
chmod +x "$repo/test/run.sh" "$repo/.githooks/pre-push"
printf 'hello\n' > "$repo/notes.txt"
git -C "$repo" add -- .githooks/pre-push test/run.sh notes.txt
git -C "$repo" commit -q -m "initial" -- .githooks/pre-push test/run.sh notes.txt

fails=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; fails=$((fails + 1)); }

# Returns 0 when the push is accepted, 1 when refused. Output goes to $work/out.
push() {
  if git -C "$repo" push -q origin "$@" > "$work/out" 2>&1; then return 0; else return 1; fi
}
expect_refused() {
  local label=$1 needle=$2; shift 2
  if push "$@"; then fail "$label: push was accepted"
  elif grep -q -F -e "$needle" "$work/out"; then pass "$label"
  else fail "$label: refused for another reason: $(tr '\n' ' ' < "$work/out")"; fi
}
expect_accepted() {
  local label=$1; shift
  if push "$@"; then pass "$label"; else fail "$label: push refused: $(tr '\n' ' ' < "$work/out")"; fi
}

printf 'pre-push gate\n'

# 1. No term list: every push refused.
expect_refused "no term list refuses the push" "No confidential term list" HEAD:refs/heads/main

# 2. Empty list: still refused.
: > "$WHS_CONFIDENTIAL_TERMS"
expect_refused "empty term list refuses the push" "No confidential term list" HEAD:refs/heads/main

# 3. Opt out with no-terms: accepted, and the stub test ran from the archive.
printf 'no-terms\n' > "$WHS_CONFIDENTIAL_TERMS"
expect_accepted "no-terms opt-out accepts a clean push" HEAD:refs/heads/main
if [ -s "$WHS_TEST_MARKER" ]; then pass "test/run.sh ran on the pushed commit"; else fail "test/run.sh did not run"; fi

# 4. A listed term in a diff is refused, case-insensitively.
printf 'Zebra\n' > "$WHS_CONFIDENTIAL_TERMS"
printf 'the ZEBRA project\n' >> "$repo/notes.txt"
git -C "$repo" commit -q -m "add a line" -- notes.txt
expect_refused "term in a diff refuses the push" "An outgoing commit contains a confidential term" HEAD:refs/heads/main

# 5. CRLF line endings in the list still match.
printf 'zebra\r\n' > "$WHS_CONFIDENTIAL_TERMS"
expect_refused "CRLF term list still matches" "An outgoing commit contains a confidential term" HEAD:refs/heads/main

# 6. Only the message carries the term.
git -C "$repo" reset -q --soft HEAD~1
git -C "$repo" restore -q --staged -- notes.txt
git -C "$repo" checkout -q -- notes.txt
printf 'plain line\n' >> "$repo/notes.txt"
git -C "$repo" commit -q -m "about the zebra" -- notes.txt
expect_refused "term in a commit message refuses the push" "An outgoing commit contains a confidential term" HEAD:refs/heads/main

# 7. A clean commit is accepted; then a branch name carrying the term is refused.
git -C "$repo" commit -q --amend -m "plain message" -- notes.txt
expect_accepted "clean commit accepted" HEAD:refs/heads/main
expect_refused "term in a ref name refuses the push" "A ref name contains a confidential term" HEAD:refs/heads/feature/zebra-work

# 8. A failing test suite in the pushed commit refuses the push.
printf 'another line\n' >> "$repo/notes.txt"
git -C "$repo" commit -q -m "another" -- notes.txt
export WHS_TEST_FAIL=1
expect_refused "failing tests refuse the push" "pre-push: running test/run.sh" HEAD:refs/heads/main
unset WHS_TEST_FAIL
expect_accepted "same commit accepted once tests pass" HEAD:refs/heads/main

printf '%d failure(s)\n' "$fails"
[ "$fails" -eq 0 ]
