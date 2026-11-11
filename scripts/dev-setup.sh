#!/usr/bin/env bash
# One-time setup for a clone of workhorse-security: activates the committed git hooks, checks the
# machine-level confidentiality term list, and installs the pinned scanners. Safe to re-run.
set -euo pipefail
root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
git -C "$root" config core.hooksPath .githooks
printf 'core.hooksPath = .githooks\n'

terms="${WHS_CONFIDENTIAL_TERMS:-${XDG_CONFIG_HOME:-$HOME/.config}/flywheel-teams/confidential-terms}"
if [ ! -e "$terms" ]; then
  mkdir -p "$(dirname "$terms")"
  touch "$terms"
  printf 'created %s (empty). Add one confidential term per line; the pre-push hook refuses pushes that contain any of them.\n' "$terms"
else
  printf '%s exists (%s terms)\n' "$terms" "$(grep -c -v '^[[:space:]]*$' "$terms" || true)"
fi

for tool in node python3 git br bv ntm dcg shellcheck; do
  if command -v "$tool" >/dev/null 2>&1; then printf 'found %s\n' "$tool"; else printf 'missing %s\n' "$tool"; fi
done

node "$root/bin/whs.mjs" install
