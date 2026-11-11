# checks

A check is a pinned tool that reads one surface and writes SARIF. `registry.json` declares every tool and every check; `whs` runs nothing that is not in it.

| Check | Wraps | Reads | Finds |
|---|---|---|---|
| `gitleaks` | [gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1 | commits, tree | Secrets |
| `zizmor` | [zizmor](https://github.com/zizmorcore/zizmor) 1.32.0 | tree | Unsafe GitHub Actions workflows |
| `semgrep` | [Semgrep CE](https://github.com/semgrep/semgrep) 1.185.0 | tree | Breaks of the rules in `semgrep/rules/` |

## A registry entry

| Field | Meaning |
|---|---|
| `class` | `deterministic` (its findings can stop a change) or `model` (its findings advise) |
| `sends_to` | Providers that receive content. Empty when nothing leaves the machine. A check with an entry here reads a tree with the data paths left out, and may not declare `commits` |
| `tool` | A key in `tools`: exact version, and a SHA-256 per platform or a hash-locked requirements file. A tool is a pin, installed by `whs install` (`lib/pins.mjs`) |
| `argv` | The arguments for each surface the check reads: `tree` (one commit's files) or `commits` (the commits a selector names: a change's `base..head`, everything reachable from one commit, or every ref). Placeholders: `{out}` and `{pack}` on both; `{repo}` and `{commits}` on `commits` only, where both are required. Every invocation must exit 0 when the tool ran, with or without findings, so that a non-zero exit always means failure |
| `flags` | Optional. Arguments passed on every surface, after the surface's own. A flag that switches off one of the tool's ignore mechanisms goes here, so no surface can run without it |
| `stdout` | True when the tool writes SARIF to standard output |
| `applies` | Path patterns. A tree with no matching file reports `not_applicable` |
| `canaries` | `per-rule` when the pack writes the rules (every rule needs a catching case), `per-check` otherwise |
| `rule_id_strip` | A prefix the tool adds to rule ids, removed where the tool's output is read, so findings and `scan.sarif` name a rule the same way on every machine |
| `neutralise` | What lets scanned content switch the tool off: files the pack replaces, and inline comments it strips, in the copy of the tree that this check reads and in no other |

## Adding a rule

1. Add it under `semgrep/rules/`, with `metadata.control` and `metadata.references`. A rule that comes from a finding enters this repository only after the finding is closed, in general terms, with nothing that says where it came from (standard 9.6).
2. Add a catching case and a quiet case under `canaries/semgrep/`.
3. Run `node bin/whs.mjs canary`. It fails until both exist and agree with the rule.

These rules read source as text. For Postgres they are a tripwire at change time; the catalogue is the authority, through `adapters/`. Known limit, tested on 11 November 2026: both SQL rules also report commented-out SQL and a comment string that holds the same words, and neither knows that a later migration replaced a definition.

## Changing a version

Change the version and the hashes in `registry.json`, regenerate `semgrep/requirements.txt` with `uv pip compile semgrep/requirements.in --generate-hashes --universal --python-version 3.10 --no-header -o semgrep/requirements.txt`, and run the full suite. Read the tool's release notes for new ignore mechanisms and add them to `neutralise`.
