# workhorse-security

InStrand's standard for hardening and scanning every repository it works in, and the pack that applies it.

## Vision

The standard is a thin wrapper around tools that other people maintain well: gitleaks, zizmor and Semgrep for every change; Cloudflare's `security-audit` skill and the jsm `security-audit-for-saas` skill for the deep audit; GitHub's own features and the OpenSSF tools for platform posture; Anthropic's review action as an advisory reader. The pack adds only what those tools leave open for our stacks and our customers, and it grows from what it finds: every confirmed finding adds a canary, and a rule where a pattern can catch it.

The direction follows Vercel's [self-driving infrastructure](https://vercel.com/blog/self-driving-infrastructure) post. People state intent and principles. Scanners and feeds observe. An agent investigates and proposes a bead or a pull request. A person approves. What production shows goes back into the rules, the canaries and the baselines. Today every proposal needs a person. More becomes automatic as the canary measurements justify it.

## Status

First public commit, 12 November 2026. The standard is draft v5: [docs/plans/2026-11-11-security-scanning-standard.md](docs/plans/2026-11-11-security-scanning-standard.md). Work is tracked as `whs-*` beads (`br ready`).

| Part | State |
|---|---|
| `whs install`, `canary`, `gate`, `scan` with gitleaks, zizmor and Semgrep pinned by SHA-256 | Working. 47 tests and 10 canaries pass on macOS; see the Actions tab for Linux |
| Reusable gate workflow (`.github/workflows/security.yml`) | Runs on this repository. Not yet called from another repository |
| Three starter rules, ten canaries, three fragments | Working. The two SQL rules read text and also report commented-out SQL |
| `whs audit prepare` and the `workhorse-security-audit` skill | First form, used for eight audits of real repositories. Publishing the record and creating beads is still done by the coordinating agent, by hand |
| Command-line ergonomics, `whs doctor`, one install script | Not built. The audit of the command line is in `docs/reviews/2026-11-11-cli-audit.md` |
| Advisory AI reviewer, deploy wait, platform posture, adapters, SARIF record and importer, advisory reader | Not built. Each has a README that says what it will wrap, and beads |

## How it is built

Six parts. Every capability is a combination of them, and there is no code for one layer of the standard alone.

| Part | What it is | Where |
|---|---|---|
| Repository config | The one file a repository writes about itself: data paths that never go to a provider, and exceptions a named person accepted | `security/config.json` in the repository |
| Surface | What a check reads, built once by the pack: one commit's files (`tree`), or the commits a selector names (`commits`: a change, everything reachable from one commit, or the whole history). Later: platform settings, deployed state, dependencies, advisories | `lib/surface.mjs`, `adapters/` |
| Check | A pinned tool that reads one surface and writes SARIF, declared as data | `checks/registry.json` |
| Fragment | Knowledge for model checks, in the companion shape Cloudflare's skill reads, plus the list of other people's skills an audit can draw on | `fragments/` |
| Canary | A known case with the rules that must report it, or a correct form that must stay quiet | `canaries/` |
| Record | Findings in SARIF with one identity, and one comparison of two sets of findings | `lib/findings.mjs`, `record/` |

Some properties follow from how the parts are declared, so nobody has to remember them:

- Only a deterministic check can stop a change. A model check advises.
- A surface is opened for one reader. A reader that sends content to a provider gets a tree with the data paths left out and never reads commits; a local reader gets all of it. The audit's model is such a reader, and the report written for it holds no text from a data path.
- What one check switches off in its copy (a scanner's own ignore file, an inline ignore comment) changes nothing in the copy another check reads.
- A rule the pack writes cannot be added without a canary that it catches.
- A change is judged with the exceptions of its base revision, or of a config file kept outside the repository, so it cannot excuse itself. A base that was named and cannot be read stops the gate.
- Git is read through a directory the pack owns that holds only the repository's objects, so a change cannot hide a file with `.gitattributes` or with an ignore file in the checkout.
- The gate stops only what a change adds. A finding that was already there goes to the record.
- A scanner that fails, writes no report, or reports a finding the pack cannot locate fails the gate.
- Every process the pack starts gets a short allowlisted environment: no credential of the caller, no variable that redirects git or changes what a scanner reports.
- Only `whs install` fetches anything.

These hold in the tests on macOS. The same commits have not yet run in CI on Linux.

## Use

```bash
node bin/whs.mjs install                         # every pin, each verified: the scanners and the audit process
node bin/whs.mjs canary                          # prove every check against its known cases
node bin/whs.mjs gate <repo> --base <ref> --head <ref> [--config <file>]
node bin/whs.mjs scan <repo> [--ref <ref>] [--history]
node bin/whs.mjs audit prepare <repo> --config <security/config.json>
```

Needs Node 20 or later, git, and Python 3.10 or later (Semgrep runs in its own virtual environment). Nothing is installed from npm. Exit codes: 0 pass, 1 findings, 2 a check or the command failed.

To adopt the gate in a repository, copy [workflows/security.yml](workflows/security.yml) and add a `security/config.json`. This works across organisations only once this repository is public, or the pack is vendored (decision D9 in the standard).

## Layout

| Path | Holds | Wraps |
|---|---|---|
| `bin/`, `lib/` | The `whs` command | Nothing; this is the connective code |
| `checks/` | The registry of pinned tools and checks, Semgrep rules, the gitleaks config | gitleaks, zizmor, Semgrep CE |
| `canaries/` | Known cases per check | |
| `fragments/` | Companion files and the registry of sources | Cloudflare `security-audit`, jsm `security-audit-for-saas`, OpenAI security skills |
| `skills/workhorse-security-audit/` | The deep audit skill | The same |
| `.github/workflows/`, `workflows/` | The reusable gate workflow, and the caller to copy | GitHub Actions |
| `posture/` | Declared baselines per platform (not built) | OpenSSF Scorecard and Allstar, platform APIs |
| `adapters/` | Surfaces from platforms and deployed state (not built) | Supabase, Convex, Vercel, OSV |
| `record/` | SARIF conversion, the record, the importer into beads (not built) | SARIF 2.1.0, beads |
| `probes/`, `estate/` | Probe repository definitions and scheduled jobs across organisations (not built) | Dependabot, OSV, Zero Wire |
| `docs/` | The standard, handoff notes | |

## Contributing

Read `AGENTS.md` first. Run `scripts/dev-setup.sh` once after cloning: it activates the pre-push gate, checks the machine-level confidentiality term list (which must hold a term or the line `no-terms` before any push) and installs the pinned scanners. `test/run.sh` must pass before every push; CI runs it on Ubuntu and macOS.

## Credits

The audit process is Cloudflare's [security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT). The SaaS domain knowledge is Jeffrey Emanuel's `security-audit-for-saas` skill, used under subscription where installed and never copied here. The flywheel tools this repository runs on are his as well.

## Licence

MIT. Copyright (c) 2026 Ryan Griffin.
